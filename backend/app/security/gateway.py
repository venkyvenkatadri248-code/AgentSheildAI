import uuid
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from sqlalchemy.orm import Session

from app.models.entities import (
    User, Agent, SecurityPolicy, SecurityEvent, Alert,
    ApprovalRequest, AuditEvent, UploadedFile
)
from app.schemas.api_schemas import SecurityDecision
from app.security.lifecycle import LifecycleState, validate_transition
from app.security.detectors import (
    detect_direct_prompt_injection,
    detect_indirect_prompt_injection,
    detect_sensitive_data,
    detect_path_traversal,
    detect_unsafe_mail_actions
)
from app.services.event_broadcaster import broadcaster

logger = logging.getLogger("agentshield.gateway")


class CentralSecurityGateway:
    """
    Central Security Gateway for AgentShieldAI.
    Intercepts, inspects, validates, explains, and prevents unauthorized or unsafe
    AI agent actions BEFORE any execution occurs.
    """

    @classmethod
    def evaluate_tool_call(
        cls,
        db: Session,
        actor: User,
        agent: Agent,
        tool_name: str,
        arguments: Dict[str, Any],
        conversation_id: Optional[str] = None,
        task_id: Optional[str] = None
    ) -> SecurityDecision:
        decision_id = str(uuid.uuid4())
        logger.info(f"[GATEWAY] Intercepted tool call '{tool_name}' by agent '{agent.key}' for user '{actor.email}' [Decision ID: {decision_id}]")

        # 1. Fetch relevant security policies from DB
        policies = {p.category: p for p in db.query(SecurityPolicy).all()}
        
        # -------------------------------------------------------------
        # CHECK 1: Unauthorized Tool Invocation
        # -------------------------------------------------------------
        allowed_tools = agent.allowed_tools or []
        if tool_name not in allowed_tools:
            explanation = (
                f"Agent '{agent.name}' is prohibited from executing '{tool_name}'. "
                f"Allowed tools for this agent profile are: {', '.join(allowed_tools) if allowed_tools else 'None'}."
            )
            evidence = {
                "attempted_tool": tool_name,
                "agent_key": agent.key,
                "configured_allowed_tools": allowed_tools
            }
            return cls._block_action(
                db=db,
                actor=actor,
                agent=agent,
                decision_id=decision_id,
                tool_name=tool_name,
                risk_category="unauthorized_tool_invocation",
                severity="HIGH",
                policy=policies.get("tool_auth"),
                explanation=explanation,
                evidence=evidence,
                conversation_id=conversation_id
            )

        # -------------------------------------------------------------
        # CHECK 2: Direct Prompt Injection in Tool Arguments
        # -------------------------------------------------------------
        policy_injection = policies.get("prompt_injection")
        if not policy_injection or policy_injection.is_enabled:
            for arg_key, arg_val in arguments.items():
                if isinstance(arg_val, str):
                    det = detect_direct_prompt_injection(arg_val)
                    if det.detected:
                        explanation = (
                            f"Direct prompt injection detected in argument '{arg_key}'. "
                            f"Heuristic identified: {det.reason}. "
                            f"Action blocked to prevent instruction override."
                        )
                        return cls._block_action(
                            db=db,
                            actor=actor,
                            agent=agent,
                            decision_id=decision_id,
                            tool_name=tool_name,
                            risk_category="prompt_injection",
                            severity=det.severity,
                            policy=policy_injection,
                            explanation=explanation,
                            evidence=det.evidence,
                            conversation_id=conversation_id
                        )

        # -------------------------------------------------------------
        # CHECK 3: Dangerous File Operations & Path Traversal
        # -------------------------------------------------------------
        policy_file = policies.get("file_security")
        if not policy_file or policy_file.is_enabled:
            # Check file paths / filenames
            for arg_key in ["file_path", "filename", "path", "source_file"]:
                if arg_key in arguments and isinstance(arguments[arg_key], str):
                    det = detect_path_traversal(arguments[arg_key])
                    if det.detected:
                        explanation = (
                            f"Prohibited file operation in argument '{arg_key}'. "
                            f"{det.reason}. Gateway prevented unauthorized filesystem access."
                        )
                        return cls._block_action(
                            db=db,
                            actor=actor,
                            agent=agent,
                            decision_id=decision_id,
                            tool_name=tool_name,
                            risk_category=det.category,
                            severity=det.severity,
                            policy=policy_file,
                            explanation=explanation,
                            evidence=det.evidence,
                            conversation_id=conversation_id
                        )

        # -------------------------------------------------------------
        # CHECK 4: Cross-User Resource Isolation (File Ownership)
        # -------------------------------------------------------------
        file_id = arguments.get("file_id")
        if file_id:
            file_record = db.query(UploadedFile).filter(UploadedFile.id == file_id).first()
            if file_record and file_record.user_id != actor.id and actor.role != "admin":
                explanation = (
                    f"Access denied: User '{actor.email}' does not own file '{file_id}'. "
                    f"Cross-user data access prevented by tenant isolation guardrail."
                )
                evidence = {
                    "file_id": file_id,
                    "file_owner": file_record.user_id,
                    "attempted_by": actor.id
                }
                return cls._block_action(
                    db=db,
                    actor=actor,
                    agent=agent,
                    decision_id=decision_id,
                    tool_name=tool_name,
                    risk_category="cross_user_access",
                    severity="HIGH",
                    policy=policy_file,
                    explanation=explanation,
                    evidence=evidence,
                    conversation_id=conversation_id
                )

        # -------------------------------------------------------------
        # CHECK 5: Sensitive Data / PII Exposure
        # -------------------------------------------------------------
        policy_pii = policies.get("sensitive_data")
        if not policy_pii or policy_pii.is_enabled:
            for arg_key, arg_val in arguments.items():
                det = detect_sensitive_data(arg_val)
                if det.detected:
                    explanation = (
                        f"Sensitive data exposure detected in parameter '{arg_key}'. "
                        f"{det.reason}. Request intercepted to prevent data leakage."
                    )
                    return cls._block_action(
                        db=db,
                        actor=actor,
                        agent=agent,
                        decision_id=decision_id,
                        tool_name=tool_name,
                        risk_category=det.category,
                        severity=det.severity,
                        policy=policy_pii,
                        explanation=explanation,
                        evidence=det.evidence,
                        conversation_id=conversation_id
                    )

        # -------------------------------------------------------------
        # CHECK 6: Unsafe Mail Actions & Approval Requirements
        # -------------------------------------------------------------
        policy_mail = policies.get("mail_guard")
        if tool_name == "send_authorized_email":
            recipient = str(arguments.get("recipient", ""))
            subject = str(arguments.get("subject", ""))
            body = str(arguments.get("body", ""))
            
            mail_check = detect_unsafe_mail_actions(recipient, subject, body)
            if mail_check.detected:
                explanation = f"Unsafe email dispatch blocked: {mail_check.reason}"
                return cls._block_action(
                    db=db,
                    actor=actor,
                    agent=agent,
                    decision_id=decision_id,
                    tool_name=tool_name,
                    risk_category=mail_check.category,
                    severity=mail_check.severity,
                    policy=policy_mail,
                    explanation=explanation,
                    evidence=mail_check.evidence,
                    conversation_id=conversation_id
                )

            # Email dispatch inherently requires explicit human authorization
            return cls._request_approval(
                db=db,
                actor=actor,
                agent=agent,
                decision_id=decision_id,
                tool_name=tool_name,
                arguments=arguments,
                risk_category="mail_dispatch_approval",
                severity="MEDIUM",
                policy=policy_mail,
                explanation=f"Outbound email dispatch to '{recipient}' requires human verification before sending.",
                conversation_id=conversation_id
            )

        # Check if generic policy marks tool as requiring human approval
        for p in policies.values():
            if p.is_enabled and p.requires_approval:
                tools_requiring_approval = p.config.get("tools_requiring_approval", [])
                if tool_name in tools_requiring_approval:
                    return cls._request_approval(
                        db=db,
                        actor=actor,
                        agent=agent,
                        decision_id=decision_id,
                        tool_name=tool_name,
                        arguments=arguments,
                        risk_category=p.category,
                        severity=p.risk_level,
                        policy=p,
                        explanation=f"Policy '{p.name}' mandates human approval for tool '{tool_name}'.",
                        conversation_id=conversation_id
                    )

        # -------------------------------------------------------------
        # CHECK 7: All Checks Passed -> ALLOW Tool Execution
        # -------------------------------------------------------------
        explanation = f"Security verification passed for tool '{tool_name}'. No threat indicators detected."
        
        event = SecurityEvent(
            decision_id=decision_id,
            actor_id=actor.id,
            agent_id=agent.id,
            conversation_id=conversation_id,
            tool_name=tool_name,
            risk_category="authorized_operation",
            severity="LOW",
            lifecycle_state=LifecycleState.OBSERVED.value,
            policy_id=None,
            policy_version=1,
            evidence={"arguments_keys": list(arguments.keys())},
            explanation=explanation,
            execution_prevented=False,
            verification_status="VERIFIED"
        )
        db.add(event)
        db.commit()

        # Broadcast live telemetry
        broadcaster.broadcast_sync("security_event", {
            "decision_id": decision_id,
            "status": "ALLOWED",
            "agent": agent.name,
            "tool": tool_name,
            "severity": "LOW"
        })

        return SecurityDecision(
            decision_id=decision_id,
            allowed=True,
            requires_approval=False,
            lifecycle_state=LifecycleState.OBSERVED.value,
            risk_category="authorized_operation",
            severity="LOW",
            explanation=explanation,
            evidence={"status": "CLEARED"},
            execution_prevented=False,
            verification_status="VERIFIED"
        )

    @classmethod
    def _block_action(
        cls,
        db: Session,
        actor: User,
        agent: Agent,
        decision_id: str,
        tool_name: str,
        risk_category: str,
        severity: str,
        policy: Optional[SecurityPolicy],
        explanation: str,
        evidence: Dict[str, Any],
        conversation_id: Optional[str]
    ) -> SecurityDecision:
        logger.warning(f"[GATEWAY BLOCKED] Tool: {tool_name} | Category: {risk_category} | Reason: {explanation}")
        
        # Lifecycle transition: OBSERVED -> DETECTED -> BLOCKED -> PREVENTION_VERIFIED
        event = SecurityEvent(
            decision_id=decision_id,
            actor_id=actor.id,
            agent_id=agent.id,
            conversation_id=conversation_id,
            tool_name=tool_name,
            risk_category=risk_category,
            severity=severity,
            lifecycle_state=LifecycleState.PREVENTION_VERIFIED.value,
            policy_id=policy.id if policy else None,
            policy_version=policy.version if policy else 1,
            evidence=evidence,
            explanation=explanation,
            execution_prevented=True,
            verification_status="VERIFIED"
        )
        db.add(event)
        db.flush()

        # Create persistent Alert
        alert = Alert(
            security_event_id=event.id,
            title=f"Blocked Unsafe Action: {tool_name}",
            description=explanation,
            severity=severity,
            status="OPEN",
            agent_id=agent.id,
            user_id=actor.id
        )
        db.add(alert)

        # Create Audit record
        audit = AuditEvent(
            actor_id=actor.id,
            action="TOOL_EXECUTION_BLOCKED",
            target_type="tool_call",
            target_id=tool_name,
            details={
                "decision_id": decision_id,
                "agent_key": agent.key,
                "risk_category": risk_category,
                "severity": severity,
                "evidence": evidence
            }
        )
        db.add(audit)
        db.commit()

        # Broadcast live alert to UI
        broadcaster.broadcast_sync("alert_created", {
            "alert_id": alert.id,
            "title": alert.title,
            "severity": alert.severity,
            "agent": agent.name,
            "explanation": explanation
        })

        return SecurityDecision(
            decision_id=decision_id,
            allowed=False,
            requires_approval=False,
            lifecycle_state=LifecycleState.PREVENTION_VERIFIED.value,
            risk_category=risk_category,
            severity=severity,
            policy_name=policy.name if policy else "Default Guardrail",
            explanation=explanation,
            evidence=evidence,
            execution_prevented=True,
            verification_status="VERIFIED"
        )

    @classmethod
    def _request_approval(
        cls,
        db: Session,
        actor: User,
        agent: Agent,
        decision_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        risk_category: str,
        severity: str,
        policy: Optional[SecurityPolicy],
        explanation: str,
        conversation_id: Optional[str]
    ) -> SecurityDecision:
        logger.info(f"[GATEWAY APPROVAL REQUIRED] Tool: {tool_name} requires human approval")

        event = SecurityEvent(
            decision_id=decision_id,
            actor_id=actor.id,
            agent_id=agent.id,
            conversation_id=conversation_id,
            tool_name=tool_name,
            risk_category=risk_category,
            severity=severity,
            lifecycle_state=LifecycleState.PENDING_APPROVAL.value,
            policy_id=policy.id if policy else None,
            policy_version=policy.version if policy else 1,
            evidence={"arguments": arguments},
            explanation=explanation,
            execution_prevented=True,
            verification_status="PENDING_APPROVAL"
        )
        db.add(event)
        db.flush()

        approval = ApprovalRequest(
            security_event_id=event.id,
            agent_id=agent.id,
            user_id=actor.id,
            tool_name=tool_name,
            arguments_preview=arguments,
            risk_explanation=explanation,
            status="PENDING"
        )
        db.add(approval)
        db.commit()

        # Broadcast approval needed
        broadcaster.broadcast_sync("approval_required", {
            "approval_id": approval.id,
            "tool": tool_name,
            "agent": agent.name,
            "explanation": explanation
        })

        return SecurityDecision(
            decision_id=decision_id,
            allowed=False,
            requires_approval=True,
            lifecycle_state=LifecycleState.PENDING_APPROVAL.value,
            risk_category=risk_category,
            severity=severity,
            policy_name=policy.name if policy else "Approval Policy",
            explanation=explanation,
            evidence={"arguments": arguments, "approval_id": approval.id},
            execution_prevented=True,
            verification_status="PENDING_APPROVAL"
        )
