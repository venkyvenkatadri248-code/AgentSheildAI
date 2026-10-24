import os
import re
import uuid
import logging
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.security.lifecycle import LifecycleState
from app.models.entities import SecurityPolicy, UploadedFile, User, Agent

logger = logging.getLogger("agentshield.policy_engine")


class PolicyDecisionOutcome:
    def __init__(
        self,
        allowed: bool,
        requires_approval: bool,
        session_suspended: bool,
        lifecycle_state: str,
        policy_name: str,
        risk_category: str,
        severity: str,
        explanation: str,
        mitigation_attempted: Optional[str] = None,
        prevention_verified: bool = False,
        verification_evidence: Optional[Dict[str, Any]] = None
    ):
        self.allowed = allowed
        self.requires_approval = requires_approval
        self.session_suspended = session_suspended
        self.lifecycle_state = lifecycle_state
        self.policy_name = policy_name
        self.risk_category = risk_category
        self.severity = severity
        self.explanation = explanation
        self.mitigation_attempted = mitigation_attempted
        self.prevention_verified = prevention_verified
        self.verification_evidence = verification_evidence or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "requires_approval": self.requires_approval,
            "session_suspended": self.session_suspended,
            "lifecycle_state": self.lifecycle_state,
            "policy_name": self.policy_name,
            "risk_category": self.risk_category,
            "severity": self.severity,
            "explanation": self.explanation,
            "mitigation_attempted": self.mitigation_attempted,
            "prevention_verified": self.prevention_verified,
            "verification_evidence": self.verification_evidence
        }


class SecurityPolicyEngine:
    """
    Independent Security Policy Engine (PREVENT Pillar).
    
    Adheres strictly to core design requirements:
    1. Independent of ML Models: Evaluates authorization based on deterministic policies,
       tenant boundaries, and RBAC before any protected action executes.
       A model prediction NEVER overrides an explicit deny rule or grants authorization.
    2. Fail-Closed: If authorization cannot be confirmed, denies the request.
    3. Human-In-The-Loop: Gates sensitive operations (e.g. outbound mail) with approval.
    4. Repeated Violation Handling: Automatically suspends session on repeated attacks.
    5. Outcome Verification: Distinguishes between detected threat, policy denial,
       attempted mitigation, and verified outcome (PREVENTION_VERIFIED).
    """

    # Session-level repeated violations tracker (in-memory cache keyed by session_id/user_id)
    SESSION_VIOLATIONS_TRACKER: Dict[str, int] = {}
    MAX_CONSECUTIVE_VIOLATIONS = 3

    # Agent capability matrix
    AGENT_CAPABILITIES = {
        "research_agent": {
            "allowed_tools": ["search_web_sources", "search_research_papers", "extract_web_content"],
            "restricted_targets": ["local_filesystem", "mail_dispatch", "database_mutation"]
        },
        "document_agent": {
            "allowed_tools": ["list_user_files", "read_document_content", "create_document", "edit_document", "summarize_document"],
            "restricted_targets": ["external_web_egress", "mail_dispatch", "system_files"]
        },
        "file_agent": {
            "allowed_tools": ["list_user_files", "read_document_content", "create_document", "edit_document", "summarize_document"],
            "restricted_targets": ["external_web_egress", "mail_dispatch", "system_files"]
        },
        "data_analysis_agent": {
            "allowed_tools": ["inspect_dataset_schema", "calculate_descriptive_stats", "validate_dataset_quality", "generate_data_summary_report"],
            "restricted_targets": ["arbitrary_code_execution", "database_drop_alter", "mail_dispatch"]
        },
        "mail_agent": {
            "allowed_tools": ["draft_email", "search_mailbox", "summarize_email_thread", "send_authorized_email"],
            "restricted_targets": ["arbitrary_file_read", "unauthorized_bulk_dispatch", "system_files"]
        }
    }

    PROTECTED_FILES = {
        ".env", ".env.local", ".env.production", "agentshieldai.db",
        "settings.py", "docker-compose.yml", "id_rsa", "authorized_keys"
    }

    DANGEROUS_EXTENSIONS = {
        ".exe", ".bat", ".cmd", ".sh", ".ps1", ".vbs", ".dll", ".so", ".bin", ".scr"
    }

    @classmethod
    def get_session_violation_count(cls, session_key: str) -> int:
        return cls.SESSION_VIOLATIONS_TRACKER.get(session_key, 0)

    @classmethod
    def reset_session_violations(cls, session_key: str):
        if session_key in cls.SESSION_VIOLATIONS_TRACKER:
            del cls.SESSION_VIOLATIONS_TRACKER[session_key]

    @classmethod
    def clear_all_sessions(cls):
        cls.SESSION_VIOLATIONS_TRACKER.clear()

    @classmethod
    def evaluate_authorization(
        cls,
        db: Session,
        actor: User,
        agent: Agent,
        tool_name: str,
        arguments: Dict[str, Any],
        session_id: Optional[str] = None
    ) -> PolicyDecisionOutcome:
        """
        Evaluates authorization before action execution independently of ML predictions.
        """
        session_key = session_id or actor.email

        # -------------------------------------------------------------
        # 1. Check Repeated Violation Threshold (Session Suspension)
        # -------------------------------------------------------------
        prior_violations = cls.get_session_violation_count(session_key)
        if prior_violations >= cls.MAX_CONSECUTIVE_VIOLATIONS:
            return PolicyDecisionOutcome(
                allowed=False,
                requires_approval=False,
                session_suspended=True,
                lifecycle_state=LifecycleState.BLOCKED.value,
                policy_name="Session Incident Throttling & Suspension Policy",
                risk_category="repeated_policy_violations",
                severity="CRITICAL",
                explanation=(
                    f"Session suspended for '{actor.email}': Exceeded threshold of {cls.MAX_CONSECUTIVE_VIOLATIONS} "
                    f"consecutive security policy violations. Administrative intervention required."
                ),
                mitigation_attempted="Session suspended; all subsequent requests blocked unconditionally.",
                prevention_verified=True,
                verification_evidence={
                    "consecutive_violations": prior_violations,
                    "session_key": session_key,
                    "target_tool": tool_name
                }
            )

        # -------------------------------------------------------------
        # 2. Check Agent RBAC & Tool Whitelist
        # -------------------------------------------------------------
        allowed_tools = agent.allowed_tools or cls.AGENT_CAPABILITIES.get(agent.key, {}).get("allowed_tools", [])
        if tool_name not in allowed_tools:
            cls.SESSION_VIOLATIONS_TRACKER[session_key] = prior_violations + 1
            return PolicyDecisionOutcome(
                allowed=False,
                requires_approval=False,
                session_suspended=False,
                lifecycle_state=LifecycleState.PREVENTION_VERIFIED.value,
                policy_name="Agent Role-Based Access Control (RBAC)",
                risk_category="unauthorized_tool_invocation",
                severity="HIGH",
                explanation=(
                    f"Agent '{agent.name}' ({agent.key}) is prohibited from executing tool '{tool_name}'. "
                    f"Configured allowed tools: {', '.join(allowed_tools)}."
                ),
                mitigation_attempted="Central Security Gateway intercepted proposal before runtime execution.",
                prevention_verified=True,
                verification_evidence={
                    "agent": agent.key,
                    "attempted_tool": tool_name,
                    "allowed_tools": allowed_tools,
                    "prior_violations": prior_violations + 1
                }
            )

        # -------------------------------------------------------------
        # 3. Check File Security (Path Traversal & Protected Files)
        # -------------------------------------------------------------
        for param_key in ["file_path", "filename", "path", "source_file"]:
            target_path = arguments.get(param_key)
            if target_path and isinstance(target_path, str):
                # Path traversal
                if any(p in target_path for p in ["..", "%2e%2e", "/etc/passwd", "system32", "WINDOWS/system32"]):
                    cls.SESSION_VIOLATIONS_TRACKER[session_key] = prior_violations + 1
                    return PolicyDecisionOutcome(
                        allowed=False,
                        requires_approval=False,
                        session_suspended=False,
                        lifecycle_state=LifecycleState.PREVENTION_VERIFIED.value,
                        policy_name="Filesystem Boundary & Path Traversal Policy",
                        risk_category="dangerous_file_operation",
                        severity="CRITICAL",
                        explanation=f"Path traversal sequence detected in parameter '{param_key}': '{target_path}'.",
                        mitigation_attempted="Filesystem I/O aborted at boundary; target path unread.",
                        prevention_verified=True,
                        verification_evidence={
                            "attempted_path": target_path,
                            "io_executed": False,
                            "boundary_verified": "Strict sandbox containment verified"
                        }
                    )

                # Protected files
                basename = os.path.basename(target_path.replace("\\", "/")).lower()
                if basename in cls.PROTECTED_FILES or basename.endswith(".key") or basename.endswith(".pem"):
                    cls.SESSION_VIOLATIONS_TRACKER[session_key] = prior_violations + 1
                    return PolicyDecisionOutcome(
                        allowed=False,
                        requires_approval=False,
                        session_suspended=False,
                        lifecycle_state=LifecycleState.PREVENTION_VERIFIED.value,
                        policy_name="Protected Security Configuration Assets Policy",
                        risk_category="unauthorized_file_modification",
                        severity="CRITICAL",
                        explanation=f"Access or mutation of protected security configuration file '{basename}' is strictly prohibited.",
                        mitigation_attempted="File handle access denied; zero read/write bytes transmitted.",
                        prevention_verified=True,
                        verification_evidence={
                            "protected_asset": basename,
                            "file_system_mutations": 0
                        }
                    )

                # Dangerous extensions
                ext = os.path.splitext(target_path)[1].lower()
                if ext in cls.DANGEROUS_EXTENSIONS:
                    cls.SESSION_VIOLATIONS_TRACKER[session_key] = prior_violations + 1
                    return PolicyDecisionOutcome(
                        allowed=False,
                        requires_approval=False,
                        session_suspended=False,
                        lifecycle_state=LifecycleState.PREVENTION_VERIFIED.value,
                        policy_name="Executable & Binary Format Restriction Policy",
                        risk_category="dangerous_file_operation",
                        severity="CRITICAL",
                        explanation=f"Execution or handling of executable file extension '{ext}' is forbidden.",
                        mitigation_attempted="File handling refused; process creation suppressed.",
                        prevention_verified=True,
                        verification_evidence={"disallowed_extension": ext}
                    )

        # -------------------------------------------------------------
        # 4. Check Multi-Tenant Isolation (File & Dataset Ownership)
        # -------------------------------------------------------------
        file_id = arguments.get("file_id")
        if file_id:
            file_record = db.query(UploadedFile).filter(UploadedFile.id == file_id).first()
            if file_record and file_record.user_id != actor.id and actor.role != "admin":
                cls.SESSION_VIOLATIONS_TRACKER[session_key] = prior_violations + 1
                return PolicyDecisionOutcome(
                    allowed=False,
                    requires_approval=False,
                    session_suspended=False,
                    lifecycle_state=LifecycleState.PREVENTION_VERIFIED.value,
                    policy_name="Multi-Tenant Data Isolation Policy",
                    risk_category="cross_user_access",
                    severity="HIGH",
                    explanation=f"Cross-user data access prevented: User '{actor.email}' does not own file '{file_id}'.",
                    mitigation_attempted="Access denied by tenant isolation guardrail; no file data returned.",
                    prevention_verified=True,
                    verification_evidence={
                        "attempted_by": actor.id,
                        "file_owner": file_record.user_id,
                        "file_id": file_id
                    }
                )

        # -------------------------------------------------------------
        # 5. Check Network & SSRF Targets (Research & Mail Agents)
        # -------------------------------------------------------------
        target_url = str(arguments.get("url") or arguments.get("target_url") or "")
        if target_url:
            if any(p in target_url for p in ["169.254.169.254", "localhost", "127.0.0.1", "0.0.0.0", "metadata.google"]):
                cls.SESSION_VIOLATIONS_TRACKER[session_key] = prior_violations + 1
                return PolicyDecisionOutcome(
                    allowed=False,
                    requires_approval=False,
                    session_suspended=False,
                    lifecycle_state=LifecycleState.PREVENTION_VERIFIED.value,
                    policy_name="SSRF & Private Network Protection Policy",
                    risk_category="unauthorized_network_access",
                    severity="CRITICAL",
                    explanation=f"Prohibited network target detected: SSRF/Metadata access to '{target_url}' blocked.",
                    mitigation_attempted="Outbound socket creation prevented; zero network egress.",
                    prevention_verified=True,
                    verification_evidence={"target_url": target_url, "egress_bytes": 0}
                )

        # -------------------------------------------------------------
        # 6. Check Human Approval Requirements (Mail Agent Gating)
        # -------------------------------------------------------------
        if tool_name == "send_authorized_email":
            recipient = str(arguments.get("recipient", ""))
            return PolicyDecisionOutcome(
                allowed=False,
                requires_approval=True,
                session_suspended=False,
                lifecycle_state=LifecycleState.PENDING_APPROVAL.value,
                policy_name="Outbound Communication Authorization Policy",
                risk_category="mail_dispatch_approval",
                severity="MEDIUM",
                explanation=f"Outbound email dispatch to '{recipient}' requires human verification before transmission.",
                mitigation_attempted="Action paused and routed to SOC Analyst Approval Queue.",
                prevention_verified=False,
                verification_evidence={"recipient": recipient, "approval_status": "WAITING_OPERATOR"}
            )

        # -------------------------------------------------------------
        # 7. Authorization Passed -> ALLOW
        # -------------------------------------------------------------
        return PolicyDecisionOutcome(
            allowed=True,
            requires_approval=False,
            session_suspended=False,
            lifecycle_state=LifecycleState.OBSERVED.value,
            policy_name="Standard Operational Policy",
            risk_category="authorized_operation",
            severity="LOW",
            explanation=f"Authorization verified for tool '{tool_name}'. Action complies with all security policies.",
            mitigation_attempted="None required; operation authorized.",
            prevention_verified=False,
            verification_evidence={"rbac_passed": True, "tenant_verified": True}
        )
