from typing import List
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.entities import SecurityPolicy, PolicyVersion, User, AuditEvent
from app.schemas.api_schemas import PolicyResponse, PolicyUpdateRequest, PolicyVersionResponse
from app.services.auth_service import get_current_user

router = APIRouter(prefix="/protection", tags=["Protection Policies"])


@router.get("/policies", response_model=List[PolicyResponse])
def list_policies(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(SecurityPolicy).order_by(SecurityPolicy.name.asc()).all()


@router.get("/policies/{id}", response_model=PolicyResponse)
def get_policy(id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    pol = db.query(SecurityPolicy).filter(SecurityPolicy.id == id).first()
    if not pol:
        raise HTTPException(status_code=404, detail="Policy not found")
    return pol


@router.patch("/policies/{id}", response_model=PolicyResponse)
def update_policy(
    id: str,
    req: PolicyUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    pol = db.query(SecurityPolicy).filter(SecurityPolicy.id == id).first()
    if not pol:
        raise HTTPException(status_code=404, detail="Policy not found")

    old_snapshot = {
        "is_enabled": pol.is_enabled,
        "requires_approval": pol.requires_approval,
        "risk_level": pol.risk_level,
        "config": pol.config,
        "version": pol.version
    }

    if req.is_enabled is not None:
        pol.is_enabled = req.is_enabled
    if req.requires_approval is not None:
        pol.requires_approval = req.requires_approval
    if req.risk_level is not None:
        pol.risk_level = req.risk_level.upper()
    if req.description is not None:
        pol.description = req.description
    if req.config is not None:
        pol.config = req.config

    pol.version += 1
    pol.updated_at = datetime.utcnow()

    # Save version history
    new_snapshot = {
        "is_enabled": pol.is_enabled,
        "requires_approval": pol.requires_approval,
        "risk_level": pol.risk_level,
        "config": pol.config,
        "version": pol.version
    }

    version_record = PolicyVersion(
        policy_id=pol.id,
        version=pol.version,
        changed_by=current_user.email,
        changes_summary=req.changes_summary,
        snapshot=new_snapshot
    )
    db.add(version_record)

    audit = AuditEvent(
        actor_id=current_user.id,
        action="POLICY_UPDATED",
        target_type="policy",
        target_id=pol.id,
        details={
            "policy_name": pol.name,
            "version": pol.version,
            "old": old_snapshot,
            "new": new_snapshot,
            "summary": req.changes_summary
        }
    )
    db.add(audit)
    db.commit()
    db.refresh(pol)
    return pol


@router.get("/policies/{id}/versions", response_model=List[PolicyVersionResponse])
def get_policy_versions(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return db.query(PolicyVersion).filter(PolicyVersion.policy_id == id).order_by(PolicyVersion.version.desc()).all()


@router.get("/framework")
def get_protection_framework(current_user: User = Depends(get_current_user)):
    """
    Returns the formal specification and runtime capabilities of AgentShieldAI's
    core security principle: DETECT · EXPLAIN · PREVENT.
    """
    return {
        "tagline": "DETECT · EXPLAIN · PREVENT",
        "pillars": {
            "detect": {
                "title": "Threat Detection",
                "tagline": "Perimeter & Runtime Multi-Layer Threat Inspection",
                "summary": "Every user input and autonomous agent tool invocation is intercepted and screened across deterministic pattern engines, AST parsers, and ML threat evaluators before execution.",
                "capabilities": [
                    {
                        "name": "Prompt Injection & Jailbreaks",
                        "description": "Instruction overrides, adversarial roleplays, DAN personas, and bracketed system command emulation.",
                        "status": "ACTIVE",
                        "severity": "CRITICAL"
                    },
                    {
                        "name": "Sensitive Data & PII Exposure",
                        "description": "Payment card numbers, Social Security Numbers, AWS access keys, Bearer tokens, and API secrets.",
                        "status": "ACTIVE",
                        "severity": "CRITICAL"
                    },
                    {
                        "name": "Path Traversal & Restricted Files",
                        "description": "Directory traversal sequences (../), access to .env, SSH keys, settings, and OS system files.",
                        "status": "ACTIVE",
                        "severity": "HIGH"
                    },
                    {
                        "name": "Prohibited Code Execution",
                        "description": "Dynamic script execution (eval, exec), os.system shell calls, and unauthorized subprocess spawning.",
                        "status": "ACTIVE",
                        "severity": "CRITICAL"
                    },
                    {
                        "name": "Unapproved Database Mutations",
                        "description": "Destructive SQL statements (DROP TABLE, TRUNCATE, DELETE FROM, UNION SELECT injections).",
                        "status": "ACTIVE",
                        "severity": "CRITICAL"
                    },
                    {
                        "name": "SSRF & Restricted Networks",
                        "description": "Cloud Instance Metadata Service (169.254.169.254), loopback interfaces, and RFC1918 private subnets.",
                        "status": "ACTIVE",
                        "severity": "CRITICAL"
                    },
                    {
                        "name": "Cross-User Tenant Isolation",
                        "description": "Cryptographic file ownership and dataset tenancy boundaries preventing cross-account access.",
                        "status": "ACTIVE",
                        "severity": "HIGH"
                    },
                    {
                        "name": "Mail Safety & Broadcast Filters",
                        "description": "Outbound email sanitization, mass-distribution prevention, and sensitive attachment blocking.",
                        "status": "ACTIVE",
                        "severity": "HIGH"
                    }
                ]
            },
            "explain": {
                "title": "Threat Explainability",
                "tagline": "Transparent Risk Rationale & Contextual Attribution",
                "summary": "AgentShieldAI eliminates opaque security black-boxes by generating human-comprehensible risk justifications, violated policy citations, and auditable technical evidence.",
                "capabilities": [
                    {
                        "name": "Risk Impact Analysis",
                        "description": "Translates technical threat signatures into contextual explanations detailing exploit mechanisms and potential system harm."
                    },
                    {
                        "name": "Policy & Governance Mapping",
                        "description": "Direct attribution to active security policies, including configuration versioning and governance clauses."
                    },
                    {
                        "name": "Technical Evidence Extraction",
                        "description": "Preserves matched patterns, parameter snippets, and redacted tokens for SOC analyst verification."
                    },
                    {
                        "name": "Machine Learning Threat Scoring",
                        "description": "Continuous runtime scoring from trained anomaly detection models supplementing deterministic guardrails."
                    }
                ]
            },
            "prevent": {
                "title": "Threat Prevention",
                "tagline": "Zero-Trust Pre-Execution Halting & Verifiable Integrity",
                "summary": "Threats are intercepted and stopped prior to execution. Systems and datasets remain completely unmodified with auditable prevention verification.",
                "capabilities": [
                    {
                        "name": "Pre-Execution Gate Enforcement",
                        "description": "Zero-trust interception halting actions before any filesystem, network, email, or database calls occur."
                    },
                    {
                        "name": "Lifecycle State Guarantee",
                        "description": "Strict state machine progression: OBSERVED -> DETECTED -> BLOCKED -> PREVENTION_VERIFIED."
                    },
                    {
                        "name": "Target Resource Integrity Verification",
                        "description": "Guaranteed post-verification confirming zero mutations and unmodified target resource states."
                    },
                    {
                        "name": "Human-In-The-Loop Approval Gates",
                        "description": "Mandatory sign-off workflows pausing high-impact operations until authorized by a designated operator."
                    },
                    {
                        "name": "Real-Time Telemetry & SOC Sync",
                        "description": "Instant WebSocket broadcasting to the Operations Dashboard, Security Alerts queue, and immutable Audit Log."
                    }
                ]
            }
        }
    }
