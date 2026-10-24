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
