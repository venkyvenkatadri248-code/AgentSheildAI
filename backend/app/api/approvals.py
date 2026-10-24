from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.entities import ApprovalRequest, SecurityEvent, ToolCall, User, AuditEvent
from app.schemas.api_schemas import ApprovalRequestResponse, ApprovalDecisionRequest
from app.services.auth_service import get_current_user
from app.security.lifecycle import LifecycleState
from app.agents.agent_tools import execute_tool
from app.services.event_broadcaster import broadcaster

router = APIRouter(prefix="/approvals", tags=["Approvals"])


@router.get("", response_model=List[ApprovalRequestResponse])
def list_approvals(
    status: Optional[str] = "PENDING",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(ApprovalRequest)
    if status and status.upper() != "ALL":
        query = query.filter(ApprovalRequest.status == status.upper())
    return query.order_by(ApprovalRequest.created_at.desc()).all()


@router.get("/{id}", response_model=ApprovalRequestResponse)
def get_approval(id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    appr = db.query(ApprovalRequest).filter(ApprovalRequest.id == id).first()
    if not appr:
        raise HTTPException(status_code=404, detail="Approval request not found")
    return appr


@router.post("/{id}/decide", response_model=ApprovalRequestResponse)
def decide_approval(
    id: str,
    req: ApprovalDecisionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    appr = db.query(ApprovalRequest).filter(ApprovalRequest.id == id).first()
    if not appr:
        raise HTTPException(status_code=404, detail="Approval request not found")
    if appr.status != "PENDING":
        raise HTTPException(status_code=400, detail=f"Request already decided as {appr.status}")

    decision_status = req.status.upper()
    if decision_status not in ["APPROVED", "REJECTED"]:
        raise HTTPException(status_code=400, detail="Decision must be APPROVED or REJECTED")

    appr.status = decision_status
    appr.reviewer_id = current_user.id
    appr.review_notes = req.notes
    appr.reviewed_at = datetime.utcnow()

    event = db.query(SecurityEvent).filter(SecurityEvent.id == appr.security_event_id).first()

    execution_result = None
    if decision_status == "APPROVED":
        if event:
            event.lifecycle_state = LifecycleState.MITIGATION_IN_PROGRESS.value
            event.execution_prevented = False
        
        # Execute the tool after human approval
        try:
            execution_result = execute_tool(
                tool_name=appr.tool_name,
                arguments=appr.arguments_preview,
                db=db,
                actor=current_user
            )
            if event:
                event.lifecycle_state = LifecycleState.TASK_COMPLETED.value
                event.verification_status = "VERIFIED"
                event.explanation += f" [Approved by {current_user.email}]: Operation executed and verified successfully."
        except Exception as e:
            if event:
                event.lifecycle_state = LifecycleState.TASK_FAILED.value
                event.verification_status = "VERIFICATION_FAILED"
                event.explanation += f" [Approved by {current_user.email}]: Execution failed: {str(e)}"
    else:
        # Rejected
        if event:
            event.lifecycle_state = LifecycleState.PREVENTION_VERIFIED.value
            event.execution_prevented = True
            event.verification_status = "VERIFIED"
            event.explanation += f" [Rejected by {current_user.email}]: Action permanently blocked by operator decision."

    audit = AuditEvent(
        actor_id=current_user.id,
        action=f"APPROVAL_{decision_status}",
        target_type="approval_request",
        target_id=appr.id,
        details={
            "tool_name": appr.tool_name,
            "decision": decision_status,
            "notes": req.notes,
            "result": execution_result
        }
    )
    db.add(audit)
    db.commit()
    db.refresh(appr)

    broadcaster.broadcast_sync("approval_decided", {
        "approval_id": appr.id,
        "tool": appr.tool_name,
        "decision": decision_status,
        "reviewer": current_user.email
    })

    return appr
