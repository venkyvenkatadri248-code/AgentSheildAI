from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.entities import SecurityEvent, ToolCall, AuditEvent, User
from app.schemas.api_schemas import (
    SecurityEventResponse, ToolCallResponse, AuditEventResponse
)
from app.services.auth_service import get_current_user

router = APIRouter(prefix="/history", tags=["History & Audit"])


@router.get("/events", response_model=List[SecurityEventResponse])
def list_security_events(
    risk_category: Optional[str] = None,
    severity: Optional[str] = None,
    lifecycle_state: Optional[str] = None,
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(SecurityEvent)
    if risk_category:
        query = query.filter(SecurityEvent.risk_category == risk_category)
    if severity:
        query = query.filter(SecurityEvent.severity == severity.upper())
    if lifecycle_state:
        query = query.filter(SecurityEvent.lifecycle_state == lifecycle_state.upper())

    return query.order_by(SecurityEvent.created_at.desc()).limit(limit).all()


@router.get("/tool-calls", response_model=List[ToolCallResponse])
def list_tool_calls(
    agent_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(ToolCall)
    if agent_id:
        query = query.filter(ToolCall.agent_id == agent_id)
    if status:
        query = query.filter(ToolCall.status == status.upper())

    return query.order_by(ToolCall.executed_at.desc()).limit(limit).all()


@router.get("/audits", response_model=List[AuditEventResponse])
def list_audit_events(
    action: Optional[str] = None,
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(AuditEvent)
    if action:
        query = query.filter(AuditEvent.action == action.upper())

    return query.order_by(AuditEvent.created_at.desc()).limit(limit).all()
