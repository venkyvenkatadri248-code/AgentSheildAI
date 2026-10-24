from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, joinedload

from app.database.session import get_db
from app.models.entities import Alert, SecurityEvent, User, AuditEvent
from app.schemas.api_schemas import AlertResponse, AlertStatusUpdate
from app.services.auth_service import get_current_user

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("", response_model=List[AlertResponse])
def list_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    agent_id: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Alert).options(joinedload(Alert.security_event))
    if severity:
        query = query.filter(Alert.severity == severity.upper())
    if status:
        query = query.filter(Alert.status == status.upper())
    if agent_id:
        query = query.filter(Alert.agent_id == agent_id)
    if search:
        search_filter = f"%{search}%"
        query = query.filter(
            (Alert.title.ilike(search_filter)) | (Alert.description.ilike(search_filter))
        )
    return query.order_by(Alert.created_at.desc()).all()


@router.get("/{id}", response_model=AlertResponse)
def get_alert(id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    alert = db.query(Alert).options(joinedload(Alert.security_event)).filter(Alert.id == id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{id}/status", response_model=AlertResponse)
def update_alert_status(
    id: str,
    req: AlertStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    alert = db.query(Alert).filter(Alert.id == id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    new_status = req.status.upper()
    if new_status not in ["OPEN", "ACKNOWLEDGED", "RESOLVED", "DISMISSED"]:
        raise HTTPException(status_code=400, detail="Invalid alert status")

    old_status = alert.status
    alert.status = new_status
    alert.resolved_by = current_user.email
    if req.resolution_notes:
        alert.resolution_notes = req.resolution_notes
    alert.updated_at = datetime.utcnow()

    audit = AuditEvent(
        actor_id=current_user.id,
        action="ALERT_STATUS_UPDATE",
        target_type="alert",
        target_id=alert.id,
        details={
            "old_status": old_status,
            "new_status": new_status,
            "notes": req.resolution_notes
        }
    )
    db.add(audit)
    db.commit()
    db.refresh(alert)
    return alert
