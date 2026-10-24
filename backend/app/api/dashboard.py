from datetime import datetime, timedelta
from typing import Dict, Any, List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database.session import get_db
from app.models.entities import (
    Agent, SecurityEvent, Alert, ApprovalRequest, ToolCall, AgentTask, User
)
from app.schemas.api_schemas import DashboardMetricsResponse, MetricSummary
from app.services.auth_service import get_current_user

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/metrics", response_model=DashboardMetricsResponse)
def get_dashboard_metrics(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # 1. Real Database Summary Counts
    total_agents = db.query(func.count(Agent.id)).scalar() or 0
    active_agents = db.query(func.count(Agent.id)).filter(Agent.is_active == True).scalar() or 0
    total_security_events = db.query(func.count(SecurityEvent.id)).scalar() or 0
    blocked_actions = db.query(func.count(SecurityEvent.id)).filter(SecurityEvent.execution_prevented == True).scalar() or 0
    pending_approvals = db.query(func.count(ApprovalRequest.id)).filter(ApprovalRequest.status == "PENDING").scalar() or 0
    total_tasks = db.query(func.count(ToolCall.id)).scalar() or 0
    open_alerts = db.query(func.count(Alert.id)).filter(Alert.status == "OPEN").scalar() or 0

    metrics = MetricSummary(
        total_agents=total_agents,
        active_agents=active_agents,
        total_security_events=total_security_events,
        blocked_actions=blocked_actions,
        pending_approvals=pending_approvals,
        total_tasks=total_tasks,
        open_alerts=open_alerts
    )

    # 2. Events over time (grouped by date from real records)
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    recent_events = (
        db.query(
            func.date(SecurityEvent.created_at).label("day"),
            func.count(SecurityEvent.id).label("count")
        )
        .filter(SecurityEvent.created_at >= seven_days_ago)
        .group_by(func.date(SecurityEvent.created_at))
        .all()
    )
    events_over_time = [
        {"date": str(row.day), "events": row.count}
        for row in recent_events
    ]

    # 3. Actions by decision: Blocked vs Allowed
    allowed_count = total_security_events - blocked_actions
    actions_by_decision = []
    if total_security_events > 0:
        actions_by_decision = [
            {"name": "Blocked Actions", "value": blocked_actions, "color": "#ef4444"},
            {"name": "Allowed Actions", "value": max(0, allowed_count), "color": "#10b981"}
        ]

    # 4. Severity Distribution (Real DB query)
    severity_counts = (
        db.query(SecurityEvent.severity, func.count(SecurityEvent.id))
        .group_by(SecurityEvent.severity)
        .all()
    )
    severity_distribution = [
        {"severity": sev, "count": cnt}
        for sev, cnt in severity_counts
    ]

    # 5. Agent Activity
    agent_activity_rows = (
        db.query(Agent.name, func.count(SecurityEvent.id))
        .join(SecurityEvent, Agent.id == SecurityEvent.agent_id)
        .group_by(Agent.name)
        .all()
    )
    agent_activity = [
        {"agent": name, "activity": count}
        for name, count in agent_activity_rows
    ]

    # 6. Recent Activity Stream
    recent_events_rows = (
        db.query(SecurityEvent)
        .order_by(SecurityEvent.created_at.desc())
        .limit(10)
        .all()
    )
    recent_activity = [
        {
            "id": ev.id,
            "decision_id": ev.decision_id,
            "timestamp": ev.created_at.isoformat(),
            "agent_name": ev.agent.name if ev.agent else "System",
            "tool_name": ev.tool_name,
            "event_type": ev.risk_category,
            "severity": ev.severity,
            "lifecycle_state": ev.lifecycle_state,
            "execution_prevented": ev.execution_prevented,
            "explanation": ev.explanation,
            "conversation_id": ev.conversation_id
        }
        for ev in recent_events_rows
    ]

    return DashboardMetricsResponse(
        metrics=metrics,
        events_over_time=events_over_time,
        actions_by_decision=actions_by_decision,
        severity_distribution=severity_distribution,
        agent_activity=agent_activity,
        recent_activity=recent_activity
    )
