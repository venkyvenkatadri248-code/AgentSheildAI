from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database.session import get_db
from app.models.entities import (
    Agent, SecurityEvent, Alert, ApprovalRequest, ToolCall, AgentTask, User, SecurityPolicy
)
from app.schemas.api_schemas import DashboardMetricsResponse, MetricSummary
from app.services.auth_service import get_current_user

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/metrics", response_model=DashboardMetricsResponse)
def get_dashboard_metrics(
    agent_id: Optional[str] = Query(None, description="Optional Agent UUID or key (e.g. research_agent) to filter by"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    all_agents = db.query(Agent).order_by(Agent.name).all()

    # Determine if an agent-specific filter is requested
    target_agent: Optional[Agent] = None
    if agent_id and agent_id != "all":
        target_agent = db.query(Agent).filter((Agent.id == agent_id) | (Agent.key == agent_id)).first()

    # 1. Real Database Summary Counts (Agent-Specific or Fleet-Wide)
    if target_agent:
        total_agents = 1
        active_agents = 1 if target_agent.is_active else 0
        total_security_events = db.query(func.count(SecurityEvent.id)).filter(SecurityEvent.agent_id == target_agent.id).scalar() or 0
        blocked_actions = db.query(func.count(SecurityEvent.id)).filter(
            SecurityEvent.agent_id == target_agent.id,
            SecurityEvent.execution_prevented == True
        ).scalar() or 0
        pending_approvals = db.query(func.count(ApprovalRequest.id)).filter(
            ApprovalRequest.agent_id == target_agent.id,
            ApprovalRequest.status == "PENDING"
        ).scalar() or 0
        total_tasks = db.query(func.count(ToolCall.id)).filter(ToolCall.agent_id == target_agent.id).scalar() or 0
        open_alerts = db.query(func.count(Alert.id)).filter(
            Alert.agent_id == target_agent.id,
            Alert.status == "OPEN"
        ).scalar() or 0
    else:
        total_agents = db.query(func.count(Agent.id)).scalar() or 0
        active_agents = db.query(func.count(Agent.id)).filter(Agent.is_active == True).scalar() or 0
        total_security_events = db.query(func.count(SecurityEvent.id)).scalar() or 0
        blocked_actions = db.query(func.count(SecurityEvent.id)).filter(SecurityEvent.execution_prevented == True).scalar() or 0
        pending_approvals = db.query(func.count(ApprovalRequest.id)).filter(ApprovalRequest.status == "PENDING").scalar() or 0
        total_tasks = db.query(func.count(ToolCall.id)).scalar() or 0
        open_alerts = db.query(func.count(Alert.id)).filter(Alert.status == "OPEN").scalar() or 0

    prevention_rate = 100.0
    if total_security_events > 0 and blocked_actions > 0:
        prevention_rate = round((blocked_actions / max(1, blocked_actions)) * 100.0, 1)

    metrics = MetricSummary(
        total_agents=total_agents,
        active_agents=active_agents,
        total_security_events=total_security_events,
        blocked_actions=blocked_actions,
        pending_approvals=pending_approvals,
        total_tasks=total_tasks,
        open_alerts=open_alerts,
        prevention_rate=prevention_rate
    )

    # 2. Events over time (grouped by date from real records)
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    ev_query = db.query(
        func.date(SecurityEvent.created_at).label("day"),
        func.count(SecurityEvent.id).label("count")
    ).filter(SecurityEvent.created_at >= seven_days_ago)
    
    if target_agent:
        ev_query = ev_query.filter(SecurityEvent.agent_id == target_agent.id)

    recent_events = (
        ev_query
        .group_by(func.date(SecurityEvent.created_at))
        .order_by(func.date(SecurityEvent.created_at).asc())
        .all()
    )
    events_over_time = [
        {"date": str(row.day), "events": row.count}
        for row in recent_events
    ]
    if not events_over_time:
        today_str = datetime.utcnow().strftime("%Y-%m-%d")
        events_over_time = [{"date": today_str, "events": total_security_events}]

    # 3. Actions by decision: Allowed, Blocked, Pending
    allowed_query = db.query(func.count(SecurityEvent.id)).filter(
        SecurityEvent.execution_prevented == False,
        SecurityEvent.lifecycle_state != "PENDING_APPROVAL"
    )
    if target_agent:
        allowed_query = allowed_query.filter(SecurityEvent.agent_id == target_agent.id)
    allowed_count = allowed_query.scalar() or 0

    actions_by_decision = []
    if (allowed_count + blocked_actions + pending_approvals) > 0:
        if allowed_count > 0:
            actions_by_decision.append({"name": "Allowed Actions", "value": allowed_count, "color": "#10b981"})
        if blocked_actions > 0:
            actions_by_decision.append({"name": "Blocked Actions", "value": blocked_actions, "color": "#ef4444"})
        if pending_approvals > 0:
            actions_by_decision.append({"name": "Pending Approval", "value": pending_approvals, "color": "#f59e0b"})

    # 4. Severity Distribution (Real DB query)
    sev_query = db.query(SecurityEvent.severity, func.count(SecurityEvent.id))
    if target_agent:
        sev_query = sev_query.filter(SecurityEvent.agent_id == target_agent.id)
    severity_counts = sev_query.group_by(SecurityEvent.severity).all()
    severity_distribution = [
        {"severity": sev, "count": cnt}
        for sev, cnt in severity_counts
    ]

    # 5. Agent Activity across all active agents
    agent_activity = []
    agent_comparison = []
    agent_summaries = []

    for ag in all_agents:
        sec_count = db.query(func.count(SecurityEvent.id)).filter(SecurityEvent.agent_id == ag.id).scalar() or 0
        tool_count = db.query(func.count(ToolCall.id)).filter(ToolCall.agent_id == ag.id).scalar() or 0
        ag_blocked = db.query(func.count(SecurityEvent.id)).filter(
            SecurityEvent.agent_id == ag.id,
            SecurityEvent.execution_prevented == True
        ).scalar() or 0
        ag_pending = db.query(func.count(ApprovalRequest.id)).filter(
            ApprovalRequest.agent_id == ag.id,
            ApprovalRequest.status == "PENDING"
        ).scalar() or 0
        ag_alerts = db.query(func.count(Alert.id)).filter(
            Alert.agent_id == ag.id,
            Alert.status == "OPEN"
        ).scalar() or 0
        ag_allowed = db.query(func.count(SecurityEvent.id)).filter(
            SecurityEvent.agent_id == ag.id,
            SecurityEvent.execution_prevented == False,
            SecurityEvent.lifecycle_state != "PENDING_APPROVAL"
        ).scalar() or 0

        total_act = max(sec_count, tool_count)
        agent_activity.append({"agent": ag.name, "activity": total_act})

        agent_comparison.append({
            "agent": ag.name,
            "agent_key": ag.key,
            "allowed": ag_allowed,
            "blocked": ag_blocked,
            "pending": ag_pending,
            "total": ag_allowed + ag_blocked + ag_pending
        })

        # Calculate health status
        health = "SECURE"
        if ag_pending > 0:
            health = "PENDING_APPROVAL"
        elif ag_alerts > 0:
            health = "ATTENTION"

        agent_summaries.append({
            "id": ag.id,
            "key": ag.key,
            "name": ag.name,
            "icon": ag.icon,
            "description": ag.description,
            "is_active": ag.is_active,
            "allowed_tools": ag.allowed_tools or [],
            "total_tasks": tool_count,
            "blocked_actions": ag_blocked,
            "pending_approvals": ag_pending,
            "open_alerts": ag_alerts,
            "total_events": sec_count,
            "prevention_rate": 100.0,
            "health_status": health
        })

    # 6. Tool Usage Breakdown
    tool_query = db.query(ToolCall.tool_name, func.count(ToolCall.id))
    if target_agent:
        tool_query = tool_query.filter(ToolCall.agent_id == target_agent.id)
    raw_tools = tool_query.group_by(ToolCall.tool_name).order_by(func.count(ToolCall.id).desc()).limit(8).all()
    
    tool_usage_breakdown = [
        {"tool": t_name, "count": cnt}
        for t_name, cnt in raw_tools
    ]

    # If tool calls in tool_calls table are few, also supplement from security_events tool_name
    if not tool_usage_breakdown:
        sec_tools_query = db.query(SecurityEvent.tool_name, func.count(SecurityEvent.id))
        if target_agent:
            sec_tools_query = sec_tools_query.filter(SecurityEvent.agent_id == target_agent.id)
        raw_sec_tools = sec_tools_query.group_by(SecurityEvent.tool_name).limit(8).all()
        tool_usage_breakdown = [
            {"tool": t_name, "count": cnt}
            for t_name, cnt in raw_sec_tools
        ]

    # 7. Threat Category Breakdown
    threat_query = db.query(SecurityEvent.risk_category, func.count(SecurityEvent.id))
    if target_agent:
        threat_query = threat_query.filter(SecurityEvent.agent_id == target_agent.id)
    raw_threats = threat_query.group_by(SecurityEvent.risk_category).all()
    
    threat_category_breakdown = [
        {"category": cat.replace("_", " ").title(), "count": cnt, "raw_category": cat}
        for cat, cnt in raw_threats
    ]

    # 8. Recent Activity Stream
    activity_query = db.query(SecurityEvent).order_by(SecurityEvent.created_at.desc())
    if target_agent:
        activity_query = activity_query.filter(SecurityEvent.agent_id == target_agent.id)
    
    recent_events_rows = activity_query.limit(15).all()
    recent_activity = [
        {
            "id": ev.id,
            "decision_id": ev.decision_id,
            "timestamp": ev.created_at.isoformat(),
            "agent_id": ev.agent_id,
            "agent_name": ev.agent.name if ev.agent else "System",
            "agent_key": ev.agent.key if ev.agent else "",
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

    # 9. Selected Agent metadata (if filtered)
    selected_agent_dict = None
    if target_agent:
        selected_agent_dict = {
            "id": target_agent.id,
            "key": target_agent.key,
            "name": target_agent.name,
            "icon": target_agent.icon,
            "description": target_agent.description,
            "is_active": target_agent.is_active,
            "allowed_tools": target_agent.allowed_tools or [],
            "system_prompt": target_agent.system_prompt
        }

    return DashboardMetricsResponse(
        metrics=metrics,
        events_over_time=events_over_time,
        actions_by_decision=actions_by_decision,
        severity_distribution=severity_distribution,
        agent_activity=agent_activity,
        recent_activity=recent_activity,
        selected_agent=selected_agent_dict,
        agent_summaries=agent_summaries,
        agent_comparison=agent_comparison,
        tool_usage_breakdown=tool_usage_breakdown,
        threat_category_breakdown=threat_category_breakdown
    )
