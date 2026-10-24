from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, ConfigDict


# ==============================
# Authentication Schemas
# ==============================
class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)
    full_name: str
    role: Optional[str] = "user"


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: Dict[str, Any]


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ==============================
# Agent Schemas
# ==============================
class AgentResponse(BaseModel):
    id: str
    key: str
    name: str
    description: str
    icon: str
    is_active: bool
    allowed_tools: List[str]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ==============================
# Conversation & Message Schemas
# ==============================
class ConversationCreate(BaseModel):
    agent_key: str
    title: Optional[str] = "New Conversation"


class ConversationUpdate(BaseModel):
    title: str


class MessageResponse(BaseModel):
    id: str
    conversation_id: str
    sender: str
    content: str
    model: Optional[str] = None
    tokens_used: int = 0
    execution_status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ConversationResponse(BaseModel):
    id: str
    user_id: str
    agent_id: str
    title: str
    created_at: datetime
    updated_at: datetime
    agent: Optional[AgentResponse] = None
    messages: Optional[List[MessageResponse]] = None

    model_config = ConfigDict(from_attributes=True)


class MessageSubmitRequest(BaseModel):
    content: str


# ==============================
# Security & Policy Schemas
# ==============================
class PolicyResponse(BaseModel):
    id: str
    name: str
    category: str
    risk_level: str
    description: str
    is_enabled: bool
    requires_approval: bool
    config: Dict[str, Any]
    version: int
    updated_at: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PolicyUpdateRequest(BaseModel):
    is_enabled: Optional[bool] = None
    requires_approval: Optional[bool] = None
    risk_level: Optional[str] = None
    description: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    changes_summary: str = "Updated policy configuration"


class PolicyVersionResponse(BaseModel):
    id: str
    policy_id: str
    version: int
    changed_by: str
    changes_summary: str
    snapshot: Dict[str, Any]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ==============================
# Security Decision & Event Schemas
# ==============================
class SecurityDecision(BaseModel):
    decision_id: str
    allowed: bool
    requires_approval: bool
    lifecycle_state: str  # OBSERVED, SUSPICIOUS, DETECTED, BLOCKED, PENDING_APPROVAL, etc.
    risk_category: str
    severity: str
    policy_name: Optional[str] = None
    explanation: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    execution_prevented: bool = False
    verification_status: str = "UNVERIFIED"


class SecurityEventResponse(BaseModel):
    id: str
    decision_id: str
    actor_id: str
    agent_id: str
    conversation_id: Optional[str] = None
    tool_name: str
    risk_category: str
    severity: str
    lifecycle_state: str
    policy_id: Optional[str] = None
    policy_version: int
    evidence: Dict[str, Any]
    explanation: str
    execution_prevented: bool
    verification_status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ==============================
# Alerts Schemas
# ==============================
class AlertResponse(BaseModel):
    id: str
    security_event_id: str
    title: str
    description: str
    severity: str
    status: str
    agent_id: str
    user_id: str
    resolved_by: Optional[str] = None
    resolution_notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    security_event: Optional[SecurityEventResponse] = None

    model_config = ConfigDict(from_attributes=True)


class AlertStatusUpdate(BaseModel):
    status: str  # OPEN, ACKNOWLEDGED, RESOLVED, DISMISSED
    resolution_notes: Optional[str] = None


# ==============================
# Approvals Schemas
# ==============================
class ApprovalRequestResponse(BaseModel):
    id: str
    security_event_id: str
    tool_call_id: Optional[str] = None
    agent_id: str
    user_id: str
    tool_name: str
    arguments_preview: Dict[str, Any]
    risk_explanation: str
    status: str  # PENDING, APPROVED, REJECTED
    reviewer_id: Optional[str] = None
    review_notes: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ApprovalDecisionRequest(BaseModel):
    status: str  # APPROVED, REJECTED
    notes: Optional[str] = None


# ==============================
# History & Tool Calls
# ==============================
class ToolCallResponse(BaseModel):
    id: str
    task_id: Optional[str] = None
    conversation_id: str
    agent_id: str
    tool_name: str
    arguments: Dict[str, Any]
    result: Optional[Dict[str, Any]] = None
    security_decision_id: Optional[str] = None
    status: str
    error_message: Optional[str] = None
    executed_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AuditEventResponse(BaseModel):
    id: str
    actor_id: str
    action: str
    target_type: str
    target_id: Optional[str] = None
    details: Dict[str, Any]
    ip_address: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ==============================
# Dashboard Schemas
# ==============================
class MetricSummary(BaseModel):
    total_agents: int
    active_agents: int
    total_security_events: int
    blocked_actions: int
    pending_approvals: int
    total_tasks: int
    open_alerts: int


class DashboardMetricsResponse(BaseModel):
    metrics: MetricSummary
    events_over_time: List[Dict[str, Any]]
    actions_by_decision: List[Dict[str, Any]]  # blocked vs allowed
    severity_distribution: List[Dict[str, Any]]
    agent_activity: List[Dict[str, Any]]
    recent_activity: List[Dict[str, Any]]


# ==============================
# File Schemas
# ==============================
class FileUploadResponse(BaseModel):
    id: str
    filename: str
    original_name: str
    file_type: str
    file_size: int
    extracted_text_preview: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
