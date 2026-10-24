import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Text, Boolean, Integer, DateTime, ForeignKey, JSON
)
from sqlalchemy.orm import relationship
from app.database.session import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=False)
    role = Column(String(50), default="user", nullable=False)  # admin, analyst, user
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    conversations = relationship("Conversation", back_populates="user", cascade="all, delete-orphan")
    files = relationship("UploadedFile", back_populates="user", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="user")
    approvals = relationship("ApprovalRequest", back_populates="user", foreign_keys="ApprovalRequest.user_id")


class Agent(Base):
    __tablename__ = "agents"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    key = Column(String(50), unique=True, index=True, nullable=False)  # research_agent, file_agent, data_analysis_agent, mail_agent
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    icon = Column(String(50), default="bot", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    system_prompt = Column(Text, nullable=False)
    allowed_tools = Column(JSON, default=list, nullable=False)  # list of allowed tool names
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    conversations = relationship("Conversation", back_populates="agent")
    security_events = relationship("SecurityEvent", back_populates="agent")


class SecurityPolicy(Base):
    __tablename__ = "security_policies"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(100), unique=True, index=True, nullable=False)
    category = Column(String(50), nullable=False)  # prompt_injection, sensitive_data, file_security, tool_auth, mail_guard
    risk_level = Column(String(20), default="HIGH", nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    description = Column(Text, nullable=False)
    is_enabled = Column(Boolean, default=True, nullable=False)
    requires_approval = Column(Boolean, default=False, nullable=False)
    config = Column(JSON, default=dict, nullable=False)
    version = Column(Integer, default=1, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    versions = relationship("PolicyVersion", back_populates="policy", cascade="all, delete-orphan")


class PolicyVersion(Base):
    __tablename__ = "policy_versions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    policy_id = Column(String(36), ForeignKey("security_policies.id", ondelete="CASCADE"), nullable=False)
    version = Column(Integer, nullable=False)
    changed_by = Column(String(255), nullable=False)
    changes_summary = Column(Text, nullable=False)
    snapshot = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    policy = relationship("SecurityPolicy", back_populates="versions")


class Conversation(Base):
    __tablename__ = "conversations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    agent_id = Column(String(36), ForeignKey("agents.id"), index=True, nullable=False)
    title = Column(String(255), default="New Conversation", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="conversations")
    agent = relationship("Agent", back_populates="conversations")
    messages = relationship("Message", back_populates="conversation", cascade="all, delete-orphan", order_by="Message.created_at")
    tasks = relationship("AgentTask", back_populates="conversation", cascade="all, delete-orphan")
    security_events = relationship("SecurityEvent", back_populates="conversation")


class Message(Base):
    __tablename__ = "messages"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    conversation_id = Column(String(36), ForeignKey("conversations.id", ondelete="CASCADE"), index=True, nullable=False)
    sender = Column(String(20), nullable=False)  # user, assistant, system
    content = Column(Text, nullable=False)
    model = Column(String(50), nullable=True)
    tokens_used = Column(Integer, default=0, nullable=False)
    execution_status = Column(String(50), default="COMPLETED", nullable=False)  # COMPLETED, FAILED, CANCELLED, BLOCKED
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    conversation = relationship("Conversation", back_populates="messages")


class AgentTask(Base):
    __tablename__ = "agent_tasks"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    conversation_id = Column(String(36), ForeignKey("conversations.id", ondelete="CASCADE"), index=True, nullable=False)
    agent_id = Column(String(36), ForeignKey("agents.id"), nullable=False)
    task_type = Column(String(100), nullable=False)
    status = Column(String(50), default="PENDING", nullable=False)  # PENDING, RUNNING, COMPLETED, FAILED, CANCELLED
    input_payload = Column(JSON, default=dict, nullable=False)
    result_payload = Column(JSON, default=dict, nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    conversation = relationship("Conversation", back_populates="tasks")
    tool_calls = relationship("ToolCall", back_populates="task", cascade="all, delete-orphan")


class ToolCall(Base):
    __tablename__ = "tool_calls"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    task_id = Column(String(36), ForeignKey("agent_tasks.id", ondelete="CASCADE"), nullable=True)
    conversation_id = Column(String(36), ForeignKey("conversations.id", ondelete="CASCADE"), index=True, nullable=False)
    agent_id = Column(String(36), ForeignKey("agents.id"), nullable=False)
    tool_name = Column(String(100), nullable=False)
    arguments = Column(JSON, default=dict, nullable=False)
    result = Column(JSON, nullable=True)
    security_decision_id = Column(String(36), nullable=True)
    status = Column(String(50), default="OBSERVED", nullable=False)  # OBSERVED, ALLOWED, BLOCKED, PENDING_APPROVAL, EXECUTED, FAILED
    error_message = Column(Text, nullable=True)
    executed_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    task = relationship("AgentTask", back_populates="tool_calls")


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    decision_id = Column(String(36), unique=True, index=True, nullable=False)
    actor_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    agent_id = Column(String(36), ForeignKey("agents.id"), nullable=False)
    conversation_id = Column(String(36), ForeignKey("conversations.id"), nullable=True)
    tool_name = Column(String(100), nullable=False)
    risk_category = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    
    # Strictly validated lifecycle states:
    # OBSERVED, SUSPICIOUS, DETECTED, BLOCKED, PENDING_APPROVAL,
    # MITIGATION_IN_PROGRESS, PREVENTION_VERIFIED, VERIFICATION_FAILED,
    # TASK_COMPLETED, TASK_FAILED
    lifecycle_state = Column(String(50), default="OBSERVED", nullable=False)
    
    policy_id = Column(String(36), ForeignKey("security_policies.id"), nullable=True)
    policy_version = Column(Integer, default=1, nullable=False)
    evidence = Column(JSON, default=dict, nullable=False)
    explanation = Column(Text, nullable=False)
    execution_prevented = Column(Boolean, default=False, nullable=False)
    verification_status = Column(String(50), default="UNVERIFIED", nullable=False)  # UNVERIFIED, VERIFIED, FAILED
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    agent = relationship("Agent", back_populates="security_events")
    conversation = relationship("Conversation", back_populates="security_events")
    alert = relationship("Alert", back_populates="security_event", uselist=False)
    approval_request = relationship("ApprovalRequest", back_populates="security_event", uselist=False)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    security_event_id = Column(String(36), ForeignKey("security_events.id", ondelete="CASCADE"), unique=True, nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(50), default="OPEN", nullable=False)  # OPEN, ACKNOWLEDGED, RESOLVED, DISMISSED
    agent_id = Column(String(36), ForeignKey("agents.id"), nullable=False)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    resolved_by = Column(String(255), nullable=True)
    resolution_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    security_event = relationship("SecurityEvent", back_populates="alert")
    user = relationship("User", back_populates="alerts")


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    security_event_id = Column(String(36), ForeignKey("security_events.id", ondelete="CASCADE"), unique=True, nullable=False)
    tool_call_id = Column(String(36), nullable=True)
    agent_id = Column(String(36), ForeignKey("agents.id"), nullable=False)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    tool_name = Column(String(100), nullable=False)
    arguments_preview = Column(JSON, default=dict, nullable=False)
    risk_explanation = Column(Text, nullable=False)
    status = Column(String(50), default="PENDING", nullable=False)  # PENDING, APPROVED, REJECTED
    reviewer_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    review_notes = Column(Text, nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    security_event = relationship("SecurityEvent", back_populates="approval_request")
    user = relationship("User", back_populates="approvals", foreign_keys=[user_id])


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    actor_id = Column(String(36), nullable=False)
    action = Column(String(100), nullable=False)  # LOGIN, POLICY_UPDATE, APPROVAL_DECISION, TOOL_EXECUTE, FILE_UPLOAD
    target_type = Column(String(50), nullable=False)
    target_id = Column(String(36), nullable=True)
    details = Column(JSON, default=dict, nullable=False)
    ip_address = Column(String(45), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class UploadedFile(Base):
    __tablename__ = "uploaded_files"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    filename = Column(String(255), nullable=False)
    original_name = Column(String(255), nullable=False)
    file_type = Column(String(50), nullable=False)
    file_size = Column(Integer, nullable=False)
    storage_path = Column(String(500), nullable=False)
    extracted_text = Column(Text, nullable=True)
    metadata_json = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="files")
