export interface User {
  id: string;
  email: string;
  full_name: string;
  role: 'admin' | 'analyst' | 'user';
  created_at?: string;
}

export interface Agent {
  id: string;
  key: 'research_agent' | 'file_agent' | 'data_analysis_agent' | 'mail_agent';
  name: string;
  description: string;
  icon: string;
  is_active: boolean;
  allowed_tools: string[];
  created_at: string;
}

export interface Message {
  id: string;
  conversation_id: string;
  sender: 'user' | 'assistant' | 'system';
  content: string;
  model?: string;
  tokens_used: number;
  execution_status: string;
  created_at: string;
}

export interface Conversation {
  id: string;
  user_id: string;
  agent_id: string;
  title: string;
  created_at: string;
  updated_at: string;
  agent?: Agent;
  messages?: Message[];
}

export interface SecurityDecision {
  decision_id: string;
  allowed: boolean;
  requires_approval: boolean;
  lifecycle_state: string;
  risk_category: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  policy_name?: string;
  explanation: string;
  evidence: Record<string, any>;
  execution_prevented: boolean;
  verification_status: string;
}

export interface SecurityEvent {
  id: string;
  decision_id: string;
  actor_id: string;
  agent_id: string;
  conversation_id?: string;
  tool_name: string;
  risk_category: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  lifecycle_state: string;
  policy_id?: string;
  policy_version: number;
  evidence: Record<string, any>;
  explanation: string;
  execution_prevented: boolean;
  verification_status: string;
  created_at: string;
}

export interface Alert {
  id: string;
  security_event_id: string;
  title: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED' | 'DISMISSED';
  agent_id: string;
  user_id: string;
  resolved_by?: string;
  resolution_notes?: string;
  created_at: string;
  updated_at: string;
  security_event?: SecurityEvent;
}

export interface Policy {
  id: string;
  name: string;
  category: string;
  risk_level: string;
  description: string;
  is_enabled: boolean;
  requires_approval: boolean;
  config: Record<string, any>;
  version: number;
  updated_at: string;
  created_at: string;
}

export interface PolicyVersion {
  id: string;
  policy_id: string;
  version: number;
  changed_by: string;
  changes_summary: string;
  snapshot: Record<string, any>;
  created_at: string;
}

export interface ApprovalRequest {
  id: string;
  security_event_id: string;
  tool_call_id?: string;
  agent_id: string;
  user_id: string;
  tool_name: string;
  arguments_preview: Record<string, any>;
  risk_explanation: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
  reviewer_id?: string;
  review_notes?: string;
  reviewed_at?: string;
  created_at: string;
}

export interface MetricSummary {
  total_agents: number;
  active_agents: number;
  total_security_events: number;
  blocked_actions: number;
  pending_approvals: number;
  total_tasks: number;
  open_alerts: number;
  prevention_rate?: number;
}

export interface AgentSummary {
  id: string;
  key: string;
  name: string;
  icon: string;
  description: string;
  is_active: boolean;
  allowed_tools: string[];
  total_tasks: number;
  blocked_actions: number;
  pending_approvals: number;
  open_alerts: number;
  total_events: number;
  prevention_rate: number;
  health_status: 'SECURE' | 'PENDING_APPROVAL' | 'ATTENTION';
}

export interface DashboardMetrics {
  metrics: MetricSummary;
  events_over_time: { date: string; events: number }[];
  actions_by_decision: { name: string; value: number; color: string }[];
  severity_distribution: { severity: string; count: number }[];
  agent_activity: { agent: string; activity: number }[];
  recent_activity: any[];
  selected_agent?: {
    id: string;
    key: string;
    name: string;
    icon: string;
    description: string;
    is_active: boolean;
    allowed_tools: string[];
    system_prompt?: string;
  } | null;
  agent_summaries: AgentSummary[];
  agent_comparison: {
    agent: string;
    agent_key: string;
    allowed: number;
    blocked: number;
    pending: number;
    total: number;
  }[];
  tool_usage_breakdown: { tool: string; count: number }[];
  threat_category_breakdown: { category: string; count: number; raw_category: string }[];
}

export interface UploadedFileItem {
  id: string;
  filename: string;
  original_name: string;
  file_type: string;
  file_size: number;
  extracted_text_preview?: string;
  created_at: string;
}
