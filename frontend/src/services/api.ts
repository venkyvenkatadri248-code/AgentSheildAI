import {
  User, Agent, Conversation, Alert, Policy, PolicyVersion,
  ApprovalRequest, DashboardMetrics, UploadedFileItem
} from '../types';

const API_BASE = '/api';

export function getToken(): string | null {
  return localStorage.getItem('agentshield_token');
}

export function setToken(token: string): void {
  localStorage.setItem('agentshield_token', token);
}

export function removeToken(): void {
  localStorage.removeItem('agentshield_token');
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let errorDetail = 'Request failed';
    try {
      const errJson = await response.json();
      errorDetail = errJson.detail || errJson.message || errorDetail;
    } catch {
      errorDetail = response.statusText || errorDetail;
    }
    throw new Error(errorDetail);
  }

  if (response.status === 204) {
    return {} as T;
  }

  return response.json();
}

// ==========================================
// API Methods
// ==========================================
export const api = {
  // Auth
  async login(email: string, password: string): Promise<{ access_token: string; user: User }> {
    return request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  },

  async register(email: string, password: string, full_name: string, role = 'user'): Promise<{ access_token: string; user: User }> {
    return request('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, full_name, role }),
    });
  },

  async getMe(): Promise<User> {
    return request('/auth/me');
  },

  // Agents
  async getAgents(): Promise<Agent[]> {
    return request('/agents');
  },

  async getAgent(key: string): Promise<Agent> {
    return request(`/agents/${key}`);
  },

  // Conversations
  async getConversations(agent_key?: string): Promise<Conversation[]> {
    const query = agent_key ? `?agent_key=${agent_key}` : '';
    return request(`/conversations${query}`);
  },

  async getConversation(id: string): Promise<Conversation> {
    return request(`/conversations/${id}`);
  },

  async createConversation(agent_key: string, title?: string): Promise<Conversation> {
    return request('/conversations', {
      method: 'POST',
      body: JSON.stringify({ agent_key, title }),
    });
  },

  async renameConversation(id: string, title: string): Promise<Conversation> {
    return request(`/conversations/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ title }),
    });
  },

  async deleteConversation(id: string): Promise<void> {
    return request(`/conversations/${id}`, {
      method: 'DELETE',
    });
  },

  // Streaming Chat with Gemini & Security Gateway
  async *streamMessage(conversationId: string, content: string, signal?: AbortSignal) {
    const token = getToken();
    const response = await fetch(`${API_BASE}/conversations/${conversationId}/messages/stream`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({ content }),
      signal,
    });

    if (!response.ok) {
      let err = 'Streaming request failed';
      try {
        const json = await response.json();
        err = json.detail || err;
      } catch {}
      throw new Error(err);
    }

    const reader = response.body?.getReader();
    if (!reader) throw new Error('No readable stream available');

    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (!line.trim()) continue;
        const eventMatch = line.match(/^event: (.*)$/m);
        const dataMatch = line.match(/^data: (.*)$/m);

        const event = eventMatch ? eventMatch[1].trim() : 'chunk';
        let data: any = {};
        if (dataMatch) {
          try {
            data = JSON.parse(dataMatch[1].trim());
          } catch {
            data = { text: dataMatch[1].trim() };
          }
        }

        yield { event, data };
      }
    }
  },

  // Tools
  async executeTool(agent_key: string, tool_name: string, args: Record<string, any>, conversation_id?: string): Promise<any> {
    return request('/tools/execute', {
      method: 'POST',
      body: JSON.stringify({ agent_key, tool_name, arguments: args, conversation_id }),
    });
  },

  // Dashboard
  async getDashboardMetrics(): Promise<DashboardMetrics> {
    return request('/dashboard/metrics');
  },

  // Alerts
  async getAlerts(params: { severity?: string; status?: string; search?: string } = {}): Promise<Alert[]> {
    const query = new URLSearchParams();
    if (params.severity) query.append('severity', params.severity);
    if (params.status) query.append('status', params.status);
    if (params.search) query.append('search', params.search);
    const qs = query.toString();
    return request(`/alerts${qs ? `?${qs}` : ''}`);
  },

  async updateAlertStatus(id: string, status: string, resolution_notes?: string): Promise<Alert> {
    return request(`/alerts/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status, resolution_notes }),
    });
  },

  // Protection Policies
  async getPolicies(): Promise<Policy[]> {
    return request('/protection/policies');
  },

  async updatePolicy(id: string, updates: Partial<Policy> & { changes_summary?: string }): Promise<Policy> {
    return request(`/protection/policies/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(updates),
    });
  },

  async getPolicyVersions(id: string): Promise<PolicyVersion[]> {
    return request(`/protection/policies/${id}/versions`);
  },

  // Approvals
  async getApprovals(status = 'PENDING'): Promise<ApprovalRequest[]> {
    return request(`/approvals?status=${status}`);
  },

  async decideApproval(id: string, status: 'APPROVED' | 'REJECTED', notes?: string): Promise<ApprovalRequest> {
    return request(`/approvals/${id}/decide`, {
      method: 'POST',
      body: JSON.stringify({ status, notes }),
    });
  },

  // History & Audits
  async getSecurityHistory(params: { risk_category?: string; severity?: string; limit?: number } = {}): Promise<any[]> {
    const query = new URLSearchParams();
    if (params.risk_category) query.append('risk_category', params.risk_category);
    if (params.severity) query.append('severity', params.severity);
    if (params.limit) query.append('limit', String(params.limit));
    const qs = query.toString();
    return request(`/history/events${qs ? `?${qs}` : ''}`);
  },

  async getToolCalls(limit = 50): Promise<any[]> {
    return request(`/history/tool-calls?limit=${limit}`);
  },

  async getAuditEvents(limit = 50): Promise<any[]> {
    return request(`/history/audits?limit=${limit}`);
  },

  // Files
  async getFiles(): Promise<UploadedFileItem[]> {
    return request('/files');
  },

  async uploadFile(file: File): Promise<UploadedFileItem> {
    const token = getToken();
    const formData = new FormData();
    formData.append('file', file);

    const res = await fetch(`${API_BASE}/files/upload`, {
      method: 'POST',
      headers: {
        ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
      },
      body: formData,
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Upload failed' }));
      throw new Error(err.detail || 'Upload failed');
    }
    return res.json();
  },

  async deleteFile(id: string): Promise<void> {
    return request(`/files/${id}`, { method: 'DELETE' });
  },

  // Settings
  async getHealth(): Promise<any> {
    return request('/settings/health');
  },

  async updateGeminiKey(apiKey: string): Promise<any> {
    return request('/settings/gemini-key', {
      method: 'POST',
      body: JSON.stringify({ api_key: apiKey }),
    });
  },
};
