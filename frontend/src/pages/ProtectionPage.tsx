import React, { useEffect, useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Sliders,
  CheckCircle2,
  Clock,
  History as HistoryIcon,
  Check,
  X,
  FileCheck,
  RefreshCw
} from 'lucide-react';
import { api } from '../services/api';
import { Policy, PolicyVersion, ApprovalRequest } from '../types';
import { Badge } from '../components/Badge';
import { useNotifications } from '../context/NotificationContext';

export const ProtectionPage: React.FC = () => {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedPolicyVersions, setSelectedPolicyVersions] = useState<{ policy: Policy; versions: PolicyVersion[] } | null>(null);
  const [decidingId, setDecidingId] = useState<string | null>(null);
  const [approvalNotes, setApprovalNotes] = useState<Record<string, string>>({});
  const { decrementApprovals } = useNotifications();

  const loadData = async () => {
    setLoading(true);
    try {
      const [pList, aList] = await Promise.all([
        api.getPolicies(),
        api.getApprovals('PENDING'),
      ]);
      setPolicies(pList);
      setApprovals(aList);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleTogglePolicy = async (policy: Policy) => {
    const updatedStatus = !policy.is_enabled;
    try {
      const updated = await api.updatePolicy(policy.id, {
        is_enabled: updatedStatus,
        changes_summary: `Toggled policy enforcement to ${updatedStatus ? 'ENABLED' : 'DISABLED'}`,
      });
      setPolicies(policies.map((p) => (p.id === policy.id ? updated : p)));
    } catch (e) {
      console.error(e);
    }
  };

  const handleToggleApproval = async (policy: Policy) => {
    const updatedApproval = !policy.requires_approval;
    try {
      const updated = await api.updatePolicy(policy.id, {
        requires_approval: updatedApproval,
        changes_summary: `Changed human approval requirement to ${updatedApproval ? 'REQUIRED' : 'NOT REQUIRED'}`,
      });
      setPolicies(policies.map((p) => (p.id === policy.id ? updated : p)));
    } catch (e) {
      console.error(e);
    }
  };

  const handleViewVersions = async (policy: Policy) => {
    try {
      const versions = await api.getPolicyVersions(policy.id);
      setSelectedPolicyVersions({ policy, versions });
    } catch (e) {
      console.error(e);
    }
  };

  const handleApprovalDecision = async (id: string, decision: 'APPROVED' | 'REJECTED') => {
    setDecidingId(id);
    try {
      const note = approvalNotes[id] || (decision === 'APPROVED' ? 'Operator authorized action' : 'Operator rejected action');
      await api.decideApproval(id, decision, note);
      setApprovals(approvals.filter((a) => a.id !== id));
      decrementApprovals();
    } catch (e) {
      console.error(e);
    } finally {
      setDecidingId(null);
    }
  };

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Header */}
      <div className="border-b border-slate-800/80 pb-6 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center space-x-2">
            <span>Security Protection & Policies</span>
            <span className="text-xs font-mono font-medium px-2 py-0.5 rounded-full bg-purple-950 text-purple-300 border border-purple-800/50">
              RUNTIME ENFORCEMENT
            </span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Dynamic policy configurations, human authorization approvals, and policy audit versions.
          </p>
        </div>
        <button
          onClick={loadData}
          className="flex items-center space-x-2 px-3 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-700/80 rounded-xl text-xs font-medium text-slate-200 transition-colors self-start"
        >
          <RefreshCw className="w-3.5 h-3.5 text-purple-400" />
          <span>Refresh Policies</span>
        </button>
      </div>

      {/* Human Approval Queue Section */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-bold text-white flex items-center space-x-2">
              <Clock className="w-5 h-5 text-orange-400" />
              <span>Pending Human Approvals</span>
              {approvals.length > 0 && (
                <span className="px-2 py-0.5 rounded-full bg-orange-950 text-orange-300 border border-orange-600/50 text-xs font-mono">
                  {approvals.length} ACTION{approvals.length > 1 ? 'S' : ''} AWAITING OPERATOR
                </span>
              )}
            </h2>
            <p className="text-xs text-slate-400">
              High-risk agent operations halted at the gateway until verified by an authorized human.
            </p>
          </div>
        </div>

        {approvals.length === 0 ? (
          <div className="p-8 rounded-2xl border border-slate-800/80 bg-slate-950/40 text-center text-slate-500 text-xs">
            <CheckCircle2 className="w-8 h-8 text-emerald-500/50 mx-auto mb-2" />
            <p className="font-medium text-slate-400">No operations pending human approval.</p>
            <p className="text-[11px] text-slate-500 mt-0.5">
              Actions requiring authorization (such as outbound email sending) will appear here in real time.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {approvals.map((appr) => (
              <div
                key={appr.id}
                className="p-5 rounded-2xl border border-orange-500/40 bg-orange-950/20 backdrop-blur-md space-y-4"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <span className="text-[10px] font-mono uppercase tracking-wider text-orange-400 font-semibold block mb-1">
                      Approval Request
                    </span>
                    <h3 className="text-sm font-bold text-white flex items-center space-x-2">
                      <span>Tool: {appr.tool_name}</span>
                    </h3>
                  </div>
                  <Badge label="PENDING_APPROVAL" variant="lifecycle" />
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">
                  {appr.risk_explanation}
                </p>

                {/* Arguments Preview */}
                <div className="space-y-1">
                  <span className="text-[11px] font-semibold text-slate-400">Requested Arguments:</span>
                  <pre className="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800 font-mono text-[11px] text-purple-300 overflow-x-auto max-h-32">
                    {JSON.stringify(appr.arguments_preview, null, 2)}
                  </pre>
                </div>

                {/* Notes Input */}
                <input
                  type="text"
                  placeholder="Review notes or rationale..."
                  value={approvalNotes[appr.id] || ''}
                  onChange={(e) =>
                    setApprovalNotes({ ...approvalNotes, [appr.id]: e.target.value })
                  }
                  className="w-full bg-slate-900 border border-slate-700/80 rounded-xl px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500"
                />

                {/* Action Buttons */}
                <div className="flex items-center space-x-2 pt-2">
                  <button
                    disabled={decidingId === appr.id}
                    onClick={() => handleApprovalDecision(appr.id, 'APPROVED')}
                    className="flex-1 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs flex items-center justify-center space-x-1 shadow-md shadow-emerald-950 transition-all disabled:opacity-50"
                  >
                    <Check className="w-3.5 h-3.5" />
                    <span>Authorize & Execute</span>
                  </button>
                  <button
                    disabled={decidingId === appr.id}
                    onClick={() => handleApprovalDecision(appr.id, 'REJECTED')}
                    className="flex-1 py-2 rounded-xl bg-red-900/60 hover:bg-red-800 border border-red-700/60 text-red-200 font-semibold text-xs flex items-center justify-center space-x-1 transition-all disabled:opacity-50"
                  >
                    <X className="w-3.5 h-3.5" />
                    <span>Block & Reject</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Security Policies List */}
      <div className="space-y-4 pt-4 border-t border-slate-800/80">
        <div>
          <h2 className="text-base font-bold text-white flex items-center space-x-2">
            <Sliders className="w-5 h-5 text-purple-400" />
            <span>Active Security Policies & Guardrails</span>
          </h2>
          <p className="text-xs text-slate-400">
            Toggles instantly update backend gateway evaluation rules and trigger version audits.
          </p>
        </div>

        <div className="space-y-3">
          {policies.map((p) => (
            <div
              key={p.id}
              className={`p-5 rounded-2xl border transition-all ${
                p.is_enabled
                  ? 'border-slate-800 bg-slate-950/60 hover:border-slate-700'
                  : 'border-slate-900 bg-slate-950/20 opacity-60'
              }`}
            >
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div className="space-y-1.5 max-w-2xl">
                  <div className="flex items-center space-x-3 flex-wrap gap-y-1">
                    <span className="font-bold text-white text-sm">{p.name}</span>
                    <Badge label={p.risk_level} variant="severity" />
                    <span className="text-[10px] font-mono text-purple-400 bg-purple-950/60 border border-purple-800/60 px-2 py-0.5 rounded">
                      v{p.version}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">{p.description}</p>
                </div>

                {/* Toggles & Version Controls */}
                <div className="flex items-center space-x-4 shrink-0 flex-wrap gap-y-2">
                  {/* Human Approval Toggle */}
                  <label className="flex items-center space-x-2 text-xs text-slate-300 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={p.requires_approval}
                      onChange={() => handleToggleApproval(p)}
                      className="rounded bg-slate-900 border-slate-700 text-purple-600 focus:ring-0 cursor-pointer"
                    />
                    <span className="text-xs">Require Human Approval</span>
                  </label>

                  {/* Enforcement Enabled Toggle */}
                  <button
                    onClick={() => handleTogglePolicy(p)}
                    className={`px-3 py-1.5 rounded-xl text-xs font-semibold flex items-center space-x-1.5 transition-all ${
                      p.is_enabled
                        ? 'bg-emerald-950 text-emerald-300 border border-emerald-600/60'
                        : 'bg-slate-900 text-slate-400 border border-slate-700'
                    }`}
                  >
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>{p.is_enabled ? 'Enforced' : 'Disabled'}</span>
                  </button>

                  {/* History Button */}
                  <button
                    onClick={() => handleViewVersions(p)}
                    title="View Policy Version History"
                    className="p-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-400 hover:text-slate-200 transition-colors"
                  >
                    <HistoryIcon className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Policy Version History Modal */}
      {selectedPolicyVersions && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-2xl bg-slate-950 border border-slate-800 rounded-2xl p-6 shadow-2xl space-y-4 max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="font-bold text-white text-base">
                  {selectedPolicyVersions.policy.name} History
                </h3>
                <span className="text-xs text-slate-400">Audit trail of all policy configurations</span>
              </div>
              <button
                onClick={() => setSelectedPolicyVersions(null)}
                className="text-slate-400 hover:text-white text-xl leading-none"
              >
                &times;
              </button>
            </div>

            <div className="space-y-3">
              {selectedPolicyVersions.versions.map((ver) => (
                <div key={ver.id} className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-bold text-purple-400 font-mono">Version {ver.version}</span>
                    <span className="text-slate-500 font-mono text-[11px]">
                      {new Date(ver.created_at).toLocaleString()}
                    </span>
                  </div>
                  <div className="text-xs text-slate-300">
                    <span className="text-slate-400 font-medium">Changed by:</span> {ver.changed_by}
                  </div>
                  <div className="text-xs text-slate-300">
                    <span className="text-slate-400 font-medium">Summary:</span> {ver.changes_summary}
                  </div>
                  <pre className="p-2 rounded bg-slate-950 border border-slate-800 text-[10px] font-mono text-slate-400 overflow-x-auto">
                    {JSON.stringify(ver.snapshot, null, 2)}
                  </pre>
                </div>
              ))}
            </div>

            <div className="pt-2 flex justify-end border-t border-slate-800">
              <button
                onClick={() => setSelectedPolicyVersions(null)}
                className="px-4 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-xl text-xs font-medium text-slate-300"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
