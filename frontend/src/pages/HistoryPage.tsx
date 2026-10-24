import React, { useEffect, useState } from 'react';
import {
  History as HistoryIcon,
  ShieldCheck,
  Terminal,
  Activity,
  FileText,
  RefreshCw,
  Search
} from 'lucide-react';
import { api } from '../services/api';
import { Badge } from '../components/Badge';

export const HistoryPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'events' | 'tools' | 'audits'>('events');
  const [events, setEvents] = useState<any[]>([]);
  const [toolCalls, setToolCalls] = useState<any[]>([]);
  const [audits, setAudits] = useState<any[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [search, setSearch] = useState<string>('');

  const loadData = async () => {
    setLoading(true);
    try {
      if (activeTab === 'events') {
        const data = await api.getSecurityHistory({ limit: 100 });
        setEvents(data);
      } else if (activeTab === 'tools') {
        const data = await api.getToolCalls(100);
        setToolCalls(data);
      } else {
        const data = await api.getAuditEvents(100);
        setAudits(data);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [activeTab]);

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Header */}
      <div className="border-b border-slate-800/80 pb-6 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center space-x-2">
            <span>Audit & Verification History</span>
            <span className="text-xs font-mono font-medium px-2 py-0.5 rounded-full bg-purple-950 text-purple-300 border border-purple-800/50">
              IMMUTABLE LOGS
            </span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Complete persistent audit records of agent tool actions, gateway decisions, and operator authorizations.
          </p>
        </div>
        <button
          onClick={loadData}
          className="flex items-center space-x-2 px-3 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-700/80 rounded-xl text-xs font-medium text-slate-200 transition-colors self-start"
        >
          <RefreshCw className="w-3.5 h-3.5 text-purple-400" />
          <span>Refresh History</span>
        </button>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-800 space-x-6 text-sm font-medium">
        <button
          onClick={() => setActiveTab('events')}
          className={`pb-3 flex items-center space-x-2 transition-all relative ${
            activeTab === 'events' ? 'text-purple-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <ShieldCheck className="w-4 h-4" />
          <span>Security Decisions ({events.length})</span>
          {activeTab === 'events' && (
            <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-purple-500 rounded-full" />
          )}
        </button>

        <button
          onClick={() => setActiveTab('tools')}
          className={`pb-3 flex items-center space-x-2 transition-all relative ${
            activeTab === 'tools' ? 'text-purple-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Terminal className="w-4 h-4" />
          <span>Tool Calls ({toolCalls.length})</span>
          {activeTab === 'tools' && (
            <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-purple-500 rounded-full" />
          )}
        </button>

        <button
          onClick={() => setActiveTab('audits')}
          className={`pb-3 flex items-center space-x-2 transition-all relative ${
            activeTab === 'audits' ? 'text-purple-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Activity className="w-4 h-4" />
          <span>Operator Audit Log ({audits.length})</span>
          {activeTab === 'audits' && (
            <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-purple-500 rounded-full" />
          )}
        </button>
      </div>

      {/* Content Table */}
      <div className="rounded-2xl border border-slate-800 bg-slate-950/60 backdrop-blur-md overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-slate-400 text-sm">
            <RefreshCw className="w-6 h-6 mx-auto animate-spin text-purple-400 mb-2" />
            Loading persistent records from database...
          </div>
        ) : activeTab === 'events' ? (
          events.length === 0 ? (
            <div className="p-12 text-center text-slate-500 text-xs">Zero security events recorded yet.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-900/40 text-slate-400 font-semibold uppercase tracking-wider">
                    <th className="py-3 px-4">Severity</th>
                    <th className="py-3 px-4">Decision ID</th>
                    <th className="py-3 px-4">Tool Name</th>
                    <th className="py-3 px-4">Risk Category</th>
                    <th className="py-3 px-4">Lifecycle State</th>
                    <th className="py-3 px-4">Verification</th>
                    <th className="py-3 px-4">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                  {events.map((ev) => (
                    <tr key={ev.id} className="hover:bg-slate-900/40 transition-colors">
                      <td className="py-3 px-4">
                        <Badge label={ev.severity} variant="severity" />
                      </td>
                      <td className="py-3 px-4 text-purple-400">{ev.decision_id.slice(0, 8)}...</td>
                      <td className="py-3 px-4 text-slate-200">{ev.tool_name}</td>
                      <td className="py-3 px-4 text-slate-400">{ev.risk_category}</td>
                      <td className="py-3 px-4">
                        <Badge label={ev.lifecycle_state} variant="lifecycle" />
                      </td>
                      <td className="py-3 px-4">
                        <span className={ev.verification_status === 'VERIFIED' ? 'text-emerald-400 font-bold' : 'text-amber-400'}>
                          {ev.verification_status}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-500">{new Date(ev.created_at).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        ) : activeTab === 'tools' ? (
          toolCalls.length === 0 ? (
            <div className="p-12 text-center text-slate-500 text-xs">No tool executions recorded yet.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-900/40 text-slate-400 font-semibold uppercase tracking-wider">
                    <th className="py-3 px-4">Tool Name</th>
                    <th className="py-3 px-4">Arguments</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4">Execution Time</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-xs font-mono">
                  {toolCalls.map((tc) => (
                    <tr key={tc.id} className="hover:bg-slate-900/40">
                      <td className="py-3 px-4 font-bold text-slate-200">{tc.tool_name}</td>
                      <td className="py-3 px-4 text-slate-400 max-w-xs truncate">
                        {JSON.stringify(tc.arguments)}
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                            tc.status === 'EXECUTED'
                              ? 'bg-emerald-950 text-emerald-300 border border-emerald-700/50'
                              : tc.status === 'BLOCKED'
                              ? 'bg-red-950 text-red-300 border border-red-700/50'
                              : 'bg-amber-950 text-amber-300 border border-amber-700/50'
                          }`}
                        >
                          {tc.status}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-500">{new Date(tc.executed_at).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        ) : (
          audits.length === 0 ? (
            <div className="p-12 text-center text-slate-500 text-xs">No audit events recorded yet.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-900/40 text-slate-400 font-semibold uppercase tracking-wider">
                    <th className="py-3 px-4">Action</th>
                    <th className="py-3 px-4">Target Type</th>
                    <th className="py-3 px-4">Details</th>
                    <th className="py-3 px-4">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-xs font-mono">
                  {audits.map((au) => (
                    <tr key={au.id} className="hover:bg-slate-900/40">
                      <td className="py-3 px-4 font-bold text-purple-300">{au.action}</td>
                      <td className="py-3 px-4 text-slate-300">{au.target_type}</td>
                      <td className="py-3 px-4 text-slate-400 max-w-sm truncate">
                        {JSON.stringify(au.details)}
                      </td>
                      <td className="py-3 px-4 text-slate-500">{new Date(au.created_at).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        )}
      </div>
    </div>
  );
};
