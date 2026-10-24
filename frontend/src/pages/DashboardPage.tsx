import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Bot,
  CheckCircle2,
  Clock,
  Activity,
  Layers,
  ArrowUpRight,
  RefreshCw
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, BarChart, Bar, CartesianGrid
} from 'recharts';
import { api } from '../services/api';
import { DashboardMetrics } from '../types';
import { Badge } from '../components/Badge';
import { Link } from 'react-router-dom';

export const DashboardPage: React.FC = () => {
  const [data, setData] = useState<DashboardMetrics | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchMetrics = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getDashboardMetrics();
      setData(res);
    } catch (err: any) {
      setError(err.message || 'Failed to load dashboard metrics');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMetrics();
    const interval = setInterval(fetchMetrics, 15000);
    return () => clearInterval(interval);
  }, []);

  if (loading && !data) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-3">
        <RefreshCw className="w-8 h-8 text-purple-400 animate-spin" />
        <p className="text-sm text-slate-400">Loading security platform metrics...</p>
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="p-8 text-center bg-red-950/20 border border-red-500/30 rounded-2xl m-6">
        <ShieldAlert className="w-12 h-12 text-red-400 mx-auto mb-3" />
        <h3 className="text-lg font-semibold text-red-200">Failed to load telemetry</h3>
        <p className="text-sm text-slate-400 mt-1">{error}</p>
        <button
          onClick={fetchMetrics}
          className="mt-4 px-4 py-2 bg-red-900/40 hover:bg-red-900/60 border border-red-700/50 rounded-xl text-xs font-medium text-red-200"
        >
          Retry Connection
        </button>
      </div>
    );
  }

  const metrics = data?.metrics || {
    total_agents: 4,
    active_agents: 4,
    total_security_events: 0,
    blocked_actions: 0,
    pending_approvals: 0,
    total_tasks: 0,
    open_alerts: 0
  };

  const cards = [
    {
      title: 'Configured Agents',
      value: `${metrics.active_agents} / ${metrics.total_agents}`,
      desc: 'Active security agent profiles',
      icon: Bot,
      color: 'from-blue-500/20 to-indigo-500/20 text-blue-400 border-blue-500/30',
      link: '/agents'
    },
    {
      title: 'Blocked Actions',
      value: metrics.blocked_actions,
      desc: 'Threats intercepted before execution',
      icon: ShieldAlert,
      color: 'from-red-500/20 to-orange-500/20 text-red-400 border-red-500/30',
      link: '/alerts'
    },
    {
      title: 'Pending Approvals',
      value: metrics.pending_approvals,
      desc: 'Sensitive operations requiring human sign-off',
      icon: Clock,
      color: 'from-amber-500/20 to-yellow-500/20 text-amber-400 border-amber-500/30',
      link: '/protection'
    },
    {
      title: 'Total Tool Executions',
      value: metrics.total_tasks,
      desc: 'Authorized tool tasks recorded',
      icon: CheckCircle2,
      color: 'from-emerald-500/20 to-teal-500/20 text-emerald-400 border-emerald-500/30',
      link: '/history'
    },
  ];

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center space-x-2">
            <span>Security Operations Dashboard</span>
            <span className="text-xs font-mono font-medium px-2 py-0.5 rounded-full bg-purple-950 text-purple-300 border border-purple-800/50">
              REAL-TIME AGGREGATE
            </span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Deterministic surveillance, threat prevention, and real-time agent telemetry.
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={fetchMetrics}
            className="flex items-center space-x-2 px-3 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-700/80 rounded-xl text-xs font-medium text-slate-200 transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5 text-purple-400" />
            <span>Refresh Telemetry</span>
          </button>
          <Link
            to="/chat"
            className="flex items-center space-x-2 px-4 py-2 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white rounded-xl text-xs font-semibold shadow-lg shadow-purple-950/40 transition-all"
          >
            <span>Launch Agent Chat</span>
            <ArrowUpRight className="w-4 h-4" />
          </Link>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        {cards.map((c) => {
          const Icon = c.icon;
          return (
            <Link
              key={c.title}
              to={c.link}
              className={`p-5 rounded-2xl border bg-gradient-to-b ${c.color} backdrop-blur-md flex flex-col justify-between hover:scale-[1.02] transition-transform`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-300">{c.title}</span>
                <Icon className="w-5 h-5 opacity-80" />
              </div>
              <div className="my-3">
                <div className="text-3xl font-extrabold text-white tracking-tight">{c.value}</div>
                <div className="text-[11px] text-slate-400 mt-0.5">{c.desc}</div>
              </div>
            </Link>
          );
        })}
      </div>

      {/* Visualizations Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Chart 1: Security Decisions (Blocked vs Allowed) */}
        <div className="p-6 rounded-2xl border border-slate-800 bg-slate-950/50 backdrop-blur-md">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-200 flex items-center space-x-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span>Enforcement Decisions (Allowed vs. Blocked)</span>
              </h3>
              <p className="text-xs text-slate-400">Actual security gateway verdicts recorded in database</p>
            </div>
          </div>
          {data?.actions_by_decision && data.actions_by_decision.length > 0 ? (
            <div className="h-64 flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={data.actions_by_decision}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={90}
                    paddingAngle={4}
                    label
                  >
                    {data.actions_by_decision.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                    itemStyle={{ color: '#f8fafc' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-64 flex flex-col items-center justify-center text-slate-500 text-xs border border-dashed border-slate-800/80 rounded-xl">
              <Layers className="w-8 h-8 mb-2 opacity-50" />
              <span>No tool execution actions recorded yet.</span>
              <span className="text-[10px] mt-1 text-slate-600">Interact with agents to generate security telemetry.</span>
            </div>
          )}
        </div>

        {/* Chart 2: Threat Severity Distribution */}
        <div className="p-6 rounded-2xl border border-slate-800 bg-slate-950/50 backdrop-blur-md">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-200 flex items-center space-x-2">
                <ShieldAlert className="w-4 h-4 text-amber-400" />
                <span>Threat Severity Breakdown</span>
              </h3>
              <p className="text-xs text-slate-400">Security events grouped by risk severity level</p>
            </div>
          </div>
          {data?.severity_distribution && data.severity_distribution.length > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data.severity_distribution}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="severity" stroke="#64748b" fontSize={11} />
                  <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                    itemStyle={{ color: '#f8fafc' }}
                  />
                  <Bar dataKey="count" fill="#8b5cf6" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-64 flex flex-col items-center justify-center text-slate-500 text-xs border border-dashed border-slate-800/80 rounded-xl">
              <Activity className="w-8 h-8 mb-2 opacity-50" />
              <span>Zero recorded security alerts currently.</span>
              <span className="text-[10px] mt-1 text-slate-600">All agent actions remain nominal.</span>
            </div>
          )}
        </div>
      </div>

      {/* Recent Security Activity Stream */}
      <div className="p-6 rounded-2xl border border-slate-800 bg-slate-950/50 backdrop-blur-md space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 flex items-center space-x-2">
              <Activity className="w-4 h-4 text-purple-400" />
              <span>Live Security Telemetry Stream</span>
            </h3>
            <p className="text-xs text-slate-400">Direct audit records from Central Security Gateway</p>
          </div>
          <Link to="/history" className="text-xs text-purple-400 hover:text-purple-300 font-medium">
            View Full History &rarr;
          </Link>
        </div>

        {data?.recent_activity && data.recent_activity.length > 0 ? (
          <div className="divide-y divide-slate-800/80">
            {data.recent_activity.map((ev: any) => (
              <div key={ev.id} className="py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                <div className="space-y-1 max-w-2xl">
                  <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                    <span className="font-semibold text-slate-200">{ev.agent_name}</span>
                    <span className="text-slate-500 font-mono text-[10px]">tool: {ev.tool_name}</span>
                    <Badge label={ev.severity} variant="severity" />
                    <Badge label={ev.lifecycle_state} variant="lifecycle" />
                  </div>
                  <p className="text-slate-400 text-xs leading-relaxed">{ev.explanation}</p>
                </div>
                <div className="text-right shrink-0">
                  <div className="text-[11px] font-mono text-slate-500">
                    {new Date(ev.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                  </div>
                  <span className={`text-[10px] font-semibold ${ev.execution_prevented ? 'text-red-400' : 'text-emerald-400'}`}>
                    {ev.execution_prevented ? 'PREVENTED' : 'AUTHORIZED'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="py-12 text-center text-slate-500 text-xs border border-dashed border-slate-800/80 rounded-xl">
            <ShieldCheck className="w-10 h-10 mx-auto text-emerald-500/50 mb-2" />
            <p className="font-medium text-slate-400">Database contains zero security incidents.</p>
            <p className="text-[11px] text-slate-500 mt-0.5">
              Run test prompts or tool queries in Chat to observe live detection in action.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
