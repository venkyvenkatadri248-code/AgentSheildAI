import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  ShieldCheck,
  Bot,
  CheckCircle2,
  Clock,
  Activity,
  Layers,
  ArrowUpRight,
  RefreshCw,
  Search,
  FileText,
  BarChart2,
  Mail,
  Filter,
  Sparkles,
  Lock,
  ChevronRight,
  RotateCcw
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, BarChart, Bar, CartesianGrid
} from 'recharts';
import { api } from '../services/api';
import { DashboardMetrics } from '../types';
import { Badge } from '../components/Badge';
import { useNotifications } from '../context/NotificationContext';

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const { eventTrigger } = useNotifications();

  const [selectedAgentKey, setSelectedAgentKey] = useState<string>('all');
  const [data, setData] = useState<DashboardMetrics | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());
  const [isResetting, setIsResetting] = useState<boolean>(false);

  const fetchMetrics = async (agentKey = selectedAgentKey) => {
    setError(null);
    try {
      const res = await api.getDashboardMetrics(agentKey === 'all' ? undefined : agentKey);
      setData(res);
      setLastUpdated(new Date());
    } catch (err: any) {
      setError(err.message || 'Failed to load dashboard metrics');
    } finally {
      setLoading(false);
    }
  };

  const handleResetTelemetry = async () => {
    if (!window.confirm("Reset all dashboard metrics to 0? The dashboard will update strictly based on new live actions by agents.")) {
      return;
    }
    setIsResetting(true);
    try {
      await api.resetTelemetry();
      await fetchMetrics(selectedAgentKey);
    } catch (e: any) {
      alert("Failed to reset telemetry: " + (e.message || "Unknown error"));
    } finally {
      setIsResetting(false);
    }
  };

  // Re-fetch whenever selectedAgentKey changes
  useEffect(() => {
    setLoading(true);
    fetchMetrics(selectedAgentKey);
  }, [selectedAgentKey]);

  // Real-time synchronization: Re-fetch whenever an agent acts (eventTrigger from WebSocket)
  useEffect(() => {
    if (eventTrigger > 0) {
      fetchMetrics(selectedAgentKey);
    }
  }, [eventTrigger]);

  // Auto-polling every 4 seconds to guarantee live database reflection
  useEffect(() => {
    const interval = setInterval(() => {
      fetchMetrics(selectedAgentKey);
    }, 4000);
    return () => clearInterval(interval);
  }, [selectedAgentKey]);

  const getAgentIcon = (key: string, size = 'w-4 h-4') => {
    switch (key) {
      case 'research_agent':
        return <Search className={`${size} text-cyan-400`} />;
      case 'file_agent':
        return <FileText className={`${size} text-purple-400`} />;
      case 'data_analysis_agent':
        return <BarChart2 className={`${size} text-emerald-400`} />;
      case 'mail_agent':
        return <Mail className={`${size} text-amber-400`} />;
      default:
        return <Bot className={`${size} text-purple-400`} />;
    }
  };

  const getAgentBadgeColor = (key: string) => {
    switch (key) {
      case 'research_agent':
        return 'border-cyan-500/40 bg-cyan-950/40 text-cyan-300';
      case 'file_agent':
        return 'border-purple-500/40 bg-purple-950/40 text-purple-300';
      case 'data_analysis_agent':
        return 'border-emerald-500/40 bg-emerald-950/40 text-emerald-300';
      case 'mail_agent':
        return 'border-amber-500/40 bg-amber-950/40 text-amber-300';
      default:
        return 'border-slate-700 bg-slate-900 text-slate-300';
    }
  };

  const metrics = data?.metrics || {
    total_agents: 4,
    active_agents: 4,
    total_security_events: 0,
    blocked_actions: 0,
    pending_approvals: 0,
    total_tasks: 0,
    open_alerts: 0,
    prevention_rate: 100.0
  };

  const isFiltered = selectedAgentKey !== 'all';
  const selectedAgentInfo = data?.selected_agent;

  const cards = [
    {
      title: isFiltered ? 'Operational Profile' : 'Configured Agents',
      value: isFiltered
        ? (selectedAgentInfo?.name || 'Active')
        : `${metrics.active_agents} / ${metrics.total_agents}`,
      desc: isFiltered ? `Key: ${selectedAgentKey}` : 'Active operational agent profiles',
      icon: Bot,
      color: 'from-blue-500/20 to-indigo-500/20 text-blue-400 border-blue-500/30',
      link: '/agents'
    },
    {
      title: isFiltered ? 'Threats Intercepted' : 'Blocked Actions',
      value: metrics.blocked_actions,
      desc: isFiltered ? `Blocked for ${selectedAgentInfo?.name || 'agent'}` : 'Threats intercepted before execution',
      icon: ShieldAlert,
      color: 'from-red-500/20 to-orange-500/20 text-red-400 border-red-500/30',
      link: '/alerts'
    },
    {
      title: 'Pending Approvals',
      value: metrics.pending_approvals,
      desc: isFiltered ? `Approval queue for ${selectedAgentInfo?.name || 'agent'}` : 'Operations requiring human sign-off',
      icon: Clock,
      color: 'from-amber-500/20 to-yellow-500/20 text-amber-400 border-amber-500/30',
      link: '/protection'
    },
    {
      title: isFiltered ? 'Tool Executions' : 'Total Tool Tasks',
      value: metrics.total_tasks,
      desc: isFiltered ? `Authorized actions by ${selectedAgentInfo?.name || 'agent'}` : 'Authorized tool actions recorded',
      icon: CheckCircle2,
      color: 'from-emerald-500/20 to-teal-500/20 text-emerald-400 border-emerald-500/30',
      link: '/history'
    },
  ];

  const agentFilters = [
    { key: 'all', name: 'All Agents Fleet', icon: Bot, color: 'text-purple-400' },
    { key: 'research_agent', name: 'Research Bot', icon: Search, color: 'text-cyan-400' },
    { key: 'file_agent', name: 'Document Bot', icon: FileText, color: 'text-purple-400' },
    { key: 'data_analysis_agent', name: 'Data Analytics Bot', icon: BarChart2, color: 'text-emerald-400' },
    { key: 'mail_agent', name: 'Security Mail Bot', icon: Mail, color: 'text-amber-400' },
  ];

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center space-x-2.5">
            <h1 className="text-2xl font-bold text-white">
              Security Operations Dashboard
            </h1>
            <span className="text-xs font-mono font-semibold px-2.5 py-0.5 rounded-full bg-emerald-950 text-emerald-300 border border-emerald-800/50 flex items-center space-x-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>LIVE DATABASE TELEMETRY</span>
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Real-time execution metrics, deterministic threat prevention, and surveillance across autonomous AI agents.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <div className="text-right text-[11px] font-mono text-slate-500 hidden sm:block">
            <span>Last Synced: </span>
            <span className="text-slate-300">{lastUpdated.toLocaleTimeString()}</span>
          </div>

          <button
            onClick={() => fetchMetrics(selectedAgentKey)}
            className="flex items-center space-x-2 px-3 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-700/80 rounded-xl text-xs font-medium text-slate-200 transition-colors cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-purple-400 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>

          <button
            onClick={handleResetTelemetry}
            disabled={isResetting}
            title="Reset telemetry to 0 so the dashboard only updates as agents take actions"
            className="flex items-center space-x-1.5 px-3 py-2 bg-slate-900/90 hover:bg-red-950/40 border border-slate-700/80 hover:border-red-500/40 rounded-xl text-xs font-medium text-slate-400 hover:text-red-300 transition-colors cursor-pointer"
          >
            <RotateCcw className={`w-3.5 h-3.5 ${isResetting ? 'animate-spin text-red-400' : 'text-slate-500'}`} />
            <span>Reset to 0</span>
          </button>

          <Link
            to="/agents"
            className="flex items-center space-x-2 px-4 py-2 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white rounded-xl text-xs font-semibold shadow-lg shadow-purple-950/40 transition-all cursor-pointer"
          >
            <span>My Agents</span>
            <ArrowUpRight className="w-4 h-4" />
          </Link>
        </div>
      </div>

      {/* ========================================================= */}
      {/* AGENT ACTION FILTER SELECTOR (DASHBOARD REACTS PER AGENT) */}
      {/* ========================================================= */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center space-x-2">
            <Filter className="w-3.5 h-3.5 text-purple-400" />
            <span>Filter Dashboard Data by Agent Action</span>
          </div>
          {isFiltered && (
            <button
              onClick={() => setSelectedAgentKey('all')}
              className="text-xs text-purple-400 hover:text-purple-300 font-medium cursor-pointer"
            >
              Reset to Fleet-Wide &rarr;
            </button>
          )}
        </div>

        {/* Filter Pills Bar */}
        <div className="flex items-center space-x-2 overflow-x-auto pb-1">
          {agentFilters.map((f) => {
            const Icon = f.icon;
            const isSelected = selectedAgentKey === f.key;
            return (
              <button
                key={f.key}
                onClick={() => setSelectedAgentKey(f.key)}
                className={`px-4 py-2 rounded-xl text-xs font-medium transition-all flex items-center space-x-2 shrink-0 cursor-pointer ${
                  isSelected
                    ? 'bg-purple-600 text-white shadow-lg shadow-purple-950 border border-purple-500/60'
                    : 'bg-slate-900/90 text-slate-400 hover:text-slate-200 border border-slate-800 hover:bg-slate-800/80'
                }`}
              >
                <Icon className={`w-4 h-4 ${isSelected ? 'text-white' : f.color}`} />
                <span>{f.name}</span>
                {f.key !== 'all' && (
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse ml-1" />
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* Agent Context Banner when Filtered */}
      {isFiltered && selectedAgentInfo && (
        <div className="p-4 rounded-2xl border border-purple-500/40 bg-purple-950/20 backdrop-blur-md flex flex-col md:flex-row md:items-center justify-between gap-4 animate-fadeIn">
          <div className="flex items-center space-x-3.5">
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
              {getAgentIcon(selectedAgentInfo.key, 'w-6 h-6')}
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="text-sm font-bold text-white">{selectedAgentInfo.name}</h3>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${getAgentBadgeColor(selectedAgentInfo.key)}`}>
                  {selectedAgentInfo.key}
                </span>
                <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/40">
                  ● Guarded & Active
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5 max-w-xl">
                {selectedAgentInfo.description}
              </p>
              <div className="flex items-center space-x-1.5 mt-2">
                <span className="text-[11px] text-slate-500 font-medium">Permitted Tools:</span>
                {selectedAgentInfo.allowed_tools.map((t) => (
                  <span key={t} className="px-2 py-0.5 rounded bg-slate-900 text-slate-300 font-mono text-[10px] border border-slate-800">
                    {t}
                  </span>
                ))}
              </div>
            </div>
          </div>

          <div className="flex items-center space-x-2 self-end md:self-center">
            <Link
              to={`/agents`}
              className="px-3.5 py-1.5 bg-purple-600 hover:bg-purple-500 rounded-xl text-xs font-semibold text-white shadow-md shadow-purple-950 flex items-center space-x-1.5 transition-all"
            >
              <span>Chat with {selectedAgentInfo.name}</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>
      )}

      {/* Metric Cards Grid (Changes dynamically based on Agent) */}
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

      {/* ========================================================= */}
      {/* REAL-TIME OPERATIONAL AGENTS ACTION MATRIX                */}
      {/* ========================================================= */}
      <div className="p-6 rounded-2xl border border-slate-800 bg-slate-950/60 backdrop-blur-md space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 flex items-center space-x-2">
              <Bot className="w-4 h-4 text-purple-400" />
              <span>Real-Time Agents Execution Matrix</span>
            </h3>
            <p className="text-xs text-slate-400">
              Live database audit of actions, tool invocations, and gateway blocks per operational agent
            </p>
          </div>
          <div className="text-xs font-mono text-purple-400 font-medium">
            Database Synchronized
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[10px]">
                <th className="pb-3 font-semibold">Agent Profile</th>
                <th className="pb-3 font-semibold text-center">Total Actions</th>
                <th className="pb-3 font-semibold text-center">Allowed Executions</th>
                <th className="pb-3 font-semibold text-center">Blocked Threats</th>
                <th className="pb-3 font-semibold text-center">Pending Approvals</th>
                <th className="pb-3 font-semibold text-center">Security Status</th>
                <th className="pb-3 font-semibold text-right">Dashboard Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {data?.agent_summaries && data.agent_summaries.length > 0 ? (
                data.agent_summaries.map((ag) => {
                  const isCurrent = selectedAgentKey === ag.key;
                  return (
                    <tr
                      key={ag.id}
                      className={`hover:bg-slate-900/60 transition-colors ${
                        isCurrent ? 'bg-purple-950/30' : ''
                      }`}
                    >
                      <td className="py-3.5 flex items-center space-x-3">
                        <div className="p-2 rounded-xl bg-slate-900 border border-slate-800">
                          {getAgentIcon(ag.key, 'w-4 h-4')}
                        </div>
                        <div>
                          <span className="font-bold text-white block">{ag.name}</span>
                          <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded border ${getAgentBadgeColor(ag.key)}`}>
                            {ag.key}
                          </span>
                        </div>
                      </td>

                      <td className="py-3.5 text-center font-mono font-bold text-white">
                        {ag.total_tasks}
                      </td>

                      <td className="py-3.5 text-center font-mono text-emerald-400 font-semibold">
                        {Math.max(0, ag.total_tasks - ag.blocked_actions - ag.pending_approvals)}
                      </td>

                      <td className="py-3.5 text-center font-mono text-red-400 font-semibold">
                        {ag.blocked_actions}
                      </td>

                      <td className="py-3.5 text-center font-mono text-amber-400 font-semibold">
                        {ag.pending_approvals}
                      </td>

                      <td className="py-3.5 text-center">
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                          ag.health_status === 'SECURE'
                            ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/40'
                            : ag.health_status === 'PENDING_APPROVAL'
                            ? 'bg-amber-950/80 text-amber-300 border border-amber-800/40'
                            : 'bg-red-950/80 text-red-300 border border-red-800/40'
                        }`}>
                          {ag.health_status}
                        </span>
                      </td>

                      <td className="py-3.5 text-right space-x-2">
                        <button
                          onClick={() => setSelectedAgentKey(ag.key)}
                          className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                            isCurrent
                              ? 'bg-purple-600 text-white shadow-sm'
                              : 'bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700'
                          }`}
                        >
                          {isCurrent ? 'Viewing' : 'Filter View'}
                        </button>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={7} className="py-6 text-center text-slate-500">
                    Loading agent matrix telemetry...
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ========================================================= */}
      {/* VISUALIZATIONS GRID                                       */}
      {/* ========================================================= */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Chart 1: Decisions by Gateway (Allowed vs Blocked vs Pending) */}
        <div className="p-6 rounded-2xl border border-slate-800 bg-slate-950/50 backdrop-blur-md">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-200 flex items-center space-x-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span>
                  {isFiltered ? `${selectedAgentInfo?.name} Decisions` : 'Enforcement Decisions (Allowed vs Blocked)'}
                </span>
              </h3>
              <p className="text-xs text-slate-400">Actual Central Security Gateway verdicts recorded in database</p>
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
              <span>Zero recorded actions for this profile currently.</span>
              <span className="text-[10px] mt-1 text-slate-600">Run queries or test tools with this agent to observe live updates.</span>
            </div>
          )}
        </div>

        {/* Chart 2: Tool Usage Breakdown or Agent Comparison */}
        <div className="p-6 rounded-2xl border border-slate-800 bg-slate-950/50 backdrop-blur-md">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-200 flex items-center space-x-2">
                <Activity className="w-4 h-4 text-purple-400" />
                <span>
                  {isFiltered ? `${selectedAgentInfo?.name} Tool Breakdown` : 'Agent Action Distribution'}
                </span>
              </h3>
              <p className="text-xs text-slate-400">
                {isFiltered
                  ? 'Specific tool calls dispatched by this operational profile'
                  : 'Total tool executions and security actions per operational agent'}
              </p>
            </div>
          </div>

          {isFiltered && data?.tool_usage_breakdown && data.tool_usage_breakdown.length > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data.tool_usage_breakdown}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis
                    dataKey="tool"
                    stroke="#64748b"
                    fontSize={11}
                    tickFormatter={(val: string) => val.slice(0, 14)}
                  />
                  <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                    itemStyle={{ color: '#f8fafc' }}
                  />
                  <Bar dataKey="count" name="Tool Calls" fill="#8b5cf6" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : !isFiltered && data?.agent_comparison && data.agent_comparison.length > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data.agent_comparison}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis
                    dataKey="agent"
                    stroke="#64748b"
                    fontSize={11}
                    tickFormatter={(val: string) => val.replace(' Agent', '')}
                  />
                  <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                    itemStyle={{ color: '#f8fafc' }}
                  />
                  <Bar dataKey="total" name="Total Actions" fill="#8b5cf6" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-64 flex flex-col items-center justify-center text-slate-500 text-xs border border-dashed border-slate-800/80 rounded-xl">
              <Activity className="w-8 h-8 mb-2 opacity-50" />
              <span>Zero recorded actions for this profile currently.</span>
              <span className="text-[10px] mt-1 text-slate-600">Run queries or test tools with this agent to observe live updates.</span>
            </div>
          )}
        </div>
      </div>

      {/* ========================================================= */}
      {/* RECENT SECURITY ACTIVITY STREAM (FILTERED BY AGENT)       */}
      {/* ========================================================= */}
      <div className="p-6 rounded-2xl border border-slate-800 bg-slate-950/50 backdrop-blur-md space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 flex items-center space-x-2">
              <Activity className="w-4 h-4 text-purple-400" />
              <span>
                {isFiltered
                  ? `Live Telemetry Stream: ${selectedAgentInfo?.name}`
                  : 'Live Fleet Security Telemetry Stream'}
              </span>
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
            <p className="font-medium text-slate-400">
              {isFiltered
                ? `Zero security incidents recorded for ${selectedAgentInfo?.name}.`
                : 'Database contains zero security incidents.'}
            </p>
            <p className="text-[11px] text-slate-500 mt-0.5">
              Interact with agents to generate live security telemetry.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
