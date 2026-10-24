import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Search,
  FileText,
  BarChart2,
  Mail,
  ShieldCheck,
  CheckCircle2,
  Lock,
  ArrowRight,
  Info
} from 'lucide-react';
import { api } from '../services/api';
import { Agent } from '../types';

export const AgentsPage: React.FC = () => {
  const navigate = useNavigate();
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null);

  useEffect(() => {
    api.getAgents()
      .then(setAgents)
      .finally(() => setLoading(false));
  }, []);

  const getAgentIcon = (iconName: string) => {
    switch (iconName.toLowerCase()) {
      case 'search':
        return <Search className="w-6 h-6 text-cyan-400" />;
      case 'filetext':
      case 'file-text':
        return <FileText className="w-6 h-6 text-purple-400" />;
      case 'barchart2':
      case 'bar-chart-2':
        return <BarChart2 className="w-6 h-6 text-emerald-400" />;
      case 'mail':
        return <Mail className="w-6 h-6 text-amber-400" />;
      default:
        return <Search className="w-6 h-6 text-cyan-400" />;
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

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Header */}
      <div className="border-b border-slate-800/80 pb-6">
        <h1 className="text-2xl font-bold text-white flex items-center space-x-2">
          <span>Configured AI Agents</span>
          <span className="text-xs font-mono font-medium px-2 py-0.5 rounded-full bg-purple-950 text-purple-300 border border-purple-800/50">
            4 OPERATIONAL PROFILES
          </span>
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Specialized conversational agents with isolated operational toolsets and strict runtime security policies.
        </p>
      </div>

      {loading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-64 rounded-2xl bg-slate-900/50 border border-slate-800 animate-pulse" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {agents.map((agent) => (
            <div
              key={agent.id}
              className="p-6 rounded-2xl border border-slate-800 bg-slate-950/60 backdrop-blur-md flex flex-col justify-between hover:border-purple-500/40 transition-all group"
            >
              <div>
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center space-x-3.5">
                    <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 shadow-inner">
                      {getAgentIcon(agent.icon)}
                    </div>
                    <div>
                      <h3 className="text-lg font-bold text-white group-hover:text-purple-300 transition-colors">
                        {agent.name}
                      </h3>
                      <span className={`inline-block text-[11px] font-mono px-2 py-0.5 rounded border mt-0.5 ${getAgentBadgeColor(agent.key)}`}>
                        {agent.key}
                      </span>
                    </div>
                  </div>
                  <div className="flex items-center space-x-1.5 text-xs text-emerald-400 font-medium">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Active</span>
                  </div>
                </div>

                <p className="text-sm text-slate-300 leading-relaxed mb-4">
                  {agent.description}
                </p>

                {/* Enabled Tools */}
                <div className="space-y-2 mb-6">
                  <div className="text-xs font-semibold text-slate-400 flex items-center space-x-1.5">
                    <Lock className="w-3.5 h-3.5 text-slate-500" />
                    <span>Authorized Tools</span>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {agent.allowed_tools && agent.allowed_tools.length > 0 ? (
                      agent.allowed_tools.map((t) => (
                        <span
                          key={t}
                          className="px-2.5 py-1 text-xs font-mono rounded-lg bg-slate-900 border border-slate-800 text-slate-300"
                        >
                          {t}
                        </span>
                      ))
                    ) : (
                      <span className="text-xs text-slate-500 italic">No tools assigned</span>
                    )}
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center space-x-3 pt-4 border-t border-slate-900">
                <button
                  onClick={() => setSelectedAgent(agent)}
                  className="flex-1 py-2 px-3 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700/80 text-xs font-medium text-slate-300 flex items-center justify-center space-x-1.5 transition-colors"
                >
                  <Info className="w-3.5 h-3.5 text-purple-400" />
                  <span>Inspect Policy</span>
                </button>
                <button
                  onClick={() => navigate(`/chat?agent=${agent.key}`)}
                  className="flex-1 py-2 px-3 rounded-xl bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-xs font-semibold flex items-center justify-center space-x-1.5 shadow-md shadow-purple-950/30 transition-all"
                >
                  <span>Open Chat</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Agent Policy Detail Modal */}
      {selectedAgent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg bg-slate-950 border border-slate-800 rounded-2xl p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <ShieldCheck className="w-5 h-5 text-purple-400" />
                <h3 className="font-bold text-white text-base">{selectedAgent.name} Security Profile</h3>
              </div>
              <button
                onClick={() => setSelectedAgent(null)}
                className="text-slate-400 hover:text-white text-lg leading-none"
              >
                &times;
              </button>
            </div>

            <div className="space-y-3 text-xs text-slate-300">
              <div>
                <span className="font-semibold text-slate-400 block mb-1">Agent Identifier:</span>
                <code className="text-purple-300 font-mono bg-slate-900 px-2 py-1 rounded">
                  {selectedAgent.key}
                </code>
              </div>
              <div>
                <span className="font-semibold text-slate-400 block mb-1">Enforced Guardrails:</span>
                <ul className="list-disc pl-5 space-y-1 text-slate-400">
                  <li>Mandatory argument schema validation before tool dispatch</li>
                  <li>Indirect prompt injection sanitization on external payloads</li>
                  <li>Zero-trust resource ownership verification</li>
                  {selectedAgent.key === 'mail_agent' && (
                    <li className="text-amber-300 font-medium">Human-in-the-loop approval gated for outbound email dispatch</li>
                  )}
                </ul>
              </div>
              <div>
                <span className="font-semibold text-slate-400 block mb-1">Permitted Tool Call Whitelist:</span>
                <div className="flex flex-wrap gap-1">
                  {selectedAgent.allowed_tools.map((t) => (
                    <span key={t} className="px-2 py-0.5 font-mono text-[11px] rounded bg-purple-950/60 border border-purple-800/60 text-purple-300">
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end space-x-2">
              <button
                onClick={() => setSelectedAgent(null)}
                className="px-4 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-xl text-xs font-medium text-slate-300"
              >
                Close
              </button>
              <button
                onClick={() => {
                  const k = selectedAgent.key;
                  setSelectedAgent(null);
                  navigate(`/chat?agent=${k}`);
                }}
                className="px-4 py-1.5 bg-purple-600 hover:bg-purple-500 rounded-xl text-xs font-semibold text-white"
              >
                Start Chatting
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
