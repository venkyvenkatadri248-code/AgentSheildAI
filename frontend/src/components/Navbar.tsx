import React from 'react';
import { Shield, Radio, Bell, LogOut, User as UserIcon } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useNotifications } from '../context/NotificationContext';

export const Navbar: React.FC = () => {
  const { user, logout } = useAuth();
  const { wsConnected, pendingApprovalsCount } = useNotifications();

  return (
    <header className="h-16 border-b border-slate-800 bg-slate-950/80 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-40">
      {/* Brand & Tagline */}
      <div className="flex items-center space-x-3">
        <div className="p-2 bg-gradient-to-tr from-purple-600 via-indigo-600 to-cyan-500 rounded-xl shadow-lg shadow-purple-950/50 flex items-center justify-center">
          <Shield className="w-5 h-5 text-white" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <span className="font-bold text-lg tracking-tight bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-transparent">
              AgentShieldAI
            </span>
            <span className="px-1.5 py-0.5 text-[10px] font-semibold bg-purple-950 border border-purple-600/40 text-purple-300 rounded">
              GEMINI GATEWAY
            </span>
          </div>
          <p className="text-[10px] tracking-widest uppercase font-medium text-slate-400">
            DETECT · EXPLAIN · PREVENT
          </p>
        </div>
      </div>

      {/* Center/Right Status Indicators */}
      <div className="flex items-center space-x-4">
        {/* Live WebSocket Status */}
        <div className="flex items-center space-x-2 px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-xs">
          <Radio className={`w-3.5 h-3.5 ${wsConnected ? 'text-emerald-400 animate-pulse' : 'text-amber-400'}`} />
          <span className="font-mono text-[11px] text-slate-300">
            {wsConnected ? 'LIVE MONITOR ACTIVE' : 'CONNECTING...'}
          </span>
        </div>

        {/* Pending Approvals Pill */}
        {pendingApprovalsCount > 0 && (
          <div className="flex items-center space-x-1.5 px-3 py-1 rounded-full bg-orange-950/80 border border-orange-500/60 text-orange-200 text-xs animate-bounce">
            <Bell className="w-3.5 h-3.5 text-orange-400" />
            <span className="font-semibold">{pendingApprovalsCount} Action{pendingApprovalsCount > 1 ? 's' : ''} Pending</span>
          </div>
        )}

        {/* User Info & Actions */}
        {user && (
          <div className="flex items-center space-x-3 pl-3 border-l border-slate-800">
            <div className="flex items-center space-x-2">
              <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300">
                <UserIcon className="w-4 h-4" />
              </div>
              <div className="hidden md:block text-left">
                <div className="text-xs font-medium text-slate-200">{user.full_name}</div>
                <div className="text-[10px] font-mono text-purple-400 uppercase">{user.role}</div>
              </div>
            </div>

            <button
              onClick={logout}
              title="Sign Out"
              className="p-1.5 rounded-lg text-slate-400 hover:text-red-400 hover:bg-slate-900 transition-colors"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </header>
  );
};
