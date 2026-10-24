import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Bot,
  MessageSquare,
  AlertTriangle,
  ShieldCheck,
  History,
  Settings,
} from 'lucide-react';
import { useNotifications } from '../context/NotificationContext';

export const Sidebar: React.FC = () => {
  const { pendingApprovalsCount } = useNotifications();

  const navItems = [
    { name: 'Home', path: '/', icon: LayoutDashboard },
    { name: 'My Agents', path: '/agents', icon: Bot },
    { name: 'Chat', path: '/chat', icon: MessageSquare },
    { name: 'Alerts', path: '/alerts', icon: AlertTriangle },
    { name: 'Protection', path: '/protection', icon: ShieldCheck, badge: pendingApprovalsCount },
    { name: 'History', path: '/history', icon: History },
    { name: 'Settings', path: '/settings', icon: Settings },
  ];

  return (
    <aside className="w-64 border-r border-slate-800/80 bg-slate-950/60 backdrop-blur-md flex flex-col shrink-0 min-h-[calc(100vh-4rem)]">
      <div className="p-4 space-y-1">
        <div className="text-[11px] font-semibold tracking-wider text-slate-500 uppercase px-3 py-2">
          Security Platform
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center justify-between px-3 py-2.5 rounded-xl text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-purple-900/30 text-purple-200 border border-purple-600/40 shadow-sm shadow-purple-950'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/70 border border-transparent'
                }`
              }
            >
              <div className="flex items-center space-x-3">
                <Icon className="w-4 h-4" />
                <span>{item.name}</span>
              </div>
              {item.badge && item.badge > 0 ? (
                <span className="px-2 py-0.5 text-[10px] font-bold bg-orange-950 text-orange-300 border border-orange-500/50 rounded-full">
                  {item.badge}
                </span>
              ) : null}
            </NavLink>
          );
        })}
      </div>

      <div className="mt-auto p-4 m-4 rounded-xl border border-purple-900/30 bg-purple-950/20 text-xs text-slate-400">
        <div className="flex items-center space-x-2 text-purple-300 font-semibold mb-1">
          <ShieldCheck className="w-4 h-4 text-purple-400" />
          <span>Gateway Active</span>
        </div>
        <p className="text-[11px] text-slate-400 leading-relaxed">
          Zero-trust inspection on all agent tool invocations and prompt boundaries.
        </p>
      </div>
    </aside>
  );
};
