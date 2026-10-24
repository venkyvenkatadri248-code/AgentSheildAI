import React from 'react';

interface BadgeProps {
  label: string;
  variant?: 'severity' | 'lifecycle' | 'status' | 'default';
  className?: string;
}

export const Badge: React.FC<BadgeProps> = ({ label, variant = 'default', className = '' }) => {
  const norm = (label || '').toUpperCase();

  let colorClasses = 'bg-slate-800 text-slate-300 border-slate-700';

  if (variant === 'severity') {
    switch (norm) {
      case 'CRITICAL':
        colorClasses = 'bg-red-950/80 text-red-300 border-red-700/60 font-semibold';
        break;
      case 'HIGH':
        colorClasses = 'bg-amber-950/80 text-amber-300 border-amber-700/60 font-semibold';
        break;
      case 'MEDIUM':
        colorClasses = 'bg-yellow-950/70 text-yellow-300 border-yellow-700/50';
        break;
      case 'LOW':
        colorClasses = 'bg-blue-950/70 text-blue-300 border-blue-700/50';
        break;
    }
  } else if (variant === 'lifecycle') {
    switch (norm) {
      case 'BLOCKED':
      case 'PREVENTION_VERIFIED':
        colorClasses = 'bg-red-900/60 text-red-200 border-red-600/70';
        break;
      case 'PENDING_APPROVAL':
        colorClasses = 'bg-orange-950/80 text-orange-300 border-orange-600/70 animate-pulse';
        break;
      case 'MITIGATION_IN_PROGRESS':
        colorClasses = 'bg-purple-950/70 text-purple-300 border-purple-600/60';
        break;
      case 'TASK_COMPLETED':
      case 'VERIFIED':
        colorClasses = 'bg-emerald-950/80 text-emerald-300 border-emerald-600/60';
        break;
      case 'DETECTED':
      case 'SUSPICIOUS':
        colorClasses = 'bg-amber-900/60 text-amber-200 border-amber-600/60';
        break;
      case 'OBSERVED':
      default:
        colorClasses = 'bg-slate-800 text-slate-300 border-slate-700';
        break;
    }
  }

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium border ${colorClasses} ${className}`}
    >
      {label}
    </span>
  );
};
