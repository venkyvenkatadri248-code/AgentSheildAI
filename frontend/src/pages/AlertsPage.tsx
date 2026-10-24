import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  Search,
  Filter,
  CheckCircle,
  Eye,
  XCircle,
  ShieldAlert,
  Clock,
  RefreshCw,
  FileText
} from 'lucide-react';
import { api } from '../services/api';
import { Alert } from '../types';
import { Badge } from '../components/Badge';

export const AlertsPage: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [resolutionNotes, setResolutionNotes] = useState<string>('');
  const [updating, setUpdating] = useState<boolean>(false);

  const loadAlerts = async () => {
    setLoading(true);
    try {
      const data = await api.getAlerts({
        severity: severityFilter || undefined,
        status: statusFilter || undefined,
        search: searchQuery || undefined,
      });
      setAlerts(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, [severityFilter, statusFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    loadAlerts();
  };

  const handleUpdateStatus = async (alertId: string, newStatus: string) => {
    setUpdating(true);
    try {
      const updated = await api.updateAlertStatus(alertId, newStatus, resolutionNotes || undefined);
      setAlerts(alerts.map((a) => (a.id === alertId ? updated : a)));
      if (selectedAlert?.id === alertId) {
        setSelectedAlert(updated);
      }
      setResolutionNotes('');
    } catch (e) {
      console.error(e);
    } finally {
      setUpdating(false);
    }
  };

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Header */}
      <div className="border-b border-slate-800/80 pb-6 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center space-x-2">
            <span>Security Alerts & Incidents</span>
            <span className="text-xs font-mono font-medium px-2 py-0.5 rounded-full bg-red-950 text-red-300 border border-red-800/50">
              AUDIT VERIFIED
            </span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Real security threats, policy violations, and intercepted agent actions.
          </p>
        </div>
        <button
          onClick={loadAlerts}
          className="flex items-center space-x-2 px-3 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-700/80 rounded-xl text-xs font-medium text-slate-200 transition-colors self-start"
        >
          <RefreshCw className="w-3.5 h-3.5 text-purple-400" />
          <span>Refresh Incidents</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-2xl border border-slate-800 bg-slate-950/60 backdrop-blur-md flex flex-col sm:flex-row items-center justify-between gap-4">
        {/* Search */}
        <form onSubmit={handleSearchSubmit} className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
          <input
            type="text"
            placeholder="Search alerts by title or content..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-900 border border-slate-700/80 rounded-xl pl-9 pr-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500"
          />
        </form>

        {/* Severity & Status Dropdowns */}
        <div className="flex items-center space-x-3 w-full sm:w-auto">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-900 border border-slate-700/80 rounded-xl px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-purple-500 cursor-pointer"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-900 border border-slate-700/80 rounded-xl px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-purple-500 cursor-pointer"
          >
            <option value="">All Lifecycle Statuses</option>
            <option value="OPEN">Open</option>
            <option value="ACKNOWLEDGED">Acknowledged</option>
            <option value="RESOLVED">Resolved</option>
            <option value="DISMISSED">Dismissed</option>
          </select>
        </div>
      </div>

      {/* Alert Records Table */}
      <div className="rounded-2xl border border-slate-800 bg-slate-950/60 backdrop-blur-md overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-slate-400 text-sm">
            <RefreshCw className="w-6 h-6 mx-auto animate-spin text-purple-400 mb-2" />
            Loading recorded security incidents...
          </div>
        ) : alerts.length === 0 ? (
          <div className="p-16 text-center text-slate-500 space-y-2">
            <ShieldAlert className="w-12 h-12 mx-auto text-slate-600 mb-3" />
            <h3 className="text-base font-semibold text-slate-300">No Security Alerts Found</h3>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              There are currently no security violations matching your filter criteria. All monitored agent interactions adhere to active policies.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/40 text-xs text-slate-400 font-semibold uppercase tracking-wider">
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Incident Title</th>
                  <th className="py-3 px-4">Category</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-xs">
                {alerts.map((alert) => (
                  <tr
                    key={alert.id}
                    className="hover:bg-slate-900/40 transition-colors cursor-pointer"
                    onClick={() => setSelectedAlert(alert)}
                  >
                    <td className="py-3.5 px-4">
                      <Badge label={alert.severity} variant="severity" />
                    </td>
                    <td className="py-3.5 px-4 font-semibold text-slate-200">
                      {alert.title}
                    </td>
                    <td className="py-3.5 px-4 font-mono text-[11px] text-purple-400">
                      {alert.security_event?.risk_category || 'security_policy'}
                    </td>
                    <td className="py-3.5 px-4">
                      <span
                        className={`inline-block px-2 py-0.5 rounded text-[10px] font-semibold font-mono ${
                          alert.status === 'OPEN'
                            ? 'bg-red-950/80 text-red-300 border border-red-700/50'
                            : alert.status === 'ACKNOWLEDGED'
                            ? 'bg-amber-950/80 text-amber-300 border border-amber-700/50'
                            : alert.status === 'RESOLVED'
                            ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-700/50'
                            : 'bg-slate-800 text-slate-400 border border-slate-700'
                        }`}
                      >
                        {alert.status}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 font-mono text-[11px]">
                      {new Date(alert.created_at).toLocaleString()}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedAlert(alert);
                        }}
                        className="px-2.5 py-1 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-lg text-slate-300 text-[11px] font-medium"
                      >
                        View Evidence
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Incident Detail Modal */}
      {selectedAlert && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-2xl bg-slate-950 border border-slate-800 rounded-2xl p-6 shadow-2xl space-y-5 max-h-[90vh] overflow-y-auto">
            <div className="flex items-start justify-between border-b border-slate-800 pb-4">
              <div>
                <div className="flex items-center space-x-2 mb-1">
                  <Badge label={selectedAlert.severity} variant="severity" />
                  <span className="text-xs font-mono text-slate-500">
                    Event ID: {selectedAlert.security_event_id.slice(0, 8)}...
                  </span>
                </div>
                <h3 className="text-lg font-bold text-white">{selectedAlert.title}</h3>
              </div>
              <button
                onClick={() => setSelectedAlert(null)}
                className="text-slate-400 hover:text-white text-xl leading-none"
              >
                &times;
              </button>
            </div>

            {/* Explanation */}
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1">
              <span className="text-xs font-semibold text-slate-400 block">Gateway Verdict & Explanation:</span>
              <p className="text-sm text-slate-200 leading-relaxed">
                {selectedAlert.description}
              </p>
            </div>

            {/* Evidence & Technical Metadata */}
            {selectedAlert.security_event && (
              <div className="space-y-2">
                <span className="text-xs font-semibold text-slate-400 flex items-center space-x-1.5">
                  <FileText className="w-3.5 h-3.5 text-purple-400" />
                  <span>Intercepted Technical Evidence</span>
                </span>
                <pre className="p-3 rounded-xl bg-slate-900 border border-slate-800 font-mono text-[11px] text-purple-300 overflow-x-auto">
                  {JSON.stringify(selectedAlert.security_event.evidence, null, 2)}
                </pre>
              </div>
            )}

            {/* Resolution Form */}
            <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40 space-y-3">
              <span className="text-xs font-semibold text-slate-300">Incident Remediation:</span>
              <textarea
                rows={2}
                placeholder="Add resolution or analysis notes..."
                value={resolutionNotes}
                onChange={(e) => setResolutionNotes(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700/80 rounded-xl p-2.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500"
              />
              <div className="flex items-center space-x-2 pt-1">
                {selectedAlert.status !== 'ACKNOWLEDGED' && (
                  <button
                    disabled={updating}
                    onClick={() => handleUpdateStatus(selectedAlert.id, 'ACKNOWLEDGED')}
                    className="px-3 py-1.5 rounded-lg bg-amber-950/80 hover:bg-amber-900 border border-amber-700/60 text-amber-200 text-xs font-semibold"
                  >
                    Acknowledge
                  </button>
                )}
                {selectedAlert.status !== 'RESOLVED' && (
                  <button
                    disabled={updating}
                    onClick={() => handleUpdateStatus(selectedAlert.id, 'RESOLVED')}
                    className="px-3 py-1.5 rounded-lg bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-700/60 text-emerald-200 text-xs font-semibold"
                  >
                    Resolve Incident
                  </button>
                )}
                {selectedAlert.status !== 'DISMISSED' && (
                  <button
                    disabled={updating}
                    onClick={() => handleUpdateStatus(selectedAlert.id, 'DISMISSED')}
                    className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 text-xs font-medium"
                  >
                    Dismiss False Positive
                  </button>
                )}
              </div>
            </div>

            <div className="flex justify-end pt-2 border-t border-slate-800">
              <button
                onClick={() => setSelectedAlert(null)}
                className="px-4 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-xl text-xs font-medium text-slate-300"
              >
                Close Drawer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
