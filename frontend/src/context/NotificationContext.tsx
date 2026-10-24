import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';

export interface ToastNotification {
  id: string;
  type: 'security_event' | 'alert_created' | 'approval_required' | 'info';
  title: string;
  message: string;
  severity?: string;
  timestamp: Date;
}

interface NotificationContextType {
  wsConnected: boolean;
  toasts: ToastNotification[];
  removeToast: (id: string) => void;
  pendingApprovalsCount: number;
  incrementApprovals: () => void;
  decrementApprovals: () => void;
  eventTrigger: number;
}

const NotificationContext = createContext<NotificationContextType | undefined>(undefined);

export const NotificationProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [wsConnected, setWsConnected] = useState<boolean>(false);
  const [toasts, setToasts] = useState<ToastNotification[]>([]);
  const [pendingApprovalsCount, setPendingApprovalsCount] = useState<number>(0);
  const [eventTrigger, setEventTrigger] = useState<number>(0);

  const addToast = useCallback((toast: Omit<ToastNotification, 'id' | 'timestamp'>) => {
    const id = Math.random().toString(36).substring(2, 9);
    const newToast: ToastNotification = { ...toast, id, timestamp: new Date() };
    setToasts((prev) => [newToast, ...prev].slice(0, 5));

    // Auto dismiss after 8 seconds
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 8000);
  }, []);

  const removeToast = (id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  const incrementApprovals = () => setPendingApprovalsCount((c) => c + 1);
  const decrementApprovals = () => setPendingApprovalsCount((c) => Math.max(0, c - 1));

  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const defaultWsUrl = `${protocol}//${window.location.host}/ws`;
    const wsUrl = (import.meta.env.VITE_WS_URL as string) || defaultWsUrl;

    let ws: WebSocket | null = null;
    let reconnectTimeout: any = null;

    const connect = () => {
      try {
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          setWsConnected(true);
        };

        ws.onmessage = (event) => {
          try {
            const payload = JSON.parse(event.data);
            if (payload.type === 'alert_created') {
              addToast({
                type: 'alert_created',
                title: payload.data.title || 'Security Alert Triggered',
                message: payload.data.explanation || 'An unsafe agent action was blocked.',
                severity: payload.data.severity || 'HIGH',
              });
            } else if (payload.type === 'approval_required') {
              incrementApprovals();
              addToast({
                type: 'approval_required',
                title: 'Human Approval Required',
                message: payload.data.explanation || 'Agent requested a sensitive operation.',
                severity: 'MEDIUM',
              });
            } else if (payload.type === 'security_event' && payload.data.status === 'ALLOWED') {
              // Log subtle safe event
            }
            setEventTrigger((prev) => prev + 1);
          } catch {}
        };

        ws.onclose = () => {
          setWsConnected(false);
          reconnectTimeout = setTimeout(connect, 4000);
        };

        ws.onerror = () => {
          setWsConnected(false);
          ws?.close();
        };
      } catch {
        setWsConnected(false);
        reconnectTimeout = setTimeout(connect, 4000);
      }
    };

    connect();

    return () => {
      if (ws) ws.close();
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
    };
  }, [addToast]);

  return (
    <NotificationContext.Provider
      value={{
        wsConnected,
        toasts,
        removeToast,
        pendingApprovalsCount,
        incrementApprovals,
        decrementApprovals,
        eventTrigger,
      }}
    >
      {children}
      {/* Toast Notification Container */}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col space-y-2 max-w-sm pointer-events-none">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`pointer-events-auto p-4 rounded-xl border shadow-xl flex items-start space-x-3 transition-all transform translate-y-0 backdrop-blur-md ${
              t.severity === 'CRITICAL'
                ? 'bg-red-950/90 border-red-500/50 text-red-200'
                : t.severity === 'HIGH'
                ? 'bg-amber-950/90 border-amber-500/50 text-amber-200'
                : 'bg-slate-900/90 border-cyan-500/50 text-cyan-200'
            }`}
          >
            <div className="flex-1">
              <div className="text-sm font-semibold flex items-center justify-between">
                <span>{t.title}</span>
                <span className="text-xs opacity-75 font-mono">{t.severity || 'INFO'}</span>
              </div>
              <p className="text-xs mt-1 text-slate-300 line-clamp-2">{t.message}</p>
            </div>
            <button
              onClick={() => removeToast(t.id)}
              className="text-slate-400 hover:text-white text-sm leading-none p-1"
            >
              &times;
            </button>
          </div>
        ))}
      </div>
    </NotificationContext.Provider>
  );
};

export const useNotifications = () => {
  const ctx = useContext(NotificationContext);
  if (!ctx) throw new Error('useNotifications must be used within NotificationProvider');
  return ctx;
};
