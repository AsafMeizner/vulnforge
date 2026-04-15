import { useState, useEffect, useCallback, createContext, useContext } from 'react';

interface ToastItem {
  id: number;
  message: string;
  type: 'success' | 'error' | 'info';
}

interface ToastContextValue {
  toast: (message: string, type?: ToastItem['type']) => void;
}

const ToastContext = createContext<ToastContextValue>({ toast: () => {} });

let _nextId = 1;

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const toast = useCallback((message: string, type: ToastItem['type'] = 'info') => {
    const id = _nextId++;
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 3500);
  }, []);

  const remove = (id: number) => setToasts(prev => prev.filter(t => t.id !== id));

  const typeColor: Record<ToastItem['type'], string> = {
    success: 'var(--green)',
    error: 'var(--red)',
    info: 'var(--blue)',
  };

  return (
    <ToastContext.Provider value={{ toast }}>
      {children}
      <div style={{
        position: 'fixed',
        bottom: 24,
        right: 24,
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
        zIndex: 2000,
      }}>
        {toasts.map(t => (
          <div
            key={t.id}
            onClick={() => remove(t.id)}
            style={{
              background: 'var(--surface)',
              border: `1px solid ${typeColor[t.type]}`,
              borderLeft: `4px solid ${typeColor[t.type]}`,
              borderRadius: 6,
              padding: '10px 16px',
              fontSize: 13,
              color: 'var(--text)',
              cursor: 'pointer',
              maxWidth: 360,
              boxShadow: '0 4px 16px rgba(0,0,0,0.4)',
              animation: 'slideIn 0.2s ease',
            }}
          >
            {t.message}
          </div>
        ))}
      </div>
      <style>{`
        @keyframes slideIn {
          from { opacity: 0; transform: translateX(20px); }
          to   { opacity: 1; transform: translateX(0); }
        }
      `}</style>
    </ToastContext.Provider>
  );
}

export const useToast = () => useContext(ToastContext);
