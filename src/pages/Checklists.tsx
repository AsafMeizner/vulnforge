import { useState } from 'react';

interface ChecklistItem {
  id: string;
  label: string;
  checked: boolean;
  severity?: string;
  cwe?: string;
}

interface Checklist {
  id: string;
  name: string;
  description: string;
  items: ChecklistItem[];
}

const BUILTIN_CHECKLISTS: Checklist[] = [
  {
    id: 'preauth',
    name: 'Pre-Auth Attack Surface',
    description: 'Check all code paths reachable before authentication',
    items: [
      { id: 'pa1', label: 'Network accept() → first auth check traced', checked: false, severity: 'Critical' },
      { id: 'pa2', label: 'TLS/DTLS parsing before cert validation', checked: false, severity: 'Critical' },
      { id: 'pa3', label: 'Protocol version negotiation handling', checked: false, severity: 'High' },
      { id: 'pa4', label: 'Banner/greeting generation (format strings)', checked: false, severity: 'High' },
      { id: 'pa5', label: 'UDP packet parsing (no connection state)', checked: false, severity: 'High' },
      { id: 'pa6', label: 'HTTP parsing before route dispatch', checked: false, severity: 'Medium' },
      { id: 'pa7', label: 'DNS response parsing (client-side)', checked: false, severity: 'High' },
    ],
  },
  {
    id: 'memory',
    name: 'Memory Safety',
    description: 'Common memory corruption patterns',
    items: [
      { id: 'ms1', label: 'Integer overflow in allocation size (n * sizeof)', checked: false, severity: 'Critical', cwe: 'CWE-190' },
      { id: 'ms2', label: 'realloc() return value used before NULL check', checked: false, severity: 'High', cwe: 'CWE-476' },
      { id: 'ms3', label: 'Use-after-free on error paths', checked: false, severity: 'Critical', cwe: 'CWE-416' },
      { id: 'ms4', label: 'Off-by-one in buffer indexing', checked: false, severity: 'High', cwe: 'CWE-193' },
      { id: 'ms5', label: 'Stack variable address returned/stored', checked: false, severity: 'High', cwe: 'CWE-562' },
      { id: 'ms6', label: 'Double-free on error unwind', checked: false, severity: 'Critical', cwe: 'CWE-415' },
      { id: 'ms7', label: 'uint64→size_t truncation on 32-bit targets', checked: false, severity: 'High', cwe: 'CWE-197' },
    ],
  },
  {
    id: 'crypto',
    name: 'Cryptography',
    description: 'Cryptographic implementation weaknesses',
    items: [
      { id: 'cr1', label: 'Timing-safe comparison for secrets (memcmp)', checked: false, severity: 'High', cwe: 'CWE-385' },
      { id: 'cr2', label: 'RNG seeding with time/PID only', checked: false, severity: 'High', cwe: 'CWE-338' },
      { id: 'cr3', label: 'Hard-coded cryptographic keys or IVs', checked: false, severity: 'Critical', cwe: 'CWE-321' },
      { id: 'cr4', label: 'ECB mode usage', checked: false, severity: 'High', cwe: 'CWE-327' },
      { id: 'cr5', label: 'Certificate validation bypass (skip verify flag)', checked: false, severity: 'Critical', cwe: 'CWE-295' },
      { id: 'cr6', label: 'Nonce reuse in AEAD ciphers', checked: false, severity: 'Critical', cwe: 'CWE-330' },
      { id: 'cr7', label: 'Key material in core dump / log files', checked: false, severity: 'High', cwe: 'CWE-312' },
    ],
  },
  {
    id: 'concurrency',
    name: 'Concurrency',
    description: 'Race conditions and async-signal safety',
    items: [
      { id: 'co1', label: 'Signal handler calls non-async-signal-safe functions', checked: false, severity: 'Critical', cwe: 'CWE-364' },
      { id: 'co2', label: 'TOCTOU on file operations', checked: false, severity: 'High', cwe: 'CWE-367' },
      { id: 'co3', label: 'Shared state accessed without locks', checked: false, severity: 'High', cwe: 'CWE-362' },
      { id: 'co4', label: 'Lock ordering inconsistency (deadlock/livelock)', checked: false, severity: 'Medium' },
      { id: 'co5', label: 'setjmp/longjmp across lock boundaries', checked: false, severity: 'High' },
      { id: 'co6', label: 'PID reuse race (kill/waitpid)', checked: false, severity: 'Medium', cwe: 'CWE-362' },
    ],
  },
];

export default function Checklists() {
  const [checklists, setChecklists] = useState<Checklist[]>(
    () => {
      try {
        const saved = localStorage.getItem('vf_checklists');
        return saved ? JSON.parse(saved) as Checklist[] : BUILTIN_CHECKLISTS;
      } catch {
        return BUILTIN_CHECKLISTS;
      }
    }
  );
  const [activeId, setActiveId] = useState<string>(checklists[0]?.id ?? '');

  const toggle = (checklistId: string, itemId: string) => {
    const updated = checklists.map(cl =>
      cl.id !== checklistId ? cl : {
        ...cl,
        items: cl.items.map(it =>
          it.id !== itemId ? it : { ...it, checked: !it.checked }
        ),
      }
    );
    setChecklists(updated);
    localStorage.setItem('vf_checklists', JSON.stringify(updated));
  };

  const resetChecklist = (checklistId: string) => {
    const updated = checklists.map(cl =>
      cl.id !== checklistId ? cl : {
        ...cl,
        items: cl.items.map(it => ({ ...it, checked: false })),
      }
    );
    setChecklists(updated);
    localStorage.setItem('vf_checklists', JSON.stringify(updated));
  };

  const active = checklists.find(cl => cl.id === activeId);
  const checkedCount = active?.items.filter(it => it.checked).length ?? 0;
  const totalCount = active?.items.length ?? 0;
  const progress = totalCount > 0 ? (checkedCount / totalCount) * 100 : 0;

  const severityColor: Record<string, string> = {
    Critical: 'var(--red)',
    High: 'var(--orange)',
    Medium: 'var(--yellow)',
    Low: 'var(--muted)',
  };

  return (
    <div style={{ display: 'flex', gap: 20, height: 'calc(100vh - 120px)' }}>
      {/* Sidebar */}
      <div style={{ width: 220, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 4 }}>
        <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.5px', fontWeight: 600, marginBottom: 8 }}>
          Checklists
        </div>
        {checklists.map(cl => {
          const done = cl.items.filter(it => it.checked).length;
          const total = cl.items.length;
          return (
            <button
              key={cl.id}
              onClick={() => setActiveId(cl.id)}
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 4,
                padding: '10px 12px',
                background: activeId === cl.id ? 'var(--surface)' : 'transparent',
                border: `1px solid ${activeId === cl.id ? 'var(--blue)' : 'var(--border)'}`,
                borderRadius: 6,
                cursor: 'pointer',
                textAlign: 'left',
              }}
            >
              <span style={{ fontSize: 12, fontWeight: 600, color: activeId === cl.id ? 'var(--text)' : 'var(--muted)' }}>
                {cl.name}
              </span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <div style={{ flex: 1, height: 3, background: 'var(--border)', borderRadius: 2, overflow: 'hidden' }}>
                  <div style={{ width: `${total > 0 ? (done / total) * 100 : 0}%`, height: '100%', background: done === total ? 'var(--green)' : 'var(--blue)', borderRadius: 2, transition: 'width 0.2s' }} />
                </div>
                <span style={{ fontSize: 10, color: 'var(--muted)' }}>{done}/{total}</span>
              </div>
            </button>
          );
        })}
      </div>

      {/* Main content */}
      {active && (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 16, overflow: 'hidden' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexShrink: 0 }}>
            <div>
              <h2 style={{ fontSize: 18, fontWeight: 700, margin: 0, color: 'var(--text)' }}>{active.name}</h2>
              <p style={{ fontSize: 12, color: 'var(--muted)', margin: '4px 0 0' }}>{active.description}</p>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: 20, fontWeight: 700, color: progress === 100 ? 'var(--green)' : 'var(--text)' }}>
                  {checkedCount}/{totalCount}
                </div>
                <div style={{ fontSize: 10, color: 'var(--muted)', textTransform: 'uppercase' }}>complete</div>
              </div>
              <button
                onClick={() => resetChecklist(active.id)}
                style={{ background: 'none', border: '1px solid var(--border)', borderRadius: 5, padding: '5px 12px', color: 'var(--muted)', fontSize: 11, cursor: 'pointer' }}
              >
                Reset
              </button>
            </div>
          </div>

          {/* Progress bar */}
          <div style={{ height: 4, background: 'var(--border)', borderRadius: 2, overflow: 'hidden', flexShrink: 0 }}>
            <div style={{ width: `${progress}%`, height: '100%', background: progress === 100 ? 'var(--green)' : 'var(--blue)', borderRadius: 2, transition: 'width 0.3s' }} />
          </div>

          {/* Items */}
          <div style={{ flex: 1, overflow: 'auto', display: 'flex', flexDirection: 'column', gap: 6 }}>
            {active.items.map(item => (
              <label
                key={item.id}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                  padding: '12px 16px',
                  background: item.checked ? 'var(--surface)' : 'var(--surface)',
                  border: `1px solid ${item.checked ? 'var(--border)' : 'var(--border)'}`,
                  borderRadius: 6,
                  cursor: 'pointer',
                  opacity: item.checked ? 0.6 : 1,
                  transition: 'opacity 0.15s',
                }}
              >
                <input
                  type="checkbox"
                  checked={item.checked}
                  onChange={() => toggle(active.id, item.id)}
                  style={{ accentColor: 'var(--green)', width: 15, height: 15, flexShrink: 0 }}
                />
                <span style={{
                  flex: 1,
                  fontSize: 13,
                  color: item.checked ? 'var(--muted)' : 'var(--text)',
                  textDecoration: item.checked ? 'line-through' : 'none',
                }}>
                  {item.label}
                </span>
                {item.cwe && (
                  <code style={{ fontSize: 10, color: 'var(--muted)', background: 'var(--surface-2)', padding: '2px 6px', borderRadius: 3, border: '1px solid var(--border)' }}>
                    {item.cwe}
                  </code>
                )}
                {item.severity && (
                  <span style={{
                    fontSize: 10,
                    fontWeight: 600,
                    color: severityColor[item.severity] ?? 'var(--muted)',
                    textTransform: 'uppercase',
                    letterSpacing: '0.3px',
                    minWidth: 48,
                    textAlign: 'right',
                  }}>
                    {item.severity}
                  </span>
                )}
              </label>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
