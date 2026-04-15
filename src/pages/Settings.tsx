import { useState, useEffect, useCallback } from 'react';
import { getTools, updateAIProvider, getAIProviders } from '@/lib/api';
import type { Tool, AIProvider } from '@/lib/types';
import { useToast } from '@/components/Toast';

interface ScanProfile {
  id: string;
  name: string;
  tools: string[];
  severity_threshold: string;
}

const DEFAULT_PROFILES: ScanProfile[] = [
  { id: 'quick', name: 'Quick Scan', tools: ['dangerous_patterns', 'integer_overflow_scanner'], severity_threshold: 'High' },
  { id: 'full', name: 'Full Scan', tools: ['all'], severity_threshold: 'Medium' },
  { id: 'crypto', name: 'Crypto Audit', tools: ['crypto_misuse_scanner', 'timing_oracle_scanner'], severity_threshold: 'Medium' },
  { id: 'memory', name: 'Memory Safety', tools: ['uaf_detector', 'realloc_dangling_scanner', 'cross_arch_truncation'], severity_threshold: 'High' },
];

type SettingsTab = 'general' | 'tools' | 'profiles';

export default function Settings() {
  const [tab, setTab] = useState<SettingsTab>('general');
  const [tools, setTools] = useState<Tool[]>([]);
  const [providers, setProviders] = useState<AIProvider[]>([]);
  const [toolsLoading, setToolsLoading] = useState(true);
  const [profiles] = useState<ScanProfile[]>(DEFAULT_PROFILES);
  const [severityThreshold, setSeverityThreshold] = useState(() =>
    localStorage.getItem('vf_severity_threshold') ?? 'Medium'
  );
  const [autoTriage, setAutoTriage] = useState(() =>
    localStorage.getItem('vf_auto_triage') === 'true'
  );
  const [maxFindings, setMaxFindings] = useState(() =>
    localStorage.getItem('vf_max_findings') ?? '1000'
  );
  const { toast } = useToast();

  const load = useCallback(async () => {
    setToolsLoading(true);
    try {
      const [t, p] = await Promise.all([getTools(), getAIProviders()]);
      setTools(t);
      setProviders(p);
    } catch (err) {
      toast(`Load error: ${err instanceof Error ? err.message : err}`, 'error');
    } finally {
      setToolsLoading(false);
    }
  }, [toast]);

  useEffect(() => { load(); }, [load]);

  const saveGeneral = () => {
    localStorage.setItem('vf_severity_threshold', severityThreshold);
    localStorage.setItem('vf_auto_triage', String(autoTriage));
    localStorage.setItem('vf_max_findings', maxFindings);
    toast('Settings saved', 'success');
  };

  const toggleProvider = async (p: AIProvider) => {
    try {
      const updated = await updateAIProvider(p.id, { enabled: !p.enabled });
      setProviders(prev => prev.map(x => x.id === p.id ? updated : x));
      toast(`${p.name} ${updated.enabled ? 'enabled' : 'disabled'}`, 'success');
    } catch (err) {
      toast(`Failed: ${err instanceof Error ? err.message : err}`, 'error');
    }
  };

  const tabStyle = (t: SettingsTab): React.CSSProperties => ({
    background: 'none',
    border: 'none',
    borderBottom: tab === t ? '2px solid var(--blue)' : '2px solid transparent',
    color: tab === t ? 'var(--text)' : 'var(--muted)',
    padding: '8px 16px',
    cursor: 'pointer',
    fontSize: 13,
    fontWeight: tab === t ? 600 : 400,
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
      <div style={{ marginBottom: 20 }}>
        <h2 style={{ fontSize: 20, fontWeight: 700, margin: 0, color: 'var(--text)' }}>Settings</h2>
        <p style={{ fontSize: 12, color: 'var(--muted)', margin: '4px 0 0' }}>Configure VulnForge preferences and scan behavior</p>
      </div>

      <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', marginBottom: 24, flexShrink: 0 }}>
        <button style={tabStyle('general')} onClick={() => setTab('general')}>General</button>
        <button style={tabStyle('tools')} onClick={() => setTab('tools')}>Tools</button>
        <button style={tabStyle('profiles')} onClick={() => setTab('profiles')}>Scan Profiles</button>
      </div>

      {/* General tab */}
      {tab === 'general' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20, maxWidth: 600 }}>
          <Section title="Analysis Defaults">
            <Field label="Minimum Severity to Report">
              <select
                value={severityThreshold}
                onChange={e => setSeverityThreshold(e.target.value)}
                style={selectStyle}
              >
                <option value="Critical">Critical only</option>
                <option value="High">High and above</option>
                <option value="Medium">Medium and above</option>
                <option value="Low">Low and above</option>
                <option value="Info">All (including Info)</option>
              </select>
            </Field>
            <Field label="Max Findings to Store">
              <input
                type="number"
                value={maxFindings}
                onChange={e => setMaxFindings(e.target.value)}
                style={inputStyle}
                min={100}
                max={100000}
              />
            </Field>
          </Section>

          <Section title="AI Behavior">
            <Field label="">
              <label style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={autoTriage}
                  onChange={e => setAutoTriage(e.target.checked)}
                  style={{ accentColor: 'var(--blue)', width: 14, height: 14 }}
                />
                <span style={{ fontSize: 13, color: 'var(--text)' }}>Auto-triage new findings after scan</span>
              </label>
            </Field>
          </Section>

          <Section title="AI Providers">
            {providers.map(p => (
              <div key={p.id} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
                <span style={{ flex: 1, fontSize: 13, color: 'var(--text)' }}>{p.name}</span>
                <code style={{ fontSize: 11, color: 'var(--muted)' }}>{p.model || 'not configured'}</code>
                <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', fontSize: 12 }}>
                  <input
                    type="checkbox"
                    checked={p.enabled}
                    onChange={() => toggleProvider(p)}
                    style={{ accentColor: 'var(--blue)' }}
                  />
                  <span style={{ color: p.enabled ? 'var(--green)' : 'var(--muted)' }}>
                    {p.enabled ? 'On' : 'Off'}
                  </span>
                </label>
              </div>
            ))}
          </Section>

          <button
            onClick={saveGeneral}
            style={{
              background: 'var(--blue)',
              border: 'none',
              borderRadius: 6,
              padding: '9px 20px',
              color: '#fff',
              fontSize: 13,
              fontWeight: 600,
              cursor: 'pointer',
              alignSelf: 'flex-start',
            }}
          >
            Save Settings
          </button>
        </div>
      )}

      {/* Tools tab */}
      {tab === 'tools' && (
        <div>
          {toolsLoading ? (
            <div style={{ padding: 32, textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>Loading tools...</div>
          ) : (
            <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    {['Tool', 'Category', 'Description', 'Enabled'].map(h => (
                      <th key={h} style={{ padding: '9px 14px', textAlign: 'left', color: 'var(--muted)', fontWeight: 500, fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.4px' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {tools.map(t => (
                    <tr key={t.id} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '9px 14px', color: 'var(--purple)', fontWeight: 600, whiteSpace: 'nowrap' }}>{t.name}</td>
                      <td style={{ padding: '9px 14px', color: 'var(--muted)', fontSize: 11 }}>{t.category}</td>
                      <td style={{ padding: '9px 14px', color: 'var(--muted)', fontSize: 12, maxWidth: 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{t.description}</td>
                      <td style={{ padding: '9px 14px' }}>
                        <span style={{
                          fontSize: 11,
                          fontWeight: 600,
                          color: t.enabled ? 'var(--green)' : 'var(--muted)',
                        }}>
                          {t.enabled ? 'Yes' : 'No'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Profiles tab */}
      {tab === 'profiles' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <p style={{ fontSize: 13, color: 'var(--muted)', margin: 0 }}>
            Scan profiles define which tools run and what severity threshold to apply.
          </p>
          {profiles.map(profile => (
            <div
              key={profile.id}
              style={{
                background: 'var(--surface)',
                border: '1px solid var(--border)',
                borderRadius: 8,
                padding: '16px 20px',
              }}
            >
              <div style={{ fontWeight: 600, fontSize: 14, color: 'var(--text)', marginBottom: 8 }}>{profile.name}</div>
              <div style={{ display: 'flex', gap: 20, fontSize: 12, color: 'var(--muted)' }}>
                <div>
                  <span style={{ color: 'var(--muted)', textTransform: 'uppercase', fontSize: 10, letterSpacing: '0.4px' }}>Tools: </span>
                  <span style={{ color: 'var(--text)' }}>{profile.tools.join(', ')}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--muted)', textTransform: 'uppercase', fontSize: 10, letterSpacing: '0.4px' }}>Min Severity: </span>
                  <span style={{ color: profile.severity_threshold === 'Critical' ? 'var(--red)' : profile.severity_threshold === 'High' ? 'var(--orange)' : 'var(--yellow)' }}>
                    {profile.severity_threshold}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
      <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--border)', fontSize: 12, fontWeight: 600, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
        {title}
      </div>
      <div style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 12 }}>
        {children}
      </div>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      {label && <label style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.5px', fontWeight: 600 }}>{label}</label>}
      {children}
    </div>
  );
}

const selectStyle: React.CSSProperties = {
  background: 'var(--bg)',
  border: '1px solid var(--border)',
  borderRadius: 5,
  padding: '7px 10px',
  color: 'var(--text)',
  fontSize: 13,
  outline: 'none',
  cursor: 'pointer',
  width: '100%',
};

const inputStyle: React.CSSProperties = {
  background: 'var(--bg)',
  border: '1px solid var(--border)',
  borderRadius: 5,
  padding: '7px 10px',
  color: 'var(--text)',
  fontSize: 13,
  outline: 'none',
  width: '100%',
};
