import { useState, useEffect, useCallback } from 'react';
import {
  getTools, updateAIProvider, getAIProviders,
  listNotesProviders, createNotesProvider, updateNotesProvider,
  deleteNotesProvider, testNotesProvider,
  type NotesProvider as NotesProviderRow,
} from '@/lib/api';
import type { Tool, AIProvider } from '@/lib/types';
import { useToast } from '@/components/Toast';
import { ThemePicker } from '@/components/ThemePicker';
import { LanguageSwitcher } from '@/components/LanguageSwitcher';

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

type SettingsTab = 'general' | 'appearance' | 'language' | 'tools' | 'profiles' | 'notes' | 'advanced';

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

      <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', marginBottom: 24, flexShrink: 0, flexWrap: 'wrap' }}>
        <button style={tabStyle('general')} onClick={() => setTab('general')}>General</button>
        <button style={tabStyle('appearance')} onClick={() => setTab('appearance')}>Appearance</button>
        <button style={tabStyle('language')} onClick={() => setTab('language')}>Language</button>
        <button style={tabStyle('tools')} onClick={() => setTab('tools')}>Tools</button>
        <button style={tabStyle('profiles')} onClick={() => setTab('profiles')}>Scan Profiles</button>
        <button style={tabStyle('notes')} onClick={() => setTab('notes')}>Note Backends</button>
        <button style={tabStyle('advanced' as any)} onClick={() => setTab('advanced' as any)}>Advanced</button>
      </div>

      {tab === 'appearance' && (
        <div style={{ overflowY: 'auto', paddingRight: 8, flex: 1 }}>
          <div style={{ marginBottom: 16, color: 'var(--muted)', fontSize: 13 }}>
            Pick a theme. Choice persists to <code>localStorage['vulnforge.theme']</code>.
            Select &quot;System preference&quot; to auto-follow your OS theme.
          </div>
          <ThemePicker />
        </div>
      )}

      {tab === 'language' && (
        <div style={{ overflowY: 'auto', paddingRight: 8, flex: 1 }}>
          <div style={{ marginBottom: 16, color: 'var(--muted)', fontSize: 13 }}>
            Interface language. Choice persists to <code>localStorage['vulnforge.lang']</code>.
            RTL locales (Arabic, Hebrew) flip <code>document.dir</code> automatically.
          </div>
          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <span style={{ fontSize: 13, color: 'var(--muted)' }}>Current:</span>
            <LanguageSwitcher />
          </div>
        </div>
      )}

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

      {/* Note Backends tab */}
      {tab === 'notes' && <NoteBackendsSection />}

      {/* Advanced tab */}
      {tab === ('advanced' as any) && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20, maxWidth: 600 }}>
          <Section title="Scan Behavior">
            <Field label="Scan Timeout (seconds per tool, 0 = unlimited)">
              <input
                type="number"
                value={localStorage.getItem('vf_scan_timeout') || '300'}
                onChange={e => localStorage.setItem('vf_scan_timeout', e.target.value)}
                style={inputStyle}
              />
            </Field>
            <Field label="Max Concurrent Scan Jobs">
              <input
                type="number"
                min={1}
                max={10}
                value={localStorage.getItem('vf_max_concurrent') || '3'}
                onChange={e => localStorage.setItem('vf_max_concurrent', e.target.value)}
                style={inputStyle}
              />
            </Field>
          </Section>

          <Section title="Sandbox Defaults">
            <Field label="Default Docker Memory Limit">
              <input
                value={localStorage.getItem('vf_sandbox_memory') || '512m'}
                onChange={e => localStorage.setItem('vf_sandbox_memory', e.target.value)}
                placeholder="512m, 1g, 2g"
                style={inputStyle}
              />
            </Field>
            <Field label="Default Docker CPU Limit">
              <input
                type="number"
                step={0.5}
                value={localStorage.getItem('vf_sandbox_cpu') || '2'}
                onChange={e => localStorage.setItem('vf_sandbox_cpu', e.target.value)}
                style={inputStyle}
              />
            </Field>
            <Field label="Default Sandbox Timeout (seconds, 0 = unlimited)">
              <input
                type="number"
                value={localStorage.getItem('vf_sandbox_timeout') || '0'}
                onChange={e => localStorage.setItem('vf_sandbox_timeout', e.target.value)}
                style={inputStyle}
              />
            </Field>
          </Section>

          <Section title="Pipeline Defaults">
            <Field label="Auto-Triage After Scan">
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={localStorage.getItem('vf_auto_triage') === 'true'}
                  onChange={e => localStorage.setItem('vf_auto_triage', String(e.target.checked))}
                  style={{ accentColor: 'var(--blue)' }}
                />
                <span style={{ color: 'var(--text)', fontSize: 13 }}>Automatically run AI triage on new findings</span>
              </label>
            </Field>
            <Field label="Skip AI Stages When No Provider Enabled">
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={localStorage.getItem('vf_noai_mode') !== 'false'}
                  onChange={e => localStorage.setItem('vf_noai_mode', String(e.target.checked))}
                  style={{ accentColor: 'var(--blue)' }}
                />
                <span style={{ color: 'var(--text)', fontSize: 13 }}>Allow pipeline to complete without AI (no-AI mode)</span>
              </label>
            </Field>
          </Section>

          <Section title="Data">
            <div style={{ display: 'flex', gap: 8 }}>
              <a href="/api/export/sarif" download style={{
                padding: '8px 14px', background: 'var(--blue)', color: '#fff',
                border: 'none', borderRadius: 5, fontSize: 12, fontWeight: 600,
                textDecoration: 'none', cursor: 'pointer',
              }}>Export SARIF</a>
              <a href="/api/export/workspace" download style={{
                padding: '8px 14px', background: 'var(--green)', color: '#000',
                border: 'none', borderRadius: 5, fontSize: 12, fontWeight: 600,
                textDecoration: 'none', cursor: 'pointer',
              }}>Backup Workspace</a>
            </div>
            <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 8 }}>
              SARIF exports findings in a format compatible with GitHub Code Scanning, GitLab, and Azure DevOps.
              Workspace backup creates a full JSON dump of all data for migration or disaster recovery.
            </div>
          </Section>
        </div>
      )}
    </div>
  );
}

function NoteBackendsSection() {
  const { toast } = useToast();
  const [providers, setProviders] = useState<NotesProviderRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [adding, setAdding] = useState(false);
  const [newName, setNewName] = useState('');
  const [newType, setNewType] = useState<'local' | 'obsidian'>('obsidian');
  const [newPath, setNewPath] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await listNotesProviders();
      setProviders(res.data || []);
    } catch (err: any) {
      toast(`Failed to load: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => { load(); }, [load]);

  const handleAdd = async () => {
    if (!newName.trim() || !newPath.trim()) {
      toast('Name and path are required', 'error');
      return;
    }
    try {
      const config = newType === 'obsidian'
        ? { vault_path: newPath.trim(), subfolder: 'VulnForge' }
        : { base_path: newPath.trim() };
      await createNotesProvider({ name: newName.trim(), type: newType, config, enabled: true });
      toast(`Added ${newName}`, 'success');
      setAdding(false);
      setNewName('');
      setNewPath('');
      load();
    } catch (err: any) {
      toast(`Failed: ${err.message}`, 'error');
    }
  };

  const handleTest = async (id: number) => {
    try {
      const res = await testNotesProvider(id);
      if (res.ok) toast('Connection OK', 'success');
      else toast(`Connection failed: ${res.error || 'unknown error'}`, 'error');
    } catch (err: any) {
      toast(`Test failed: ${err.message}`, 'error');
    }
  };

  const handleToggle = async (p: NotesProviderRow) => {
    try {
      await updateNotesProvider(p.id, { enabled: p.enabled ? 0 : 1 } as any);
      load();
    } catch (err: any) {
      toast(`Update failed: ${err.message}`, 'error');
    }
  };

  const handleSetDefault = async (p: NotesProviderRow) => {
    try {
      // Unset any current default, set this one
      for (const other of providers) {
        if (other.is_default && other.id !== p.id) {
          await updateNotesProvider(other.id, { is_default: 0 } as any);
        }
      }
      await updateNotesProvider(p.id, { is_default: 1 } as any);
      toast(`${p.name} set as default`, 'success');
      load();
    } catch (err: any) {
      toast(`Update failed: ${err.message}`, 'error');
    }
  };

  const handleDelete = async (id: number, name: string) => {
    if (!confirm(`Delete provider "${name}"? Existing notes will remain in the backend but won't be listed in VulnForge.`)) return;
    try {
      await deleteNotesProvider(id);
      toast('Provider removed', 'info');
      load();
    } catch (err: any) {
      toast(`Delete failed: ${err.message}`, 'error');
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <p style={{ fontSize: 13, color: 'var(--muted)', margin: 0 }}>
        Note backends store your research notes, hypotheses, and observations. Each provider keeps content in its own format (local markdown files, Obsidian vault, etc.) - VulnForge only stores metadata. You can enable multiple backends.
      </p>

      {loading ? (
        <div style={{ padding: 24, textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>Loading...</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {providers.map(p => {
            const config = (() => { try { return JSON.parse(p.config || '{}'); } catch { return {}; } })();
            return (
              <div key={p.id} style={{
                background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8,
                padding: '14px 18px', display: 'flex', alignItems: 'center', gap: 14,
              }}>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--text)' }}>{p.name}</span>
                    <span style={{
                      fontSize: 10, padding: '2px 8px', borderRadius: 10, textTransform: 'uppercase',
                      background: `var(--${p.type === 'obsidian' ? 'purple' : 'blue'})22`,
                      color: `var(--${p.type === 'obsidian' ? 'purple' : 'blue'})`,
                    }}>{p.type}</span>
                    {p.is_default ? (
                      <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 10, background: 'var(--green)22', color: 'var(--green)' }}>DEFAULT</span>
                    ) : null}
                    {!p.enabled ? (
                      <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 10, background: 'var(--muted)22', color: 'var(--muted)' }}>DISABLED</span>
                    ) : null}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 4, fontFamily: 'monospace' }}>
                    {config.vault_path || config.base_path || config.url || '(no path)'}
                    {config.subfolder ? ` → ${config.subfolder}/` : ''}
                  </div>
                </div>
                <button onClick={() => handleTest(p.id)} style={btn('var(--blue)')}>Test</button>
                <button onClick={() => handleToggle(p)} style={btn('var(--surface-2)')}>
                  {p.enabled ? 'Disable' : 'Enable'}
                </button>
                {!p.is_default && p.enabled ? (
                  <button onClick={() => handleSetDefault(p)} style={btn('var(--surface-2)')}>Set default</button>
                ) : null}
                <button onClick={() => handleDelete(p.id, p.name)} style={btn('var(--red)')}>Delete</button>
              </div>
            );
          })}

          {providers.length === 0 && (
            <div style={{ padding: 24, textAlign: 'center', color: 'var(--muted)', fontSize: 13, border: '1px dashed var(--border)', borderRadius: 8 }}>
              No note backends configured.
            </div>
          )}
        </div>
      )}

      {/* Add new provider */}
      {!adding ? (
        <button onClick={() => setAdding(true)} style={{
          padding: '10px 16px', background: 'var(--surface-2)', color: 'var(--text)',
          border: '1px dashed var(--border)', borderRadius: 8, cursor: 'pointer', fontSize: 13,
        }}>
          + Add note backend
        </button>
      ) : (
        <div style={{ background: 'var(--surface)', border: '1px solid var(--blue)', borderRadius: 8, padding: 16 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)', marginBottom: 12 }}>Add Note Backend</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 10 }}>
            <div>
              <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>Name</label>
              <input value={newName} onChange={e => setNewName(e.target.value)} placeholder="e.g. obsidian-main"
                style={inputStyle} />
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>Type</label>
              <select value={newType} onChange={e => setNewType(e.target.value as any)} style={inputStyle}>
                <option value="obsidian">Obsidian Vault</option>
                <option value="local">Local Filesystem</option>
              </select>
            </div>
          </div>
          <div style={{ marginBottom: 10 }}>
            <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>
              {newType === 'obsidian' ? 'Vault path (the directory containing .obsidian/)' : 'Base directory for note files'}
            </label>
            <input value={newPath} onChange={e => setNewPath(e.target.value)}
              placeholder={newType === 'obsidian' ? 'C:\\Users\\you\\Documents\\MyVault' : 'X:\\vulnforge\\data\\notes'}
              style={inputStyle} />
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={handleAdd} style={btn('var(--green)')}>Add</button>
            <button onClick={() => setAdding(false)} style={btn('var(--surface-2)')}>Cancel</button>
          </div>
        </div>
      )}
    </div>
  );
}

function btn(bg: string): React.CSSProperties {
  return {
    background: bg, color: 'var(--text)', border: '1px solid var(--border)',
    borderRadius: 5, padding: '6px 12px', fontSize: 12, cursor: 'pointer', whiteSpace: 'nowrap',
  };
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
