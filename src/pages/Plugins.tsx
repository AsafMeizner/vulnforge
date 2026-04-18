import { useState, useEffect, useCallback, useRef } from 'react';
import { resolveWsBase, apiFetch } from '@/lib/api';

// -- Types --------------------------------------------------------------------

interface CatalogEntry {
  name: string;
  source_url: string;
  type: string;
  description: string;
  install_command: string;
  run_command: string;
  parse_output: string;
  requires: string[];
  version: string;
  installed: boolean;
}

interface InstalledPlugin {
  id: number;
  name: string;
  type: string | null;
  source_url: string | null;
  install_path: string | null;
  version: string | null;
  manifest: string | null;
  enabled: number;
  installed_at: string | null;
}

interface PluginStatus {
  status: 'idle' | 'installing' | 'running' | 'error' | 'ready';
  message?: string;
  lastRun?: string;
  requirements?: { met: boolean; missing: string[] };
}

interface Project {
  id: number;
  name: string;
  path: string;
}

interface RunDialogState {
  plugin: InstalledPlugin;
  modules: string[];
}

// -- Constants ----------------------------------------------------------------

const TYPE_COLORS: Record<string, string> = {
  scanner: 'var(--blue)',
  reporter: 'var(--green)',
  importer: 'var(--orange)',
};

const STATUS_COLORS: Record<string, string> = {
  idle: 'var(--muted)',
  ready: 'var(--green)',
  installing: 'var(--orange)',
  running: 'var(--orange)',
  error: 'var(--red)',
};

const PLUGIN_ICONS: Record<string, string> = {
  'OWASP Nettacker': '🌐',
  'Garak': '🤖',
  'Nuclei': '⚡',
  'Semgrep': '🔍',
  'Trivy': '🐳',
  'CodeQL': '📊',
  'Bandit': '🐍',
  'Grype': '⚓',
  'OSV-Scanner': '📦',
  'Safety': '🛡',
};

// -- Small components ---------------------------------------------------------

function Badge({
  label,
  color,
}: {
  label: string;
  color: string;
}) {
  return (
    <span
      style={{
        fontSize: 9,
        fontWeight: 700,
        letterSpacing: '0.4px',
        textTransform: 'uppercase',
        color,
        background: `${color}22`,
        border: `1px solid ${color}44`,
        padding: '1px 6px',
        borderRadius: 3,
        display: 'inline-block',
        flexShrink: 0,
      }}
    >
      {label}
    </span>
  );
}

function StatusDot({ status }: { status: string }) {
  return (
    <span
      title={status}
      style={{
        display: 'inline-block',
        width: 7,
        height: 7,
        borderRadius: '50%',
        background: STATUS_COLORS[status] ?? 'var(--muted)',
        flexShrink: 0,
      }}
    />
  );
}

function RequirementsList({ reqs }: { reqs: string[] }) {
  if (reqs.length === 0) return null;
  return (
    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
      {reqs.map((r) => (
        <span
          key={r}
          style={{
            fontSize: 9,
            color: 'var(--muted)',
            background: 'var(--bg)',
            border: '1px solid var(--border)',
            borderRadius: 3,
            padding: '1px 5px',
            fontFamily: 'monospace',
          }}
        >
          {r}
        </span>
      ))}
    </div>
  );
}

// -- Run Dialog ---------------------------------------------------------------

interface RunDialogProps {
  plugin: InstalledPlugin;
  modules: string[];
  projects: Project[];
  onClose: () => void;
}

function RunDialog({ plugin, modules, projects, onClose }: RunDialogProps) {
  const [target, setTarget] = useState('');
  const [projectId, setProjectId] = useState<number | ''>('');
  const [selectedModules, setSelectedModules] = useState<Set<string>>(new Set());
  const [severity, setSeverity] = useState<string[]>([]);
  const [running, setRunning] = useState(false);
  const [output, setOutput] = useState<string[]>([]);
  const [findingsCount, setFindingsCount] = useState<number | null>(null);
  const outputRef = useRef<HTMLDivElement>(null);

  // Determine effective target
  const effectiveTarget = projectId
    ? (projects.find((p) => p.id === Number(projectId))?.path ?? target)
    : target;

  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [output]);

  const handleRun = async () => {
    const t = effectiveTarget.trim();
    if (!t) return;
    setRunning(true);
    setOutput([`[plugin] Starting "${plugin.name}" against: ${t}`]);
    setFindingsCount(null);

    try {
      const options: Record<string, any> = {};
      if (selectedModules.size > 0) options.modules = [...selectedModules];
      if (severity.length > 0) options.severity = severity;

      const res = await apiFetch(`/api/plugins/${plugin.id}/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: t,
          options,
          project_id: projectId || undefined,
        }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({ error: res.statusText }));
        setOutput((prev) => [...prev, `[error] ${body.error || res.statusText}`]);
      } else {
        setOutput((prev) => [
          ...prev,
          '[plugin] Scan enqueued. Results will be saved to Findings.',
        ]);
        setFindingsCount(0);
      }
    } catch (err: any) {
      setOutput((prev) => [...prev, `[error] ${err.message}`]);
    } finally {
      setRunning(false);
    }
  };

  const toggleModule = (m: string) => {
    setSelectedModules((prev) => {
      const next = new Set(prev);
      if (next.has(m)) next.delete(m);
      else next.add(m);
      return next;
    });
  };

  const severities = ['Critical', 'High', 'Medium', 'Low'];
  const toggleSeverity = (s: string) =>
    setSeverity((prev) =>
      prev.includes(s) ? prev.filter((x) => x !== s) : [...prev, s]
    );

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.6)',
        zIndex: 1000,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div
        style={{
          background: 'var(--surface)',
          border: '1px solid var(--border)',
          borderRadius: 10,
          width: 560,
          maxHeight: '85vh',
          overflowY: 'auto',
          padding: 24,
          display: 'flex',
          flexDirection: 'column',
          gap: 16,
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div style={{ fontWeight: 700, fontSize: 16, color: 'var(--text)' }}>
              {PLUGIN_ICONS[plugin.name] ?? ''} Run {plugin.name}
            </div>
            <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>
              v{plugin.version ?? 'unknown'}
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'none', border: 'none', color: 'var(--muted)',
              cursor: 'pointer', fontSize: 18, lineHeight: 1,
            }}
          >
            x
          </button>
        </div>

        {/* Target selection */}
        <div>
          <label style={labelSt}>Target</label>
          <div style={{ display: 'flex', gap: 8 }}>
            <select
              value={projectId}
              onChange={(e) => setProjectId(e.target.value ? Number(e.target.value) : '')}
              style={{ ...inputSt, width: 160, flexShrink: 0 }}
            >
              <option value="">Custom path / URL</option>
              {projects.map((p) => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
            {!projectId && (
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="Path or URL..."
                style={{ ...inputSt, flex: 1 }}
              />
            )}
          </div>
          {projectId && (
            <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 4 }}>
              Path: {projects.find((p) => p.id === Number(projectId))?.path ?? ''}
            </div>
          )}
        </div>

        {/* Severity filter */}
        <div>
          <label style={labelSt}>Severity Filter (leave empty for all)</label>
          <div style={{ display: 'flex', gap: 6 }}>
            {severities.map((s) => {
              const color =
                s === 'Critical' ? 'var(--red)' :
                s === 'High' ? 'var(--orange)' :
                s === 'Medium' ? 'var(--yellow)' : 'var(--muted)';
              const active = severity.includes(s);
              return (
                <button
                  key={s}
                  onClick={() => toggleSeverity(s)}
                  style={{
                    background: active ? `${color}22` : 'var(--bg)',
                    border: `1px solid ${active ? color : 'var(--border)'}`,
                    borderRadius: 4,
                    padding: '4px 10px',
                    color: active ? color : 'var(--muted)',
                    fontSize: 11,
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                >
                  {s}
                </button>
              );
            })}
          </div>
        </div>

        {/* Modules / probes / templates */}
        {modules.length > 0 && (
          <div>
            <label style={labelSt}>
              Modules / Templates
              {selectedModules.size > 0 && (
                <span style={{ color: 'var(--blue)', marginLeft: 6 }}>
                  ({selectedModules.size} selected)
                </span>
              )}
            </label>
            <div
              style={{
                display: 'flex',
                flexWrap: 'wrap',
                gap: 6,
                maxHeight: 120,
                overflowY: 'auto',
                background: 'var(--bg)',
                border: '1px solid var(--border)',
                borderRadius: 6,
                padding: 8,
              }}
            >
              {modules.map((m) => (
                <label
                  key={m}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 4,
                    fontSize: 11,
                    color: 'var(--text)',
                    cursor: 'pointer',
                    background: selectedModules.has(m) ? 'var(--blue)22' : 'none',
                    border: `1px solid ${selectedModules.has(m) ? 'var(--blue)44' : 'transparent'}`,
                    borderRadius: 4,
                    padding: '2px 6px',
                  }}
                >
                  <input
                    type="checkbox"
                    checked={selectedModules.has(m)}
                    onChange={() => toggleModule(m)}
                    style={{ accentColor: 'var(--blue)', width: 12, height: 12 }}
                  />
                  {m}
                </label>
              ))}
            </div>
          </div>
        )}

        {/* Live output */}
        {output.length > 0 && (
          <div>
            <label style={labelSt}>Output</label>
            <div
              ref={outputRef}
              style={{
                background: 'var(--bg)',
                border: '1px solid var(--border)',
                borderRadius: 6,
                padding: '10px 12px',
                fontFamily: 'monospace',
                fontSize: 11,
                lineHeight: 1.6,
                maxHeight: 160,
                overflowY: 'auto',
                color: 'var(--text)',
              }}
            >
              {output.map((line, i) => (
                <div
                  key={i}
                  style={{
                    color: line.startsWith('[error]') ? 'var(--red)'
                      : line.startsWith('[plugin]') ? 'var(--blue)'
                      : 'var(--text)',
                  }}
                >
                  {line}
                </div>
              ))}
            </div>
          </div>
        )}

        {findingsCount !== null && (
          <div
            style={{
              background: 'var(--green)11',
              border: '1px solid var(--green)44',
              borderRadius: 6,
              padding: '8px 12px',
              fontSize: 12,
              color: 'var(--green)',
            }}
          >
            Scan queued. Findings will appear in the Findings page when complete.
          </div>
        )}

        {/* Actions */}
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button onClick={onClose} style={secondaryBtnSt}>Cancel</button>
          <button
            onClick={handleRun}
            disabled={running || !effectiveTarget.trim()}
            style={{
              ...primaryBtnSt,
              opacity: running || !effectiveTarget.trim() ? 0.5 : 1,
              cursor: running || !effectiveTarget.trim() ? 'not-allowed' : 'pointer',
            }}
          >
            {running ? 'Starting...' : 'Run Plugin'}
          </button>
        </div>
      </div>
    </div>
  );
}

// -- Main Plugins page --------------------------------------------------------

export default function Plugins() {
  const [catalog, setCatalog] = useState<CatalogEntry[]>([]);
  const [installed, setInstalled] = useState<InstalledPlugin[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [statuses, setStatuses] = useState<Record<number, PluginStatus>>({});
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [installingName, setInstallingName] = useState<string | null>(null);
  const [installError, setInstallError] = useState<string | null>(null);
  const [runDialog, setRunDialog] = useState<RunDialogState | null>(null);
  const [activeTab, setActiveTab] = useState<'catalog' | 'installed'>('catalog');
  const [installProgress, setInstallProgress] = useState<{ step: string; detail?: string; progress: number } | null>(null);

  // WebSocket for install progress
  useEffect(() => {
    // resolveWsBase (imported at top) handles Electron file:// (no
    // location.host), vite proxy, and same-origin modes.
    const ws = new WebSocket(resolveWsBase());
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.type === 'progress' && msg.category === 'plugin-install') {
          setInstallProgress({ step: msg.step, detail: msg.detail, progress: msg.progress ?? 0 });
          if (msg.status === 'complete' || msg.status === 'error') {
            setTimeout(() => setInstallProgress(null), 3000);
          }
        }
      } catch {}
    };
    return () => ws.close();
  }, []);

  const load = useCallback(async () => {
    try {
      const [plugRes, projRes] = await Promise.all([
        apiFetch('/api/plugins'),
        apiFetch('/api/projects'),
      ]);
      if (plugRes.ok) {
        const data = await plugRes.json() as {
          data: { installed: InstalledPlugin[]; catalog: CatalogEntry[] };
        };
        setInstalled(data.data.installed ?? []);
        setCatalog(data.data.catalog ?? []);
      }
      if (projRes.ok) {
        const data = await projRes.json() as { data: Project[] };
        setProjects(data.data ?? []);
      }
    } catch { /* non-fatal */ }
  }, []);

  // Poll statuses for installed plugins
  const pollStatuses = useCallback(async () => {
    if (installed.length === 0) return;
    const results = await Promise.allSettled(
      installed
        .filter((p) => p.id != null)
        .map(async (p) => {
          const res = await apiFetch(`/api/plugins/${p.id}/status`);
          if (res.ok) return { id: p.id, status: await res.json() as PluginStatus };
          return null;
        })
    );
    const next: Record<number, PluginStatus> = { ...statuses };
    for (const r of results) {
      if (r.status === 'fulfilled' && r.value) {
        next[r.value.id] = r.value.status;
      }
    }
    setStatuses(next);
  }, [installed]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { load(); }, [load]);
  useEffect(() => { pollStatuses(); }, [pollStatuses]);

  const [missingDeps, setMissingDeps] = useState<{ deps: string[]; commands: Record<string, string>; pluginName: string } | null>(null);
  const [installingDep, setInstallingDep] = useState<string | null>(null);

  const handleInstall = async (name: string) => {
    setInstallingName(name);
    setInstallError(null);
    setMissingDeps(null);
    try {
      const res = await apiFetch('/api/plugins/install', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name }),
      });
      if (res.status === 422) {
        // Missing dependencies - show install commands
        const body = await res.json();
        setMissingDeps({ deps: body.missingDeps, commands: body.installCommands, pluginName: name });
        setInstallError(null);
      } else if (!res.ok) {
        const body = await res.json().catch(() => ({ error: res.statusText }));
        setInstallError(body.error ?? 'Install failed');
      } else {
        await load();
        setActiveTab('installed');
      }
    } catch (err: any) {
      setInstallError(err.message);
    } finally {
      setInstallingName(null);
    }
  };

  const handleInstallDep = async (dep: string) => {
    setInstallingDep(dep);
    try {
      const res = await apiFetch('/api/plugins/install-dep', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ dependency: dep }),
      });
      const body = await res.json();
      if (body.ok) {
        // Remove from missing list
        setMissingDeps(prev => {
          if (!prev) return null;
          const remaining = prev.deps.filter(d => d !== dep);
          if (remaining.length === 0) {
            // All deps installed - retry plugin install
            setTimeout(() => handleInstall(prev.pluginName), 500);
            return null;
          }
          return { ...prev, deps: remaining };
        });
      } else {
        setInstallError(`Failed to install ${dep}: ${body.output?.substring(0, 200) ?? 'unknown error'}`);
      }
    } catch (err: any) {
      setInstallError(`Failed to install ${dep}: ${err.message}`);
    } finally {
      setInstallingDep(null);
    }
  };

  const handleUninstall = async (id: number, name: string) => {
    if (!window.confirm(`Uninstall "${name}"? The plugin files will remain on disk.`)) return;
    try {
      const res = await apiFetch(`/api/plugins/${id}`, { method: 'DELETE' });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        setInstallError(`Failed to uninstall ${name}: ${body.error || `HTTP ${res.status}`}`);
        return;
      }
      setInstallError(null);
      await load();
    } catch (err: any) {
      setInstallError(`Failed to uninstall ${name}: ${err.message}`);
    }
  };

  const handleOpenRun = async (plugin: InstalledPlugin) => {
    const res = await apiFetch(`/api/plugins/${plugin.id}/modules`);
    const modules: string[] = res.ok
      ? ((await res.json()) as { modules: string[] }).modules ?? []
      : [];
    setRunDialog({ plugin, modules });
  };

  const filteredCatalog = catalog.filter((e) => {
    const matchSearch =
      !search ||
      e.name.toLowerCase().includes(search.toLowerCase()) ||
      e.description.toLowerCase().includes(search.toLowerCase());
    const matchType = !typeFilter || e.type === typeFilter;
    return matchSearch && matchType;
  });

  const types = [...new Set(catalog.map((e) => e.type))].sort();
  const installedCount = catalog.filter((e) => e.installed).length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Page header */}
      <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between' }}>
        <div>
          <h2 style={{ fontSize: 20, fontWeight: 700, margin: 0, color: 'var(--text)' }}>
            Plugins
          </h2>
          <p style={{ fontSize: 12, color: 'var(--muted)', margin: '4px 0 0' }}>
            External security tools that integrate with VulnForge &mdash;{' '}
            {installedCount}/{catalog.length} installed
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={() => setActiveTab('catalog')}
            style={{
              background: activeTab === 'catalog' ? 'var(--blue)22' : 'var(--surface)',
              border: `1px solid ${activeTab === 'catalog' ? 'var(--blue)' : 'var(--border)'}`,
              borderRadius: 6,
              padding: '6px 14px',
              color: activeTab === 'catalog' ? 'var(--blue)' : 'var(--muted)',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Catalog ({catalog.length})
          </button>
          <button
            onClick={() => setActiveTab('installed')}
            style={{
              background: activeTab === 'installed' ? 'var(--green)22' : 'var(--surface)',
              border: `1px solid ${activeTab === 'installed' ? 'var(--green)' : 'var(--border)'}`,
              borderRadius: 6,
              padding: '6px 14px',
              color: activeTab === 'installed' ? 'var(--green)' : 'var(--muted)',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Installed ({installed.length})
          </button>
        </div>
      </div>

      {/* Missing dependencies banner */}
      {missingDeps && (
        <div style={{
          background: 'var(--orange)11',
          border: '1px solid var(--orange)44',
          borderRadius: 6,
          padding: '14px',
          fontSize: 13,
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
            <span style={{ color: 'var(--orange)', fontWeight: 600 }}>
              Missing dependencies for {missingDeps.pluginName}
            </span>
            <button
              onClick={() => setMissingDeps(null)}
              style={{ background: 'none', border: 'none', color: 'var(--muted)', cursor: 'pointer', fontSize: 16 }}
            >
              &times;
            </button>
          </div>
          {missingDeps.deps.map(dep => (
            <div key={dep} style={{
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              padding: '8px 0',
              borderTop: '1px solid var(--border)',
            }}>
              <code style={{
                background: 'var(--bg)',
                padding: '2px 8px',
                borderRadius: 4,
                color: 'var(--red)',
                fontWeight: 600,
                fontSize: 12,
              }}>{dep}</code>
              <code style={{
                flex: 1,
                background: 'var(--bg)',
                padding: '6px 10px',
                borderRadius: 4,
                fontSize: 11,
                color: 'var(--text)',
                fontFamily: 'monospace',
              }}>{missingDeps.commands[dep]}</code>
              <button
                onClick={() => handleInstallDep(dep)}
                disabled={installingDep !== null}
                style={{
                  padding: '5px 12px',
                  borderRadius: 4,
                  border: '1px solid var(--green)',
                  background: installingDep === dep ? 'var(--green)22' : 'var(--green)11',
                  color: 'var(--green)',
                  cursor: installingDep !== null ? 'not-allowed' : 'pointer',
                  fontSize: 11,
                  fontWeight: 600,
                  whiteSpace: 'nowrap',
                }}
              >
                {installingDep === dep ? 'Installing...' : 'Install'}
              </button>
              <button
                onClick={() => { navigator.clipboard.writeText(missingDeps.commands[dep]); }}
                style={{
                  padding: '5px 8px',
                  borderRadius: 4,
                  border: '1px solid var(--border)',
                  background: 'transparent',
                  color: 'var(--muted)',
                  cursor: 'pointer',
                  fontSize: 11,
                }}
              >
                Copy
              </button>
            </div>
          ))}
          <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 8 }}>
            Click Install to auto-install, or Copy the command to run manually. After installing all dependencies, the plugin will be installed automatically.
          </div>
        </div>
      )}

      {/* Install error banner */}
      {installError && !missingDeps && (
        <div
          style={{
            background: 'var(--red)11',
            border: '1px solid var(--red)44',
            borderRadius: 6,
            padding: '10px 14px',
            fontSize: 12,
            color: 'var(--red)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          <span>Install error: {installError}</span>
          <button
            onClick={() => setInstallError(null)}
            style={{ background: 'none', border: 'none', color: 'var(--red)', cursor: 'pointer' }}
          >
            &times;
          </button>
        </div>
      )}

      {/* -- CATALOG TAB -- */}
      {activeTab === 'catalog' && (
        <>
          {/* Add-from-URL - lets the user register an external plugin from
              any git URL. Server endpoint validates + records it; the
              actual clone/install happens when the user clicks Enable. */}
          <AddFromUrl onInstalled={() => { setActiveTab('installed'); load(); }} />

          {/* Filters */}
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              type="text"
              placeholder="Search plugins..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{
                flex: 1,
                background: 'var(--surface)',
                border: '1px solid var(--border)',
                borderRadius: 6,
                padding: '7px 12px',
                color: 'var(--text)',
                fontSize: 13,
                outline: 'none',
              }}
            />
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              style={{
                background: 'var(--surface)',
                border: '1px solid var(--border)',
                borderRadius: 6,
                padding: '7px 10px',
                color: 'var(--text)',
                fontSize: 13,
                outline: 'none',
                cursor: 'pointer',
              }}
            >
              <option value="">All types</option>
              {types.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
            <button
              onClick={load}
              style={{
                background: 'var(--surface)',
                border: '1px solid var(--border)',
                borderRadius: 6,
                padding: '7px 12px',
                color: 'var(--muted)',
                fontSize: 12,
                cursor: 'pointer',
              }}
            >
              Refresh
            </button>
          </div>

          {/* Catalog grid */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))',
              gap: 12,
            }}
          >
            {filteredCatalog.map((entry) => {
              const isInstalling = installingName === entry.name;
              const typeColor = TYPE_COLORS[entry.type] ?? 'var(--muted)';
              return (
                <div
                  key={entry.name}
                  style={{
                    background: 'var(--surface)',
                    border: `1px solid ${entry.installed ? 'var(--green)44' : 'var(--border)'}`,
                    borderRadius: 8,
                    padding: '16px 18px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 10,
                  }}
                >
                  {/* Card header */}
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                    <span style={{ fontSize: 22, lineHeight: 1 }}>
                      {PLUGIN_ICONS[entry.name] ?? '🔧'}
                    </span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                        <span style={{ fontWeight: 700, fontSize: 14, color: 'var(--text)' }}>
                          {entry.name}
                        </span>
                        {entry.installed && (
                          <Badge label="INSTALLED" color="var(--green)" />
                        )}
                        <Badge label={entry.type} color={typeColor} />
                      </div>
                      <div style={{ fontSize: 10, color: 'var(--muted)', marginTop: 1 }}>
                        v{entry.version}
                      </div>
                    </div>
                    <a
                      href={entry.source_url}
                      target="_blank"
                      rel="noreferrer"
                      style={{ fontSize: 11, color: 'var(--blue)', textDecoration: 'none', flexShrink: 0 }}
                    >
                      Docs
                    </a>
                  </div>

                  {/* Description */}
                  <p style={{ margin: 0, fontSize: 12, color: 'var(--muted)', lineHeight: 1.6 }}>
                    {entry.description}
                  </p>

                  {/* Requirements */}
                  {entry.requires.length > 0 && (
                    <div>
                      <div style={{ fontSize: 10, color: 'var(--muted)', marginBottom: 3 }}>
                        REQUIRES
                      </div>
                      <RequirementsList reqs={entry.requires} />
                    </div>
                  )}

                  {/* Install command preview */}
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 6,
                      background: 'var(--bg)',
                      border: '1px solid var(--border)',
                      borderRadius: 5,
                      padding: '5px 8px',
                    }}
                  >
                    <code
                      style={{
                        flex: 1,
                        fontSize: 10,
                        color: 'var(--text)',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {entry.install_command}
                    </code>
                  </div>

                  {/* Actions */}
                  <div style={{ display: 'flex', gap: 6, marginTop: 2 }}>
                    {!entry.installed ? (
                      <>
                        <button
                          onClick={() => handleInstall(entry.name)}
                          disabled={isInstalling || installingName !== null}
                          style={{
                            background: 'var(--green)22',
                            border: '1px solid var(--green)44',
                            borderRadius: 5,
                            padding: '5px 14px',
                            color: 'var(--green)',
                            fontSize: 11,
                            fontWeight: 600,
                            cursor: isInstalling || installingName !== null ? 'not-allowed' : 'pointer',
                            opacity: installingName !== null && !isInstalling ? 0.5 : 1,
                          }}
                        >
                          {isInstalling ? 'Installing...' : 'Install'}
                        </button>
                        {isInstalling && installProgress && (
                          <div style={{ flex: '1 1 100%', marginTop: 6 }}>
                            <div style={{ fontSize: 10, color: 'var(--muted)', marginBottom: 3 }}>
                              {installProgress.step}{installProgress.detail ? ` - ${installProgress.detail}` : ''}
                            </div>
                            <div style={{ height: 4, background: 'var(--border)', borderRadius: 2, overflow: 'hidden' }}>
                              <div style={{
                                height: '100%',
                                width: `${installProgress.progress}%`,
                                background: installProgress.progress >= 100 ? 'var(--green)' : 'var(--blue)',
                                borderRadius: 2,
                                transition: 'width 0.3s ease',
                              }} />
                            </div>
                          </div>
                        )}
                      </>
                    ) : (
                      <button
                        onClick={() => setActiveTab('installed')}
                        style={{
                          background: 'var(--blue)22',
                          border: '1px solid var(--blue)44',
                          borderRadius: 5,
                          padding: '5px 14px',
                          color: 'var(--blue)',
                          fontSize: 11,
                          fontWeight: 600,
                          cursor: 'pointer',
                        }}
                      >
                        View Installed
                      </button>
                    )}
                  </div>
                </div>
              );
            })}

            {filteredCatalog.length === 0 && (
              <div
                style={{
                  gridColumn: '1/-1',
                  textAlign: 'center',
                  padding: 40,
                  color: 'var(--muted)',
                  fontSize: 13,
                }}
              >
                No plugins match your search.
              </div>
            )}
          </div>
        </>
      )}

      {/* -- INSTALLED TAB -- */}
      {activeTab === 'installed' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {installed.length === 0 ? (
            <div
              style={{
                textAlign: 'center',
                padding: 60,
                color: 'var(--muted)',
                fontSize: 13,
                background: 'var(--surface)',
                border: '1px solid var(--border)',
                borderRadius: 8,
              }}
            >
              No plugins installed yet. Go to the Catalog tab to install one.
            </div>
          ) : (
            installed.map((plugin) => {
              const plugStatus = statuses[plugin.id ?? 0] ?? { status: 'idle' };
              const typeColor = TYPE_COLORS[plugin.type ?? ''] ?? 'var(--muted)';

              let parsedManifest: Record<string, any> = {};
              try { parsedManifest = plugin.manifest ? JSON.parse(plugin.manifest) : {}; }
              catch { /* ignore */ }

              return (
                <div
                  key={plugin.id}
                  style={{
                    background: 'var(--surface)',
                    border: `1px solid ${plugin.enabled ? 'var(--border)' : 'var(--red)44'}`,
                    borderRadius: 8,
                    padding: '14px 18px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 14,
                  }}
                >
                  <span style={{ fontSize: 22, flexShrink: 0 }}>
                    {PLUGIN_ICONS[plugin.name] ?? '🔧'}
                  </span>

                  {/* Info */}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                      <span style={{ fontWeight: 700, fontSize: 14, color: 'var(--text)' }}>
                        {plugin.name}
                      </span>
                      <Badge label={plugin.type ?? 'scanner'} color={typeColor} />
                      {!plugin.enabled && <Badge label="DISABLED" color="var(--red)" />}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>
                      v{plugin.version ?? 'unknown'}&nbsp;&bull;&nbsp;
                      {plugin.install_path ?? 'unknown path'}
                    </div>
                    {parsedManifest.requires && (
                      <RequirementsList reqs={parsedManifest.requires} />
                    )}
                    {plugStatus.message && plugStatus.status === 'error' && (
                      <div style={{ fontSize: 11, color: 'var(--red)', marginTop: 3 }}>
                        Error: {plugStatus.message}
                      </div>
                    )}
                  </div>

                  {/* Status */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: 5, flexShrink: 0 }}>
                    <StatusDot status={plugStatus.status} />
                    <span style={{ fontSize: 11, color: STATUS_COLORS[plugStatus.status] ?? 'var(--muted)', fontWeight: 600 }}>
                      {plugStatus.status.toUpperCase()}
                    </span>
                  </div>

                  {/* Actions */}
                  <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                    <button
                      onClick={() => handleOpenRun(plugin)}
                      disabled={!plugin.enabled || plugStatus.status === 'running'}
                      style={{
                        background: 'var(--blue)22',
                        border: '1px solid var(--blue)44',
                        borderRadius: 5,
                        padding: '5px 12px',
                        color: 'var(--blue)',
                        fontSize: 11,
                        fontWeight: 600,
                        cursor: !plugin.enabled || plugStatus.status === 'running' ? 'not-allowed' : 'pointer',
                        opacity: !plugin.enabled || plugStatus.status === 'running' ? 0.5 : 1,
                      }}
                    >
                      Run
                    </button>
                    <button
                      onClick={() => handleUninstall(plugin.id, plugin.name)}
                      style={{
                        background: 'none',
                        border: '1px solid var(--border)',
                        borderRadius: 5,
                        padding: '5px 12px',
                        color: 'var(--muted)',
                        fontSize: 11,
                        cursor: 'pointer',
                      }}
                    >
                      Uninstall
                    </button>
                  </div>
                </div>
              );
            })
          )}
        </div>
      )}

      {/* Run dialog */}
      {runDialog && (
        <RunDialog
          plugin={runDialog.plugin}
          modules={runDialog.modules}
          projects={projects}
          onClose={() => setRunDialog(null)}
        />
      )}
    </div>
  );
}

// -- Shared micro-styles ------------------------------------------------------

const labelSt: React.CSSProperties = {
  display: 'block',
  fontSize: 10,
  color: 'var(--muted)',
  textTransform: 'uppercase',
  letterSpacing: '0.5px',
  fontWeight: 600,
  marginBottom: 6,
};

const inputSt: React.CSSProperties = {
  background: 'var(--bg)',
  border: '1px solid var(--border)',
  borderRadius: 5,
  padding: '7px 10px',
  color: 'var(--text)',
  fontSize: 13,
  outline: 'none',
};

const primaryBtnSt: React.CSSProperties = {
  background: 'var(--blue)',
  border: 'none',
  borderRadius: 6,
  padding: '8px 20px',
  color: '#fff',
  fontSize: 13,
  fontWeight: 600,
  cursor: 'pointer',
};

const secondaryBtnSt: React.CSSProperties = {
  background: 'none',
  border: '1px solid var(--border)',
  borderRadius: 6,
  padding: '8px 16px',
  color: 'var(--muted)',
  fontSize: 13,
  cursor: 'pointer',
};

// -- AddFromUrl ----------------------------------------------------------------
// Collapsible "Add external plugin from URL" widget shown at the top of
// the Catalog tab. Accepts any git URL and POSTs to
// /api/plugins/install-from-url. Server validates + records; the clone
// happens when the user clicks Enable.

function AddFromUrl({ onInstalled }: { onInstalled: () => void }) {
  const [open, setOpen] = useState(false);
  const [url, setUrl] = useState('');
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const submit = async () => {
    setErr(null);
    setBusy(true);
    try {
      const res = await apiFetch('/api/plugins/install-from-url', {
        method: 'POST',
        body: JSON.stringify({ url: url.trim(), name: name.trim() || undefined, description: description.trim() || undefined }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || `HTTP ${res.status}`);
      }
      setUrl(''); setName(''); setDescription('');
      setOpen(false);
      onInstalled();
    } catch (e: any) {
      setErr(e.message || 'Failed to add plugin');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{
      background: 'var(--surface)',
      border: '1px solid var(--border)',
      borderRadius: 8,
      padding: '12px 14px',
      marginBottom: 12,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer' }}
           onClick={() => setOpen(v => !v)}>
        <div>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg)' }}>
            {open ? '▾' : '▸'} Add external plugin from URL
          </div>
          <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 2 }}>
            Register a git URL as a plugin. Validated + recorded on the server.
          </div>
        </div>
      </div>
      {open && (
        <div style={{ marginTop: 12, display: 'flex', flexDirection: 'column', gap: 8 }}>
          <input
            type="text"
            placeholder="https://github.com/user/plugin-repo (required)"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 4, padding: '7px 10px', color: 'var(--fg)', fontSize: 13 }}
          />
          <input
            type="text"
            placeholder="Display name (optional, defaults to repo name)"
            value={name}
            onChange={(e) => setName(e.target.value)}
            style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 4, padding: '7px 10px', color: 'var(--fg)', fontSize: 13 }}
          />
          <input
            type="text"
            placeholder="Short description (optional)"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 4, padding: '7px 10px', color: 'var(--fg)', fontSize: 13 }}
          />
          {err && <div style={{ color: 'var(--red)', fontSize: 12 }}>{err}</div>}
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={submit} disabled={!url.trim() || busy} style={{ ...primaryBtnSt, opacity: !url.trim() || busy ? 0.5 : 1 }}>
              {busy ? 'Adding…' : 'Add plugin'}
            </button>
            <button onClick={() => { setOpen(false); setErr(null); }} style={secondaryBtnSt}>
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
