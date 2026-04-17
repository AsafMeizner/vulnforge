import { useState, useEffect, useCallback } from 'react';
import { getTools, getTool, getPlugins, getPluginModules, getVulnerabilities } from '@/lib/api';
import type { Tool, Vulnerability } from '@/lib/types';
import { useToast } from '@/components/Toast';

interface ToolsProps {
  onNavigateToScanner?: (toolId: string) => void;
}

export default function Tools({ onNavigateToScanner }: ToolsProps) {
  const [tools, setTools] = useState<Tool[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState<string>('all');
  const [selected, setSelected] = useState<Tool | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [toolVulns, setToolVulns] = useState<Vulnerability[]>([]);
  const { toast } = useToast();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [builtinTools, pluginData] = await Promise.all([getTools(), getPlugins()]);

      // Expand each installed plugin into its individual modules/templates/probes
      const installedPlugins = (pluginData.installed || []).filter((p: any) => p.enabled);
      const pluginTools: Tool[] = [];

      for (const p of installedPlugins) {
        let manifest: any = {};
        try { manifest = JSON.parse(p.manifest || '{}'); } catch {}
        const pluginDesc = manifest.description || p.type || 'Plugin scanner';
        const sourceUrl = manifest.source_url || p.source_url || '';

        // Try to get modules for this plugin
        let modules: string[] = [];
        try {
          const modData = await getPluginModules(p.id);
          modules = modData.modules || [];
        } catch { /* plugin may not have modules endpoint */ }

        if (modules.length > 0) {
          // Add parent plugin entry
          pluginTools.push({
            id: 10000 + p.id,
            name: p.name,
            category: 'Plugin',
            description: pluginDesc + ' (' + modules.length + ' modules)',
            docs: 'Source: ' + sourceUrl + '\nType: ' + (p.type || 'scanner') + '\nModules: ' + modules.join(', '),
            track_record: modules.length + ' modules',
            file_path: p.install_path || '',
            config_schema: '{}',
            enabled: 1,
          });
          // Add each module as a sub-tool
          for (let i = 0; i < modules.length; i++) {
            pluginTools.push({
              id: 20000 + p.id * 100 + i,
              name: modules[i],
              category: 'Plugin: ' + p.name,
              description: p.name + ' \u2014 ' + modules[i].replace(/_/g, ' '),
              docs: 'Part of ' + p.name + '\nSource: ' + sourceUrl,
              track_record: '',
              file_path: '',
              config_schema: '{}',
              enabled: 1,
            });
          }
        } else {
          // No modules - show as single tool
          pluginTools.push({
            id: 10000 + p.id,
            name: p.name,
            category: 'Plugin',
            description: pluginDesc,
            docs: 'Source: ' + sourceUrl + '\nType: ' + (p.type || 'scanner'),
            track_record: 'Plugin',
            file_path: p.install_path || '',
            config_schema: '{}',
            enabled: 1,
          });
        }
      }

      setTools([...builtinTools, ...pluginTools]);
    } catch (err) {
      toast(`Failed to load tools: ${err instanceof Error ? err.message : err}`, 'error');
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => { load(); }, [load]);

  const openTool = async (tool: Tool) => {
    setSelected(tool);
    setToolVulns([]);
    if (!tool.docs) {
      setDetailLoading(true);
      try {
        const full = await getTool(String(tool.id));
        setSelected(full);
      } catch {
        // use cached version
      } finally {
        setDetailLoading(false);
      }
    }
    // Fetch vulns found by this tool
    try {
      const result = await getVulnerabilities({ search: tool.name, limit: 20 });
      const vulns = Array.isArray(result) ? result : (result as any).data || [];
      setToolVulns(vulns.filter((v: Vulnerability) =>
        (v.method || '').toLowerCase().includes(tool.name.toLowerCase()) ||
        (v.tool_name || '').toLowerCase().includes(tool.name.toLowerCase())
      ));
    } catch { /* non-critical */ }
  };

  const categories = [...new Set(tools.map(t => t.category))].sort();

  const filtered = tools.filter(t => {
    const matchSearch = !search
      || t.name.toLowerCase().includes(search.toLowerCase())
      || t.description.toLowerCase().includes(search.toLowerCase());
    const matchCat = !categoryFilter || t.category === categoryFilter;
    const isPlugin = t.category === 'Plugin' || t.category.startsWith('Plugin: ');
    const matchSource = sourceFilter === 'all'
      || (sourceFilter === 'builtin' && !isPlugin)
      || (sourceFilter === 'all-plugins' && isPlugin)
      || (isPlugin && t.category === 'Plugin: ' + sourceFilter)
      || (isPlugin && t.category === 'Plugin' && t.name === sourceFilter);
    return matchSearch && matchCat && matchSource;
  });

  const catColor: Record<string, string> = {
    memory: 'var(--red)',
    integer: 'var(--orange)',
    crypto: 'var(--yellow)',
    concurrency: 'var(--blue)',
    parser: 'var(--purple)',
    'supply-chain': 'var(--green)',
    recon: 'var(--muted)',
    plugin: '#9b8dff',
  };

  const getColor = (cat: string) => {
    const key = Object.keys(catColor).find(k => cat.toLowerCase().includes(k));
    return key ? catColor[key] : 'var(--muted)';
  };

  // Simulate "last used" and "findings count" from tool name hash (no real data yet)
  const getLastUsed = (name: string): string | null => {
    // In a real implementation this would come from the DB scan history
    return null;
  };

  return (
    <div style={{ display: 'flex', gap: 20, height: 'calc(100vh - 120px)' }}>
      {/* Left: tool list */}
      <div style={{ flex: selected ? '0 0 420px' : '1', display: 'flex', flexDirection: 'column', gap: 14, minWidth: 0 }}>
        {/* Header + filters */}
        <div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
            <div>
              <h2 style={{ fontSize: 20, fontWeight: 700, margin: 0, color: 'var(--text)' }}>Tools</h2>
              <p style={{ fontSize: 12, color: 'var(--muted)', margin: '4px 0 0' }}>
                {loading ? 'Loading...' : `${filtered.length} of ${tools.length} tools`}
              </p>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              type="text"
              placeholder="Search tools..."
              value={search}
              onChange={e => setSearch(e.target.value)}
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
              value={categoryFilter}
              onChange={e => setCategoryFilter(e.target.value)}
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
              <option value="">All Categories</option>
              {categories.map(c => <option key={c} value={c}>{c}</option>)}
            </select>
            <select
              value={sourceFilter}
              onChange={e => setSourceFilter(e.target.value)}
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
              <option value="all">All Sources ({tools.length})</option>
              <option value="builtin">Built-in ({tools.filter(t => !t.category.startsWith('Plugin')).length})</option>
              <option value="all-plugins">All Plugins ({tools.filter(t => t.category.startsWith('Plugin')).length})</option>
              {[...new Set(tools
                .filter(t => t.category === 'Plugin')
                .map(t => t.name)
              )].sort().map(name => {
                const count = tools.filter(t => t.category === 'Plugin: ' + name).length;
                return <option key={name} value={name}>{name} ({count > 0 ? count + ' modules' : 'plugin'})</option>;
              })}
            </select>
          </div>
        </div>

        {/* Grid */}
        <div style={{ flex: 1, overflow: 'auto' }}>
          {loading ? (
            <div style={{ padding: 40, textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>Loading...</div>
          ) : filtered.length === 0 ? (
            <div style={{ padding: 40, textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>
              No tools match your search.
            </div>
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: selected ? '1fr' : 'repeat(auto-fill, minmax(280px, 1fr))', gap: 10 }}>
              {filtered.map(t => (
                <div
                  key={t.id}
                  onClick={() => openTool(t)}
                  style={{
                    background: 'var(--surface)',
                    border: `1px solid ${selected?.id === t.id ? 'var(--purple)' : 'var(--border)'}`,
                    borderRadius: 8,
                    padding: '12px 14px',
                    cursor: 'pointer',
                    transition: 'border-color 0.15s',
                  }}
                  onMouseEnter={e => { if (selected?.id !== t.id) (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--muted)'; }}
                  onMouseLeave={e => { if (selected?.id !== t.id) (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--border)'; }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                    <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--purple)' }}>{t.name}</span>
                    <span style={{
                      fontSize: 10,
                      color: getColor(t.category),
                      background: `${getColor(t.category)}22`,
                      padding: '1px 6px',
                      borderRadius: 3,
                      marginLeft: 'auto',
                      border: `1px solid ${getColor(t.category)}44`,
                    }}>
                      {t.category}
                    </span>
                    {!t.enabled && (
                      <span style={{ fontSize: 10, color: 'var(--muted)', background: 'var(--surface-2)', padding: '1px 6px', borderRadius: 3, border: '1px solid var(--border)' }}>
                        disabled
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.5, marginBottom: t.track_record ? 8 : 0 }}>
                    {t.description}
                  </div>
                  {t.track_record && (
                    <div style={{ fontSize: 11, color: 'var(--green)', marginTop: 6, fontStyle: 'italic' }}>
                      {t.track_record}
                    </div>
                  )}
                  {/* Run button */}
                  {onNavigateToScanner && (
                    <div style={{ marginTop: 10 }}>
                      <button
                        onClick={e => { e.stopPropagation(); onNavigateToScanner(String(t.id)); }}
                        style={{
                          background: 'var(--blue)22',
                          border: '1px solid var(--blue)44',
                          borderRadius: 4,
                          padding: '3px 10px',
                          color: 'var(--blue)',
                          fontSize: 11,
                          cursor: 'pointer',
                          fontWeight: 500,
                        }}
                      >
                        Run in Scanner
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Right: tool detail */}
      {selected && (
        <div style={{
          flex: 1,
          background: 'var(--surface)',
          border: '1px solid var(--border)',
          borderRadius: 8,
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          minWidth: 0,
        }}>
          <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 700, fontSize: 15, color: 'var(--purple)' }}>{selected.name}</div>
              <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 2 }}>{selected.category}</div>
            </div>
            {/* Run button in detail panel */}
            {onNavigateToScanner && (
              <button
                onClick={() => onNavigateToScanner(String(selected.id))}
                style={{
                  background: 'var(--blue)',
                  border: 'none',
                  borderRadius: 5,
                  padding: '6px 14px',
                  color: '#fff',
                  fontSize: 12,
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                Run
              </button>
            )}
            <button
              onClick={() => setSelected(null)}
              style={{ background: 'none', border: 'none', color: 'var(--muted)', cursor: 'pointer', fontSize: 16, padding: '2px 6px' }}
            >
              x
            </button>
          </div>

          <div style={{ flex: 1, overflow: 'auto', padding: 20 }}>
            {detailLoading ? (
              <div style={{ color: 'var(--muted)', fontSize: 13 }}>Loading documentation...</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
                <div>
                  <div style={fieldLabel}>Description</div>
                  <p style={{ margin: 0, fontSize: 13, color: 'var(--text)', lineHeight: 1.6 }}>{selected.description}</p>
                </div>

                {selected.track_record && (
                  <div>
                    <div style={fieldLabel}>Track Record</div>
                    <p style={{ margin: 0, fontSize: 13, color: 'var(--green)', lineHeight: 1.6, fontStyle: 'italic' }}>{selected.track_record}</p>
                  </div>
                )}

                {/* Status row */}
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <span style={{
                    fontSize: 12,
                    color: selected.enabled ? 'var(--green)' : 'var(--muted)',
                    background: selected.enabled ? 'var(--green)22' : 'var(--surface-2)',
                    border: `1px solid ${selected.enabled ? 'var(--green)44' : 'var(--border)'}`,
                    padding: '4px 10px',
                    borderRadius: 4,
                  }}>
                    {selected.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                  <span style={{
                    fontSize: 12,
                    color: getColor(selected.category),
                    background: `${getColor(selected.category)}22`,
                    border: `1px solid ${getColor(selected.category)}44`,
                    padding: '4px 10px',
                    borderRadius: 4,
                  }}>
                    {selected.category}
                  </span>
                </div>

                {/* Findings by this tool */}
                {toolVulns.length > 0 && (
                  <div>
                    <div style={fieldLabel}>Vulnerabilities Found ({toolVulns.length})</div>
                    {/* Severity mini-bars */}
                    <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
                      {(['Critical', 'High', 'Medium', 'Low'] as const).map(sev => {
                        const count = toolVulns.filter(v => v.severity === sev).length;
                        if (count === 0) return null;
                        const colors: Record<string, string> = { Critical: 'var(--red)', High: 'var(--orange)', Medium: 'var(--yellow)', Low: 'var(--muted)' };
                        return (
                          <span key={sev} style={{
                            fontSize: 11, fontWeight: 600,
                            color: colors[sev],
                            background: colors[sev] + '18',
                            border: '1px solid ' + colors[sev] + '44',
                            padding: '3px 8px', borderRadius: 4,
                          }}>
                            {count} {sev}
                          </span>
                        );
                      })}
                    </div>
                    {/* Short list */}
                    <div style={{ maxHeight: 200, overflow: 'auto', border: '1px solid var(--border)', borderRadius: 6 }}>
                      {toolVulns.slice(0, 10).map(v => {
                        const sevColors: Record<string, string> = { Critical: 'var(--red)', High: 'var(--orange)', Medium: 'var(--yellow)', Low: 'var(--muted)' };
                        return (
                          <div key={v.id} style={{
                            display: 'flex', alignItems: 'center', gap: 8,
                            padding: '6px 10px', borderBottom: '1px solid var(--border)',
                            fontSize: 12,
                          }}>
                            <span style={{
                              width: 6, height: 6, borderRadius: '50%',
                              background: sevColors[v.severity] || 'var(--muted)',
                              flexShrink: 0,
                            }} />
                            <span style={{ flex: 1, color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {v.title}
                            </span>
                            <span style={{ color: 'var(--muted)', fontSize: 10, flexShrink: 0 }}>
                              {v.project}
                            </span>
                          </div>
                        );
                      })}
                      {toolVulns.length > 10 && (
                        <div style={{ padding: '6px 10px', fontSize: 11, color: 'var(--muted)', textAlign: 'center' }}>
                          +{toolVulns.length - 10} more
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {toolVulns.length === 0 && !detailLoading && (
                  <div style={{ fontSize: 12, color: 'var(--muted)', fontStyle: 'italic' }}>
                    No vulnerabilities found by this tool yet.
                  </div>
                )}

                {selected.docs && (
                  <div>
                    <div style={fieldLabel}>Documentation</div>
                    <pre style={{
                      background: 'var(--bg)',
                      border: '1px solid var(--border)',
                      borderRadius: 6,
                      padding: 14,
                      fontSize: 12,
                      overflow: 'auto',
                      color: 'var(--text)',
                      lineHeight: 1.6,
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-word',
                      margin: 0,
                      fontFamily: 'monospace',
                    }}>
                      {selected.docs}
                    </pre>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

const fieldLabel: React.CSSProperties = {
  fontSize: 11,
  color: 'var(--muted)',
  textTransform: 'uppercase',
  letterSpacing: '0.5px',
  fontWeight: 600,
  marginBottom: 6,
};
