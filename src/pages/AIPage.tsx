import { useState, useEffect, useRef, useCallback } from 'react';
import {
  getAIProviders,
  updateAIProvider,
  sendAIChat,
  triggerAITriage,
  getVulnerabilities,
  getAIModels,
  getAIRouting,
  updateAIRouting,
} from '@/lib/api';
import type { AIProvider, ChatMessage, Vulnerability, ModelInfo, RoutingRule } from '@/lib/types';
import { useToast } from '@/components/Toast';

type AITab = 'chat' | 'providers' | 'triage' | 'routing';

const TASK_TYPES: RoutingRule['task'][] = [
  'triage', 'verify', 'suggest-fix', 'deep-analyze', 'report', 'chat', 'batch-filter', 'simple',
];

const TASK_COMPLEXITY: Record<string, { label: string; color: string }> = {
  'verify': { label: 'Hard', color: 'var(--red)' },
  'deep-analyze': { label: 'Hard', color: 'var(--red)' },
  'suggest-fix': { label: 'Medium', color: 'var(--orange)' },
  'report': { label: 'Medium', color: 'var(--orange)' },
  'triage': { label: 'Medium', color: 'var(--orange)' },
  'chat': { label: 'Medium', color: 'var(--orange)' },
  'batch-filter': { label: 'Easy', color: 'var(--green)' },
  'simple': { label: 'Easy', color: 'var(--green)' },
};

const PROVIDER_NAMES = ['claude', 'openai', 'gemini', 'ollama', 'claude_cli'];

export default function AIPage() {
  const [tab, setTab] = useState<AITab>('chat');

  // Providers
  const [providers, setProviders] = useState<AIProvider[]>([]);
  const [providersLoading, setProvidersLoading] = useState(true);
  const [editingProvider, setEditingProvider] = useState<string | null>(null);
  const [providerEdits, setProviderEdits] = useState<Record<string, Partial<AIProvider>>>({});

  // Model registry
  const [modelRegistry, setModelRegistry] = useState<Record<string, { models: ModelInfo[] }>>({});

  // Routing rules
  const [routingRules, setRoutingRules] = useState<RoutingRule[]>([]);
  const [routingLoading, setRoutingLoading] = useState(true);
  const [routingSaving, setRoutingSaving] = useState(false);

  // Chat
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [chatLoading, setChatLoading] = useState(false);

  // Triage
  const [newFindings, setNewFindings] = useState<Vulnerability[]>([]);
  const [triagingAll, setTriagingAll] = useState(false);
  const [triageProgress, setTriageProgress] = useState<Record<number, 'pending' | 'done' | 'error'>>({});

  // Ollama refresh state
  const [ollamaRefreshing, setOllamaRefreshing] = useState(false);
  const [ollamaModels, setOllamaModels] = useState<string[]>([]);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const { toast } = useToast();

  // ── Loaders ────────────────────────────────────────────────────────────

  const loadProviders = useCallback(async () => {
    setProvidersLoading(true);
    try {
      const data = await getAIProviders();
      setProviders(data);
    } catch (err) {
      toast(`Failed to load providers: ${err instanceof Error ? err.message : err}`, 'error');
    } finally {
      setProvidersLoading(false);
    }
  }, [toast]);

  const loadModelRegistry = useCallback(async () => {
    try {
      const data = await getAIModels();
      // Cast to the expected shape — the registry values are static strings
      setModelRegistry(data as Record<string, { models: ModelInfo[] }>);
    } catch {
      // non-critical
    }
  }, []);

  const loadRoutingRules = useCallback(async () => {
    setRoutingLoading(true);
    try {
      const data = await getAIRouting();
      setRoutingRules(data as RoutingRule[]);
    } catch (err) {
      toast(`Failed to load routing rules: ${err instanceof Error ? err.message : err}`, 'error');
    } finally {
      setRoutingLoading(false);
    }
  }, [toast]);

  const loadNewFindings = useCallback(async () => {
    try {
      const result = await getVulnerabilities({ status: 'New' });
      setNewFindings(result.data);
    } catch {
      // non-critical
    }
  }, []);

  useEffect(() => {
    loadProviders();
    loadModelRegistry();
    loadRoutingRules();
    loadNewFindings();
  }, [loadProviders, loadModelRegistry, loadRoutingRules, loadNewFindings]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // ── Ollama model refresh ────────────────────────────────────────────────

  const refreshOllamaModels = async (baseUrl: string) => {
    setOllamaRefreshing(true);
    try {
      const url = (baseUrl || 'http://localhost:11434').replace(/\/$/, '');
      const res = await fetch(`${url}/api/tags`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json() as any;
      const names: string[] = (data.models || []).map((m: any) => m.name as string);
      setOllamaModels(names);
      toast(`Found ${names.length} Ollama model(s)`, 'success');
    } catch (err) {
      toast(`Ollama refresh failed: ${err instanceof Error ? err.message : err}`, 'error');
    } finally {
      setOllamaRefreshing(false);
    }
  };

  // ── Chat ───────────────────────────────────────────────────────────────

  const sendMessage = async () => {
    const text = input.trim();
    if (!text || chatLoading) return;
    const next: ChatMessage[] = [...messages, { role: 'user', content: text }];
    setMessages(next);
    setInput('');
    setChatLoading(true);
    try {
      const res = await sendAIChat(next);
      setMessages(prev => [...prev, { role: 'assistant', content: res.response }]);
    } catch (err) {
      toast(`Chat error: ${err instanceof Error ? err.message : err}`, 'error');
      setMessages(prev => [
        ...prev,
        { role: 'assistant', content: `Error: ${err instanceof Error ? err.message : String(err)}` },
      ]);
    } finally {
      setChatLoading(false);
    }
  };

  // ── Providers ──────────────────────────────────────────────────────────

  const saveProvider = async (id: string) => {
    const edits = providerEdits[id];
    if (!edits) { setEditingProvider(null); return; }
    try {
      const updated = await updateAIProvider(id, edits);
      setProviders(prev => prev.map(p => p.id === id ? updated : p));
      setEditingProvider(null);
      toast('Provider updated', 'success');
    } catch (err) {
      toast(`Save failed: ${err instanceof Error ? err.message : err}`, 'error');
    }
  };

  // ── Triage ─────────────────────────────────────────────────────────────

  const triageAll = async () => {
    if (newFindings.length === 0) { toast('No new findings to triage', 'info'); return; }
    setTriagingAll(true);
    const progress: Record<number, 'pending' | 'done' | 'error'> = {};
    newFindings.forEach(v => { progress[v.id] = 'pending'; });
    setTriageProgress({ ...progress });
    for (const v of newFindings) {
      try {
        await triggerAITriage(v.id);
        setTriageProgress(prev => ({ ...prev, [v.id]: 'done' }));
      } catch {
        setTriageProgress(prev => ({ ...prev, [v.id]: 'error' }));
      }
    }
    setTriagingAll(false);
    toast(`Triage complete for ${newFindings.length} findings`, 'success');
  };

  // ── Routing ────────────────────────────────────────────────────────────

  const saveRouting = async () => {
    setRoutingSaving(true);
    try {
      await updateAIRouting(routingRules);
      toast('Routing rules saved', 'success');
    } catch (err) {
      toast(`Save failed: ${err instanceof Error ? err.message : err}`, 'error');
    } finally {
      setRoutingSaving(false);
    }
  };

  const updateRule = (idx: number, field: keyof RoutingRule, value: string | number) => {
    setRoutingRules(prev => {
      const next = [...prev];
      next[idx] = { ...next[idx], [field]: value };
      // Reset model when provider changes
      if (field === 'provider') next[idx].model = '';
      return next;
    });
  };

  const addRule = () => {
    setRoutingRules(prev => [
      ...prev,
      { task: 'chat', provider: 'ollama', model: 'llama3.2', priority: prev.length + 1 },
    ]);
  };

  const removeRule = (idx: number) => {
    setRoutingRules(prev => prev.filter((_, i) => i !== idx));
  };

  const modelsForProvider = (providerName: string): ModelInfo[] => {
    // If we refreshed live Ollama models, use those
    if (providerName === 'ollama' && ollamaModels.length > 0) {
      return ollamaModels.map(id => ({ id, name: id, tier: 'local' as const, context: 0 }));
    }
    return modelRegistry[providerName]?.models ?? [];
  };

  // ── Styles ─────────────────────────────────────────────────────────────

  const tabStyle = (t: AITab): React.CSSProperties => ({
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
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0, height: 'calc(100vh - 120px)' }}>
      {/* Header */}
      <div style={{ marginBottom: 16 }}>
        <h2 style={{ fontSize: 20, fontWeight: 700, margin: 0, color: 'var(--text)' }}>AI</h2>
        <p style={{ fontSize: 12, color: 'var(--muted)', margin: '4px 0 0' }}>
          AI-assisted vulnerability triage and analysis
        </p>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', marginBottom: 20, flexShrink: 0 }}>
        <button style={tabStyle('chat')} onClick={() => setTab('chat')}>Chat</button>
        <button style={tabStyle('triage')} onClick={() => setTab('triage')}>Triage All</button>
        <button style={tabStyle('providers')} onClick={() => setTab('providers')}>Providers</button>
        <button style={tabStyle('routing')} onClick={() => setTab('routing')}>Routing</button>
      </div>

      {/* ── Chat tab ── */}
      {tab === 'chat' && (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <div style={{ flex: 1, overflow: 'auto', display: 'flex', flexDirection: 'column', gap: 12, paddingBottom: 8 }}>
            {messages.length === 0 && (
              <div style={{ color: 'var(--muted)', fontSize: 13, textAlign: 'center', marginTop: 60 }}>
                Start a conversation. Ask about vulnerabilities, request analysis, or get help writing disclosure reports.
              </div>
            )}
            {messages.map((m, i) => (
              <div key={i} style={{ display: 'flex', justifyContent: m.role === 'user' ? 'flex-end' : 'flex-start' }}>
                <div style={{
                  maxWidth: '75%',
                  background: m.role === 'user' ? 'var(--blue)22' : 'var(--surface)',
                  border: `1px solid ${m.role === 'user' ? 'var(--blue)44' : 'var(--border)'}`,
                  borderRadius: 8,
                  padding: '10px 14px',
                  fontSize: 13,
                  color: 'var(--text)',
                  lineHeight: 1.6,
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                }}>
                  {m.role === 'assistant' && (
                    <div style={{ fontSize: 10, color: 'var(--purple)', fontWeight: 600, marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.4px' }}>
                      AI
                    </div>
                  )}
                  {m.content}
                </div>
              </div>
            ))}
            {chatLoading && (
              <div style={{ display: 'flex', justifyContent: 'flex-start' }}>
                <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: '10px 16px', fontSize: 13, color: 'var(--muted)' }}>
                  Thinking...
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          <div style={{ display: 'flex', gap: 8, marginTop: 12, flexShrink: 0 }}>
            <textarea
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } }}
              placeholder="Ask about vulnerabilities, request analysis... (Enter to send, Shift+Enter for newline)"
              rows={3}
              style={{ flex: 1, background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6, padding: '10px 12px', color: 'var(--text)', fontSize: 13, outline: 'none', resize: 'none', fontFamily: 'inherit', lineHeight: 1.5 }}
            />
            <button
              onClick={sendMessage}
              disabled={chatLoading || !input.trim()}
              style={{ background: chatLoading || !input.trim() ? 'var(--surface-2)' : 'var(--blue)', border: 'none', borderRadius: 6, padding: '0 20px', color: chatLoading || !input.trim() ? 'var(--muted)' : '#fff', fontSize: 13, fontWeight: 600, cursor: chatLoading || !input.trim() ? 'not-allowed' : 'pointer', alignSelf: 'stretch' }}
            >
              Send
            </button>
          </div>

          <div style={{ display: 'flex', gap: 6, marginTop: 8, flexWrap: 'wrap' }}>
            {['What are the most critical findings?', 'Explain the top CVSS score finding', 'Generate a disclosure report template', 'How do I report to HackerOne?'].map(prompt => (
              <button key={prompt} onClick={() => setInput(prompt)} style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 4, padding: '4px 10px', color: 'var(--muted)', fontSize: 11, cursor: 'pointer' }}>
                {prompt}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* ── Triage tab ── */}
      {tab === 'triage' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{ flex: 1, fontSize: 13, color: 'var(--muted)' }}>
              {newFindings.length} new findings awaiting triage
            </div>
            <button
              onClick={triageAll}
              disabled={triagingAll || newFindings.length === 0}
              style={{ background: triagingAll ? 'var(--surface-2)' : 'var(--purple)', border: 'none', borderRadius: 6, padding: '8px 18px', color: triagingAll ? 'var(--muted)' : '#fff', fontSize: 13, fontWeight: 600, cursor: triagingAll || newFindings.length === 0 ? 'not-allowed' : 'pointer' }}
            >
              {triagingAll ? 'Triaging...' : 'Triage All New Findings'}
            </button>
          </div>

          {newFindings.length === 0 ? (
            <div style={{ padding: 40, textAlign: 'center', border: '1px dashed var(--border)', borderRadius: 8, color: 'var(--muted)', fontSize: 13 }}>
              No new findings. All findings have been triaged.
            </div>
          ) : (
            <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    {['Project', 'Title', 'Severity', 'Triage Status'].map(h => (
                      <th key={h} style={{ padding: '9px 14px', textAlign: 'left', color: 'var(--muted)', fontWeight: 500, fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.4px' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {newFindings.map(v => {
                    const st = triageProgress[v.id];
                    return (
                      <tr key={v.id} style={{ borderBottom: '1px solid var(--border)' }}>
                        <td style={{ padding: '9px 14px', color: 'var(--muted)' }}>{v.project}</td>
                        <td style={{ padding: '9px 14px', color: 'var(--text)', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v.title}</td>
                        <td style={{ padding: '9px 14px' }}>
                          <span style={{ fontSize: 11, fontWeight: 600, color: v.severity === 'Critical' ? 'var(--red)' : v.severity === 'High' ? 'var(--orange)' : v.severity === 'Medium' ? 'var(--yellow)' : 'var(--muted)' }}>
                            {v.severity}
                          </span>
                        </td>
                        <td style={{ padding: '9px 14px' }}>
                          {!st && <span style={{ fontSize: 11, color: 'var(--muted)' }}>Queued</span>}
                          {st === 'pending' && <span style={{ fontSize: 11, color: 'var(--orange)' }}>Triaging...</span>}
                          {st === 'done' && <span style={{ fontSize: 11, color: 'var(--green)' }}>Done</span>}
                          {st === 'error' && <span style={{ fontSize: 11, color: 'var(--red)' }}>Failed</span>}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ── Providers tab ── */}
      {tab === 'providers' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, overflow: 'auto' }}>
          {providersLoading ? (
            <div style={{ padding: 32, textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>Loading providers...</div>
          ) : providers.length === 0 ? (
            <div style={{ padding: 32, textAlign: 'center', color: 'var(--muted)', fontSize: 13, border: '1px dashed var(--border)', borderRadius: 8 }}>
              No AI providers configured.
            </div>
          ) : (
            providers.map(p => {
              const isEditing = editingProvider === p.id;
              const edits = providerEdits[p.id] ?? {};
              const providerKey = p.name.toLowerCase();
              const availableModels = modelsForProvider(providerKey);
              const currentModel = isEditing ? (edits.model ?? p.model) : p.model;
              const isOllama = providerKey === 'ollama';
              const isClaudeCLI = providerKey === 'claude_cli';
              const currentBaseUrl = isEditing ? (edits.base_url ?? p.base_url ?? '') : (p.base_url ?? '');

              return (
                <div
                  key={p.id}
                  style={{ background: 'var(--surface)', border: `1px solid ${isEditing ? 'var(--blue)' : 'var(--border)'}`, borderRadius: 8, padding: '16px 20px' }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: isEditing ? 14 : 0 }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontWeight: 600, fontSize: 14, color: 'var(--text)' }}>{p.name}</div>
                      {!isEditing && (
                        <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 2 }}>
                          Model: <code style={{ color: 'var(--blue)' }}>{p.model || '—'}</code>
                          {p.api_key && <span style={{ marginLeft: 12 }}>API Key: <code style={{ color: 'var(--green)' }}>••••••••</code></span>}
                          {p.base_url && <span style={{ marginLeft: 12 }}>URL: <code style={{ color: 'var(--muted)' }}>{p.base_url}</code></span>}
                        </div>
                      )}
                    </div>

                    {/* Enable toggle */}
                    <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', fontSize: 12 }}>
                      <input
                        type="checkbox"
                        checked={isEditing ? (edits.enabled ?? p.enabled) : p.enabled}
                        onChange={async e => {
                          if (!isEditing) {
                            try {
                              const updated = await updateAIProvider(p.id, { enabled: e.target.checked });
                              setProviders(prev => prev.map(x => x.id === p.id ? updated : x));
                              toast(`${p.name} ${e.target.checked ? 'enabled' : 'disabled'}`, 'success');
                            } catch (err) {
                              toast(`Update failed: ${err instanceof Error ? err.message : err}`, 'error');
                            }
                          } else {
                            setProviderEdits(prev => ({ ...prev, [p.id]: { ...prev[p.id], enabled: e.target.checked } }));
                          }
                        }}
                        style={{ accentColor: 'var(--blue)' }}
                      />
                      <span style={{ color: (isEditing ? (edits.enabled ?? p.enabled) : p.enabled) ? 'var(--green)' : 'var(--muted)' }}>
                        {(isEditing ? (edits.enabled ?? p.enabled) : p.enabled) ? 'Enabled' : 'Disabled'}
                      </span>
                    </label>

                    {isEditing ? (
                      <div style={{ display: 'flex', gap: 6 }}>
                        <button onClick={() => saveProvider(p.id)} style={smallBtn('var(--green)')}>Save</button>
                        <button onClick={() => { setEditingProvider(null); setProviderEdits(prev => { const n = { ...prev }; delete n[p.id]; return n; }); }} style={smallBtn('var(--surface-2)')}>Cancel</button>
                      </div>
                    ) : (
                      <button
                        onClick={() => {
                          setEditingProvider(p.id);
                          setProviderEdits(prev => ({ ...prev, [p.id]: { model: p.model, api_key: p.api_key ?? '', enabled: p.enabled, base_url: p.base_url ?? '' } }));
                          setOllamaModels([]); // reset so registry models show
                        }}
                        style={smallBtn('var(--surface-2)')}
                      >
                        Edit
                      </button>
                    )}
                  </div>

                  {isEditing && (
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                      {/* Model — dropdown (or text fallback) */}
                      <div>
                        <label style={fieldLabel}>Model</label>
                        {availableModels.length > 0 ? (
                          <select
                            value={currentModel ?? ''}
                            onChange={e => setProviderEdits(prev => ({ ...prev, [p.id]: { ...prev[p.id], model: e.target.value } }))}
                            style={selectStyle}
                          >
                            <option value="">— select model —</option>
                            {availableModels.map(m => (
                              <option key={m.id} value={m.id}>{m.name} ({m.tier})</option>
                            ))}
                          </select>
                        ) : (
                          <input
                            value={currentModel ?? ''}
                            onChange={e => setProviderEdits(prev => ({ ...prev, [p.id]: { ...prev[p.id], model: e.target.value } }))}
                            style={inputStyle}
                            placeholder="e.g. llama3.2"
                          />
                        )}
                      </div>

                      {/* API key — hidden for Ollama and Claude CLI */}
                      {!isOllama && !isClaudeCLI && (
                        <div>
                          <label style={fieldLabel}>API Key</label>
                          <input
                            type="password"
                            value={edits.api_key ?? ''}
                            onChange={e => setProviderEdits(prev => ({ ...prev, [p.id]: { ...prev[p.id], api_key: e.target.value } }))}
                            style={inputStyle}
                            placeholder="sk-..."
                          />
                        </div>
                      )}

                      {/* Claude CLI notice */}
                      {isClaudeCLI && (
                        <div style={{ display: 'flex', alignItems: 'center' }}>
                          <div style={{ fontSize: 12, color: 'var(--muted)', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 5, padding: '7px 10px', width: '100%' }}>
                            Uses the <code>claude</code> CLI binary on PATH. No API key needed.
                          </div>
                        </div>
                      )}

                      {/* Base URL — for Ollama and custom endpoints */}
                      {(isOllama || p.base_url !== undefined) && (
                        <div style={{ gridColumn: isOllama ? '1 / -1' : undefined }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 5 }}>
                            <label style={{ ...fieldLabel, marginBottom: 0 }}>
                              {isOllama ? 'Ollama Base URL' : 'Base URL (optional)'}
                            </label>
                            {isOllama && (
                              <button
                                onClick={() => refreshOllamaModels(currentBaseUrl as string)}
                                disabled={ollamaRefreshing}
                                style={{ ...smallBtn('var(--surface-2)'), marginLeft: 'auto' }}
                              >
                                {ollamaRefreshing ? 'Refreshing...' : 'Refresh Models'}
                              </button>
                            )}
                          </div>
                          <input
                            value={currentBaseUrl}
                            onChange={e => setProviderEdits(prev => ({ ...prev, [p.id]: { ...prev[p.id], base_url: e.target.value } }))}
                            style={inputStyle}
                            placeholder={isOllama ? 'http://localhost:11434' : 'http://localhost:11434/v1'}
                          />
                          {isOllama && ollamaModels.length > 0 && (
                            <div style={{ marginTop: 6, fontSize: 11, color: 'var(--muted)' }}>
                              Live models: {ollamaModels.join(', ')}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      )}

      {/* ── Routing tab ── */}
      {tab === 'routing' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16, overflow: 'auto' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 13, color: 'var(--text)', fontWeight: 600 }}>Task Routing Rules</div>
              <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 2 }}>
                Assign AI models to each task type. Hard tasks need strong models, easy tasks can use cheap/local ones.
              </div>
            </div>
            <button onClick={addRule} style={smallBtn('var(--blue)')}>+ Add Rule</button>
            <button
              onClick={saveRouting}
              disabled={routingSaving}
              style={{ ...smallBtn(routingSaving ? 'var(--surface-2)' : 'var(--green)'), padding: '4px 14px' }}
            >
              {routingSaving ? 'Saving...' : 'Save All'}
            </button>
          </div>

          {/* Preset buttons */}
          <div style={{
            background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: '12px 16px',
          }}>
            <div style={{ fontSize: 11, color: 'var(--muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 8 }}>
              Quick Presets
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {[
                { name: 'smart-split', label: 'Smart Split', desc: 'Strong + cheap mix', color: 'var(--blue)' },
                { name: 'all-claude', label: 'All Claude', desc: 'Best quality', color: 'var(--purple)' },
                { name: 'all-openai', label: 'All OpenAI', desc: 'GPT-4o + Mini', color: 'var(--green)' },
                { name: 'all-gemini', label: 'All Gemini', desc: '1M context', color: 'var(--orange)' },
                { name: 'all-local', label: 'All Local', desc: 'Free (Ollama)', color: 'var(--yellow)' },
                { name: 'budget', label: 'Budget', desc: 'Local + Sonnet fallback', color: 'var(--muted)' },
                { name: 'claude-cli', label: 'Claude CLI', desc: 'No API key needed', color: 'var(--text)' },
              ].map(p => (
                <button
                  key={p.name}
                  onClick={async () => {
                    try {
                      const res = await fetch(`/api/ai/routing/presets/${p.name}`, { method: 'POST' });
                      if (!res.ok) throw new Error(await res.text());
                      const data = await res.json();
                      // Reload routing rules
                      const { getAIRouting } = await import('@/lib/api');
                      const updated = await getAIRouting();
                      setRoutingRules(updated);
                      toast(`Applied "${p.label}" preset (${data.count} rules)`, 'success');
                    } catch (err: any) {
                      toast(`Failed: ${err.message}`, 'error');
                    }
                  }}
                  style={{
                    padding: '6px 14px', borderRadius: 6, cursor: 'pointer', fontSize: 12,
                    background: `${p.color}15`, border: `1px solid ${p.color}44`, color: p.color,
                    fontWeight: 600, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 1,
                  }}
                >
                  <span>{p.label}</span>
                  <span style={{ fontSize: 9, fontWeight: 400, opacity: 0.7 }}>{p.desc}</span>
                </button>
              ))}
            </div>
          </div>

          {routingLoading ? (
            <div style={{ padding: 32, textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>Loading routing rules...</div>
          ) : (
            <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)' }}>
                    {['Priority', 'Task', 'Provider', 'Model', ''].map(h => (
                      <th key={h} style={{ padding: '9px 14px', textAlign: 'left', color: 'var(--muted)', fontWeight: 500, fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.4px' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {routingRules.map((rule, idx) => {
                    const ruleModels = modelsForProvider(rule.provider);
                    return (
                      <tr key={idx} style={{ borderBottom: '1px solid var(--border)' }}>
                        <td style={{ padding: '8px 14px', width: 70 }}>
                          <input
                            type="number"
                            value={rule.priority}
                            min={1}
                            onChange={e => updateRule(idx, 'priority', Number(e.target.value))}
                            style={{ ...inputStyle, width: 50, padding: '4px 6px' }}
                          />
                        </td>
                        <td style={{ padding: '8px 14px' }}>
                          <select
                            value={rule.task}
                            onChange={e => updateRule(idx, 'task', e.target.value)}
                            style={selectStyle}
                          >
                            {TASK_TYPES.map(t => <option key={t} value={t}>{t} ({TASK_COMPLEXITY[t]?.label || '?'})</option>)}
                          </select>
                        </td>
                        <td style={{ padding: '8px 14px' }}>
                          <select
                            value={rule.provider}
                            onChange={e => updateRule(idx, 'provider', e.target.value)}
                            style={selectStyle}
                          >
                            {PROVIDER_NAMES.map(pn => <option key={pn} value={pn}>{pn}</option>)}
                          </select>
                        </td>
                        <td style={{ padding: '8px 14px' }}>
                          {ruleModels.length > 0 ? (
                            <select
                              value={rule.model}
                              onChange={e => updateRule(idx, 'model', e.target.value)}
                              style={selectStyle}
                            >
                              <option value="">— select —</option>
                              {ruleModels.map(m => <option key={m.id} value={m.id}>{m.name}</option>)}
                            </select>
                          ) : (
                            <input
                              value={rule.model}
                              onChange={e => updateRule(idx, 'model', e.target.value)}
                              style={{ ...inputStyle, padding: '4px 8px' }}
                              placeholder="model id"
                            />
                          )}
                        </td>
                        <td style={{ padding: '8px 14px' }}>
                          <button onClick={() => removeRule(idx)} style={{ ...smallBtn('transparent'), color: 'var(--red)', border: 'none' }}>
                            Remove
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                  {routingRules.length === 0 && (
                    <tr>
                      <td colSpan={5} style={{ padding: '24px 14px', textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>
                        No routing rules. Click "+ Add Rule" to add one.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function smallBtn(bg: string): React.CSSProperties {
  return {
    background: bg,
    border: '1px solid var(--border)',
    borderRadius: 4,
    padding: '4px 10px',
    color: 'var(--text)',
    fontSize: 11,
    cursor: 'pointer',
  };
}

const fieldLabel: React.CSSProperties = {
  fontSize: 11,
  color: 'var(--muted)',
  textTransform: 'uppercase',
  letterSpacing: '0.5px',
  fontWeight: 600,
  marginBottom: 5,
  display: 'block',
};

const inputStyle: React.CSSProperties = {
  width: '100%',
  background: 'var(--bg)',
  border: '1px solid var(--border)',
  borderRadius: 5,
  padding: '7px 10px',
  color: 'var(--text)',
  fontSize: 13,
  outline: 'none',
  fontFamily: 'inherit',
  boxSizing: 'border-box',
};

const selectStyle: React.CSSProperties = {
  width: '100%',
  background: 'var(--bg)',
  border: '1px solid var(--border)',
  borderRadius: 5,
  padding: '7px 10px',
  color: 'var(--text)',
  fontSize: 13,
  outline: 'none',
  fontFamily: 'inherit',
  cursor: 'pointer',
  boxSizing: 'border-box',
};
