import { useState, useEffect, useCallback, useRef } from 'react';
import {
  getVulnerability,
  updateVulnerability,
  deleteVulnerability,
  triggerAITriage,
  generateReport,
  sendAIChat,
  suggestFix,
  deepAnalyze,
  listExploits,
  createExploit,
  getProofLadder,
  setProofTier,
  listRuntimeJobs,
  listCrashes,
  listDisclosures,
  createDisclosure,
  type Exploit,
  type ProofLadder,
  type RuntimeJob,
  type FuzzCrash,
  type Disclosure,
  apiFetch,
} from '@/lib/api';
import type { Vulnerability, Severity, VulnStatus } from '@/lib/types';
import { SeverityBadge, StatusBadge, CvssScore } from '@/components/Badge';
import { useToast } from '@/components/Toast';
import { NotesPanel } from '@/components/NotesPanel';
import { Markdown } from '@/components/Markdown';
import { highlightReact } from '@/lib/hljs';
import { FileViewerModal } from '@/components/FileViewerModal';

// ── Types ─────────────────────────────────────────────────────────────────────

type Tab = 'overview' | 'fix' | 'report' | 'ai' | 'exploits' | 'runtime' | 'disclosure' | 'history' | 'notes';
type ReportSubTab = 'email' | 'advisory' | 'summary';

const SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Info'];
const STATUSES: VulnStatus[] = ['New', 'Triaged', 'Submitted', 'Fixed', 'Rejected', 'Wont Fix'];

interface FindingDetailProps {
  vulnId: number;
  onClose: () => void;
}

// ── Utility sub-components ────────────────────────────────────────────────────

function CopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const { toast } = useToast();

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      toast('Copied to clipboard', 'success');
      setTimeout(() => setCopied(false), 1500);
    } catch {
      toast('Clipboard not available', 'error');
    }
  };

  return (
    <button onClick={copy} style={copyBtnStyle(copied)}>
      {copied ? 'Copied!' : (label ?? 'Copy')}
    </button>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      <div style={fieldLabelStyle}>{label}</div>
      {children}
    </div>
  );
}

function renderRichLine(line: string, idx: number): React.ReactNode {
  const isAdd = line.startsWith('+') && !line.startsWith('+++');
  const isDel = line.startsWith('-') && !line.startsWith('---');
  const isHunk = line.startsWith('@@');
  const lineStyle: React.CSSProperties = {};
  if (isAdd) { lineStyle.color = 'var(--green)'; lineStyle.background = 'rgba(63,185,80,0.08)'; }
  if (isDel) { lineStyle.color = 'var(--red)'; lineStyle.background = 'rgba(248,81,73,0.08)'; }
  if (isHunk) { lineStyle.color = 'var(--blue)'; lineStyle.background = 'rgba(88,166,255,0.06)'; }
  const parts: React.ReactNode[] = [];
  let rest = line;
  let k = 0;
  while (rest.length > 0) {
    const bm = rest.match(/^(.*?)\*\*(.+?)\*\*([\s\S]*)$/);
    if (bm) {
      if (bm[1]) parts.push(<span key={k++}>{bm[1]}</span>);
      parts.push(<strong key={k++} style={{ color: 'var(--text)', fontWeight: 600 }}>{bm[2]}</strong>);
      rest = bm[3]; continue;
    }
    const cm = rest.match(/^(.*?)`(.+?)`([\s\S]*)$/);
    if (cm) {
      if (cm[1]) parts.push(<span key={k++}>{cm[1]}</span>);
      parts.push(<code key={k++} style={{ background: 'rgba(110,118,129,0.2)', padding: '1px 5px', borderRadius: 3, fontSize: '0.9em', fontFamily: 'monospace', color: 'var(--blue)' }}>{cm[2]}</code>);
      rest = cm[3]; continue;
    }
    parts.push(<span key={k++}>{rest}</span>);
    break;
  }
  return <div key={idx} style={{ padding: '1px 0', borderRadius: 2, ...lineStyle }}>{parts.length > 0 ? parts : (line || '\u00A0')}</div>;
}

function RichText({ text }: { text: string }) {
  if (!text) return null;
  const blocks: React.ReactNode[] = [];
  const cbr = /```[\w]*\n([\s\S]*?)```/g;
  let last = 0, m, bk = 0;
  while ((m = cbr.exec(text)) !== null) {
    if (m.index > last) {
      blocks.push(<div key={bk++}>{text.substring(last, m.index).split('\n').map((l, i) => renderRichLine(l, i))}</div>);
    }
    blocks.push(<pre key={bk++} style={{ background: '#0d1117', border: '1px solid var(--border)', borderRadius: 4, padding: '8px 12px', margin: '6px 0', overflow: 'auto', fontSize: 12, fontFamily: 'monospace', color: 'var(--text)', whiteSpace: 'pre' }}>{m[1]}</pre>);
    last = m.index + m[0].length;
  }
  if (last < text.length) {
    blocks.push(<div key={bk++}>{text.substring(last).split('\n').map((l, i) => renderRichLine(l, i))}</div>);
  }
  return <>{blocks}</>;
}

function InfoBox({ children, color = 'var(--yellow)' }: { children: React.ReactNode; color?: string }) {
  const content = typeof children === 'string' ? <RichText text={children} /> : children;
  return (
    <div style={{
      background: `${color}11`,
      border: `1px solid ${color}44`,
      borderLeft: `3px solid ${color}`,
      borderRadius: 6,
      padding: '10px 14px',
      fontSize: 13,
      color: 'var(--text)',
      lineHeight: 1.6,
      wordBreak: 'break-word',
    }}>
      {content}
    </div>
  );
}

function EmptyState({ children, action }: { children: React.ReactNode; action?: React.ReactNode }) {
  return (
    <div style={{
      padding: '40px 32px',
      textAlign: 'center',
      color: 'var(--muted)',
      fontSize: 13,
      border: '1px dashed var(--border)',
      borderRadius: 8,
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      gap: 12,
    }}>
      <div>{children}</div>
      {action}
    </div>
  );
}

/**
 * A self-contained "manual triage" editor. Always shown, never
 * depends on an AI provider. Starts collapsed into a compact "Write
 * your analysis" button; expands into a textarea with Save/Cancel.
 *
 * The textarea accepts markdown (rendered elsewhere on read) so users
 * can paste/write headings and code blocks just like AI output.
 */
function ManualTriageField({
  value, onSave, openSignal,
}: {
  value: string;
  onSave: (next: string) => Promise<void>;
  /**
   * When this number increases, the field enters edit mode and scrolls
   * into view. Used by the "Write Manually" button in the empty state
   * — parent bumps the signal to imperatively trigger editing.
   */
  openSignal?: number;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(value);
  const [saving, setSaving] = useState(false);
  const rootRef = useRef<HTMLDivElement | null>(null);
  // Sync when the parent vuln reloads (e.g. after save).
  useEffect(() => { setDraft(value); }, [value]);
  // Parent-triggered open. Ignores the initial render (openSignal=0).
  useEffect(() => {
    if (openSignal && openSignal > 0) {
      setEditing(true);
      // Give the textarea a beat to mount, then scroll so the user
      // sees what they just opened.
      setTimeout(() => {
        rootRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }, 50);
    }
  }, [openSignal]);

  // When there's nothing to show AND we're not editing, render nothing
  // at all. The empty state in the parent owns the CTA.
  if (!editing && !value) return null;

  return (
    <div ref={rootRef} style={{ marginTop: 16, display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <div style={{ fontSize: 11, color: 'var(--muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5 }}>
          Manual Triage
        </div>
        {!editing && (
          <button
            onClick={() => setEditing(true)}
            style={{
              marginLeft: 'auto',
              padding: '3px 10px', fontSize: 11, fontWeight: 600,
              border: '1px solid var(--border)', borderRadius: 5,
              background: 'var(--surface-2)', color: 'var(--text)', cursor: 'pointer',
            }}
          >
            Edit
          </button>
        )}
      </div>
      {editing ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <textarea
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="Your analysis. Supports markdown: # headings, `code`, ```fenced blocks```, bullet lists."
            style={{
              width: '100%', minHeight: 140, resize: 'vertical',
              background: 'var(--bg)', color: 'var(--text)',
              border: '1px solid var(--border)', borderRadius: 6,
              padding: '10px 12px', fontSize: 13, lineHeight: 1.5,
              fontFamily: 'ui-monospace, SF Mono, Menlo, Consolas, monospace',
            }}
          />
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <button
              onClick={() => { setDraft(value); setEditing(false); }}
              disabled={saving}
              style={{
                padding: '5px 12px', fontSize: 12,
                border: '1px solid var(--border)', borderRadius: 5,
                background: 'transparent', color: 'var(--muted)', cursor: 'pointer',
              }}
            >Cancel</button>
            <button
              onClick={async () => {
                setSaving(true);
                try {
                  await onSave(draft.trim());
                  setEditing(false);
                } finally { setSaving(false); }
              }}
              disabled={saving}
              style={{
                padding: '5px 14px', fontSize: 12, fontWeight: 600,
                border: '1px solid var(--green)', borderRadius: 5,
                background: 'var(--green)', color: '#fff', cursor: saving ? 'wait' : 'pointer',
                opacity: saving ? 0.7 : 1,
              }}
            >{saving ? 'Saving...' : 'Save'}</button>
          </div>
        </div>
      ) : value ? (
        // Render as markdown so users can write structured notes.
        <InfoBox color="var(--blue)">{value}</InfoBox>
      ) : null}
    </div>
  );
}

function Skeleton({ height = 16, width = '100%' }: { height?: number; width?: string }) {
  return (
    <div style={{
      height,
      width,
      background: 'var(--surface-2)',
      borderRadius: 4,
      animation: 'shimmer 1.5s infinite',
    }} />
  );
}

function SkeletonBlock() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <Skeleton height={28} width="60%" />
      <Skeleton height={14} width="40%" />
      <div style={{ height: 16 }} />
      <Skeleton height={14} />
      <Skeleton height={14} width="90%" />
      <Skeleton height={14} width="80%" />
    </div>
  );
}

// ── Code block with line numbers ──────────────────────────────────────────────

function CodeBlock({ code, language = 'c' }: { code: string; language?: string }) {
  const lines = code.split('\n');
  // Syntax-highlight each line with hljs. Per-line tokenisation is
  // good enough for the short snippets we show in Affected Code; the
  // rare multi-line token (block comments, template literals) loses
  // colour continuity but the code still renders correctly.
  const highlighted = lines.map((l) => highlightReact(l, language));
  return (
    <div style={{ position: 'relative', background: '#0d1117', border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden' }}>
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '6px 12px',
        background: 'var(--surface-2)',
        borderBottom: '1px solid var(--border)',
      }}>
        <span style={{ fontSize: 10, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.5px', fontWeight: 600 }}>{language}</span>
        <CopyButton text={code} label="Copy code" />
      </div>
      <div style={{ overflowX: 'auto', maxHeight: 360 }}>
        <table style={{ borderCollapse: 'collapse', width: '100%', fontFamily: 'monospace', fontSize: 12 }}>
          <tbody>
            {lines.map((line, i) => (
              <tr key={i}>
                <td style={{
                  padding: '0 12px',
                  color: 'var(--border)',
                  userSelect: 'none',
                  textAlign: 'right',
                  minWidth: 36,
                  borderRight: '1px solid var(--border)',
                  background: '#0d1117',
                  lineHeight: '20px',
                }}>
                  {i + 1}
                </td>
                <td className="hljs" style={{ padding: '0 16px', color: 'var(--text)', whiteSpace: 'pre', lineHeight: '20px', background: 'transparent' }}>
                  {line ? highlighted[i] : ' '}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Diff block ────────────────────────────────────────────────────────────────

function DiffBlock({ diff }: { diff: string }) {
  const lines = diff.split('\n');
  return (
    <div style={{ background: '#0d1117', border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden' }}>
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '6px 12px',
        background: 'var(--surface-2)',
        borderBottom: '1px solid var(--border)',
      }}>
        <span style={{ fontSize: 10, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.5px', fontWeight: 600 }}>diff</span>
        <CopyButton text={diff} label="Copy diff" />
      </div>
      <div style={{ overflowX: 'auto', maxHeight: 360, fontFamily: 'monospace', fontSize: 12 }}>
        {lines.map((line, i) => {
          const isAdd = line.startsWith('+') && !line.startsWith('+++');
          const isDel = line.startsWith('-') && !line.startsWith('---');
          const isHunk = line.startsWith('@@');
          return (
            <div key={i} style={{
              padding: '0 16px',
              lineHeight: '20px',
              background: isAdd ? 'rgba(63,185,80,0.1)' : isDel ? 'rgba(248,81,73,0.1)' : isHunk ? 'rgba(88,166,255,0.08)' : 'transparent',
              color: isAdd ? 'var(--green)' : isDel ? 'var(--red)' : isHunk ? 'var(--blue)' : 'var(--text)',
              whiteSpace: 'pre',
            }}>
              {line || ' '}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Spinner ───────────────────────────────────────────────────────────────────

function Spinner({ size = 14 }: { size?: number }) {
  return (
    <span style={{
      display: 'inline-block',
      width: size,
      height: size,
      border: `2px solid var(--border)`,
      borderTopColor: 'var(--blue)',
      borderRadius: '50%',
      animation: 'spin 0.7s linear infinite',
      flexShrink: 0,
    }} />
  );
}

// ── Main FindingDetail component ──────────────────────────────────────────────

export default function FindingDetail({ vulnId, onClose }: FindingDetailProps) {
  const [vuln, setVuln] = useState<Vulnerability | null>(null);
  const [tab, setTab] = useState<Tab>('overview');
  const [reportSubTab, setReportSubTab] = useState<ReportSubTab>('email');
  // "View file in full" modal, triggered from the Suggested Fix section.
  const [fileViewerOpen, setFileViewerOpen] = useState(false);
  // Incremented by the "Write Manually" empty-state button to force
  // the ManualTriageField into edit mode without it living higher up
  // in state. Just a monotonic counter — ManualTriageField's useEffect
  // reacts to the change.
  const [manualTriageOpenSignal, setManualTriageOpenSignal] = useState(0);

  const [editing, setEditing] = useState(false);
  const [editData, setEditData] = useState<Partial<Vulnerability>>({});

  const [triaging, setTriaging] = useState(false);
  const [loading, setLoading] = useState(true);
  const [deleting, setDeleting] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  // Fix tab
  const [suggestingFix, setSuggestingFix] = useState(false);
  const [suggestedFix, setSuggestedFix] = useState<string | null>(null);
  const [suggestedDiff, setSuggestedDiff] = useState<string | null>(null);

  // Report tab
  const [reportContent, setReportContent] = useState<Partial<Record<ReportSubTab, string>>>({});
  const [reportLoading, setReportLoading] = useState<ReportSubTab | null>(null);

  // AI tab
  const [deepAnalysis, setDeepAnalysis] = useState<string | null>(null);
  const [deepAnalyzing, setDeepAnalyzing] = useState(false);
  const [chatMessages, setChatMessages] = useState<{ role: 'user' | 'assistant'; content: string }[]>([]);
  const [chatInput, setChatInput] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  const chatEndRef = useRef<HTMLDivElement>(null);

  const { toast } = useToast();

  // ── Load ────────────────────────────────────────────────────────────────────

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const v = await getVulnerability(vulnId);
      setVuln(v);
      setEditData(v);
    } catch (err) {
      toast(`Failed to load finding: ${err instanceof Error ? err.message : err}`, 'error');
    } finally {
      setLoading(false);
    }
  }, [vulnId, toast]);

  useEffect(() => { load(); }, [load]);

  // Triage polling
  useEffect(() => {
    if (!triaging) return;
    const interval = setInterval(async () => {
      try {
        const fresh = await getVulnerability(vulnId);
        if (fresh.ai_triage && fresh.ai_triage !== vuln?.ai_triage) {
          setVuln(fresh);
          setTriaging(false);
          toast('AI triage complete', 'success');
          clearInterval(interval);
        }
      } catch { /* ignore poll errors */ }
    }, 2000);
    const timeout = setTimeout(() => {
      clearInterval(interval);
      setTriaging(false);
      toast('Triage is running in background - reload to see result', 'info');
    }, 60_000);
    return () => { clearInterval(interval); clearTimeout(timeout); };
  }, [triaging, vulnId, vuln?.ai_triage, toast]);

  // Chat scroll
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [chatMessages]);

  // Keyboard
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
      if (e.key === 'e' && !editing && !(e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement)) {
        setEditing(true);
      }
      if (e.key === 'v' && !(e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement)) {
        if (vuln) handleToggleVerify();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [editing, vuln]);

  // ── Actions ─────────────────────────────────────────────────────────────────

  const saveEdit = async () => {
    if (!vuln) return;
    try {
      const updated = await updateVulnerability(vuln.id, editData);
      setVuln(updated);
      setEditing(false);
      toast('Finding updated', 'success');
    } catch (err) {
      toast(`Update failed: ${err instanceof Error ? err.message : err}`, 'error');
    }
  };

  const runTriage = async () => {
    if (!vuln) return;
    setTriaging(true);
    try {
      await triggerAITriage(vuln.id);
      toast('AI triage started - results will appear shortly', 'info');
    } catch (err) {
      setTriaging(false);
      toast(`Triage failed: ${err instanceof Error ? err.message : err}`, 'error');
    }
  };

  const handleToggleVerify = async () => {
    if (!vuln) return;
    const newVal = vuln.verified ? 0 : 1;
    try {
      const updated = await updateVulnerability(vuln.id, { verified: newVal } as any);
      setVuln(updated);
      toast(newVal ? 'Marked as verified' : 'Verification removed', 'success');
    } catch (err) {
      toast(`Failed: ${err instanceof Error ? err.message : err}`, 'error');
    }
  };

  const handleMarkFalsePositive = async () => {
    if (!vuln) return;
    try {
      const updated = await updateVulnerability(vuln.id, {
        false_positive: 1,
        status: 'Wont Fix',
      } as any);
      setVuln(updated);
      toast('Marked as false positive', 'info');
    } catch (err) {
      toast(`Failed: ${err instanceof Error ? err.message : err}`, 'error');
    }
  };

  const handleDelete = async () => {
    if (!vuln) return;
    setDeleting(true);
    try {
      await deleteVulnerability(vuln.id);
      toast('Finding deleted', 'info');
      onClose();
    } catch (err) {
      toast(`Delete failed: ${err instanceof Error ? err.message : err}`, 'error');
      setDeleting(false);
    }
  };

  const handleSuggestFix = async () => {
    if (!vuln) return;
    setSuggestingFix(true);
    try {
      const res = await apiFetch('/api/ai/suggest-fix', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vuln_id: vuln.id }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({ error: res.statusText }));
        throw new Error(body.error || res.statusText);
      }
      const data = await res.json();
      setSuggestedFix(data.suggested_fix || null);
      setSuggestedDiff(data.fix_diff || null);
      toast('Fix suggestion generated', 'success');
    } catch (err) {
      toast(`Fix suggestion failed: ${err instanceof Error ? err.message : err}`, 'error');
    } finally {
      setSuggestingFix(false);
    }
  };

  const handleDeepAnalyze = async () => {
    if (!vuln) return;
    setDeepAnalyzing(true);
    try {
      const res = await apiFetch('/api/ai/deep-analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vuln_id: vuln.id }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({ error: res.statusText }));
        throw new Error(body.error || res.statusText);
      }
      const data = await res.json();
      setDeepAnalysis(data.analysis || null);
      toast('Deep analysis complete', 'success');
    } catch (err) {
      toast(`Deep analysis failed: ${err instanceof Error ? err.message : err}`, 'error');
    } finally {
      setDeepAnalyzing(false);
    }
  };

  const handleGenerateReport = async (subTab: ReportSubTab) => {
    if (!vuln) return;
    setReportLoading(subTab);
    try {
      const typeMap: Record<ReportSubTab, string> = {
        email: 'email',
        advisory: 'advisory',
        summary: 'summary',
      };
      const report = await generateReport(vuln.id, typeMap[subTab]);
      setReportContent(prev => ({ ...prev, [subTab]: report.content }));
      toast('Report generated', 'success');
    } catch (err) {
      toast(`Report generation failed: ${err instanceof Error ? err.message : err}`, 'error');
    } finally {
      setReportLoading(null);
    }
  };

  const handleSendChat = async () => {
    if (!chatInput.trim() || !vuln) return;
    const userMsg = chatInput.trim();
    setChatInput('');
    const newMessages = [...chatMessages, { role: 'user' as const, content: userMsg }];
    setChatMessages(newMessages);
    setChatLoading(true);
    try {
      // Build context-aware messages with vuln info prepended
      const contextPrefix = `Context: I'm asking about vulnerability "${vuln.title}" (${vuln.severity}, CVSS ${vuln.cvss ?? 'N/A'}, ${vuln.cwe ?? ''}).
File: ${vuln.file ?? 'unknown'}
Description: ${vuln.description ?? 'N/A'}
Code: ${vuln.code_snippet ? vuln.code_snippet.slice(0, 400) : 'N/A'}

Question: `;
      const apiMessages = newMessages.map((m, i) =>
        i === 0 && m.role === 'user'
          ? { role: m.role, content: contextPrefix + m.content }
          : m
      );
      const resp = await sendAIChat(apiMessages);
      setChatMessages(prev => [...prev, { role: 'assistant', content: resp.response }]);
    } catch (err) {
      toast(`Chat failed: ${err instanceof Error ? err.message : err}`, 'error');
    } finally {
      setChatLoading(false);
    }
  };

  // ── Parse triage ────────────────────────────────────────────────────────────

  let parsedTriage: Record<string, any> | null = null;
  if (vuln?.ai_triage) {
    try { parsedTriage = JSON.parse(vuln.ai_triage); } catch { /* raw string */ }
  }

  // ── Tab style ───────────────────────────────────────────────────────────────

  const tabBtn = (t: Tab, label: string) => (
    <button
      key={t}
      onClick={() => setTab(t)}
      style={{
        background: 'none',
        border: 'none',
        borderBottom: tab === t ? '2px solid var(--blue)' : '2px solid transparent',
        color: tab === t ? 'var(--text)' : 'var(--muted)',
        padding: '10px 16px',
        cursor: 'pointer',
        fontSize: 13,
        fontWeight: tab === t ? 600 : 400,
        whiteSpace: 'nowrap',
        transition: 'color 0.15s',
      }}
    >
      {label}
    </button>
  );

  // ── Render ───────────────────────────────────────────────────────────────────

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      zIndex: 1000,
      display: 'flex',
    }}>
      {/* Backdrop */}
      <div
        onClick={onClose}
        style={{
          flex: '0 0 30%',
          background: 'rgba(0,0,0,0.5)',
        }}
      />

      {/* Slide-over panel - 70% width */}
      <div style={{
        flex: '0 0 70%',
        background: 'var(--surface)',
        borderLeft: '1px solid var(--border)',
        display: 'flex',
        flexDirection: 'column',
        height: '100vh',
        overflow: 'hidden',
        animation: 'slideInRight 0.2s ease',
      }}>
        {loading ? (
          <div style={{ padding: 32 }}>
            <SkeletonBlock />
          </div>
        ) : !vuln ? null : (
          <>
            {/* ── Header ── */}
            <div style={{
              padding: '20px 28px 0',
              borderBottom: '1px solid var(--border)',
              flexShrink: 0,
              background: 'var(--surface)',
            }}>
              {/* Top row: close + title */}
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 16, marginBottom: 14 }}>
                <button
                  onClick={onClose}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: 'var(--muted)',
                    cursor: 'pointer',
                    fontSize: 18,
                    padding: '2px 4px',
                    lineHeight: 1,
                    flexShrink: 0,
                    marginTop: 2,
                  }}
                  title="Close (Esc)"
                >
                  x
                </button>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 11, color: 'var(--muted)', marginBottom: 3, letterSpacing: '0.3px' }}>
                    {vuln.project}
                    {vuln.tool_name && <span style={{ marginLeft: 6, color: 'var(--purple)', fontWeight: 500 }}> via {vuln.tool_name}</span>}
                  </div>
                  {editing ? (
                    <input
                      value={editData.title ?? ''}
                      onChange={e => setEditData(p => ({ ...p, title: e.target.value }))}
                      style={inputStyle}
                      autoFocus
                    />
                  ) : (
                    <h2 style={{ fontSize: 19, fontWeight: 700, color: 'var(--text)', margin: 0, lineHeight: 1.3 }}>
                      {vuln.title}
                    </h2>
                  )}
                </div>
                {/* CVSS score - prominent */}
                <div style={{ textAlign: 'center', flexShrink: 0, minWidth: 56 }}>
                  <div style={{ fontSize: 32, fontWeight: 800, lineHeight: 1 }}>
                    <CvssScore score={vuln.cvss} />
                  </div>
                  <div style={{ fontSize: 9, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.6px', marginTop: 3 }}>CVSS</div>
                </div>
              </div>

              {/* Meta row: badges + file + quick actions */}
              <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                {editing ? (
                  <>
                    <select value={editData.severity ?? vuln.severity} onChange={e => setEditData(p => ({ ...p, severity: e.target.value as Severity }))} style={selectStyle}>
                      {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
                    </select>
                    <select value={editData.status ?? vuln.status} onChange={e => setEditData(p => ({ ...p, status: e.target.value as VulnStatus }))} style={selectStyle}>
                      {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
                    </select>
                  </>
                ) : (
                  <>
                    <SeverityBadge severity={vuln.severity} />
                    <StatusBadge status={vuln.status} />
                  </>
                )}

                {vuln.cwe && (
                  <span style={{ fontSize: 11, color: 'var(--muted)', background: 'var(--surface-2)', padding: '2px 8px', borderRadius: 4, border: '1px solid var(--border)', fontFamily: 'monospace' }}>
                    {vuln.cwe}
                  </span>
                )}

                {(vuln as any).verified === 1 && (
                  <span style={{ fontSize: 11, color: 'var(--green)', background: 'var(--green)11', padding: '2px 8px', borderRadius: 4, border: '1px solid var(--green)33' }}>
                    Verified
                  </span>
                )}

                {(vuln as any).false_positive === 1 && (
                  <span style={{ fontSize: 11, color: 'var(--muted)', background: 'var(--surface-2)', padding: '2px 8px', borderRadius: 4, border: '1px solid var(--border)' }}>
                    False Positive
                  </span>
                )}

                {vuln.file && (
                  <span style={{ fontSize: 11, color: 'var(--blue)', fontFamily: 'monospace', marginLeft: 4 }}>
                    {vuln.file}{vuln.line_number ? `:${vuln.line_number}` : ''}
                  </span>
                )}

                {/* Action buttons - right side */}
                <div style={{ marginLeft: 'auto', display: 'flex', gap: 6, flexShrink: 0 }}>
                  {editing ? (
                    <>
                      <button onClick={saveEdit} style={actionBtn('var(--green)')}>Save</button>
                      <button onClick={() => { setEditing(false); setEditData(vuln); }} style={actionBtn('var(--surface-2)')}>Cancel</button>
                    </>
                  ) : (
                    <>
                      <button onClick={() => setEditing(true)} style={actionBtn('var(--surface-2)')} title="Edit (e)">Edit</button>
                      <button onClick={handleToggleVerify} style={actionBtn((vuln as any).verified ? 'var(--green)33' : 'var(--surface-2)')} title="Toggle verified (v)">
                        {(vuln as any).verified ? 'Unverify' : 'Verify'}
                      </button>
                      <button onClick={handleMarkFalsePositive} style={actionBtn('var(--surface-2)')}>False Pos.</button>
                      <button onClick={() => { setTab('report'); }} style={actionBtn('var(--blue)')}>Submit</button>
                      {confirmDelete ? (
                        <>
                          <button onClick={handleDelete} disabled={deleting} style={actionBtn('var(--red)')}>
                            {deleting ? 'Deleting...' : 'Confirm'}
                          </button>
                          <button onClick={() => setConfirmDelete(false)} style={actionBtn('var(--surface-2)')}>Cancel</button>
                        </>
                      ) : (
                        <button onClick={() => setConfirmDelete(true)} style={actionBtn('var(--surface-2)')}>Delete</button>
                      )}
                    </>
                  )}
                </div>
              </div>

              {/* Tab bar */}
              <div style={{ display: 'flex', gap: 0, overflowX: 'auto' }}>
                {tabBtn('overview', 'Overview')}
                {tabBtn('fix', 'Fix')}
                {tabBtn('exploits', 'Exploits')}
                {tabBtn('runtime', 'Runtime')}
                {tabBtn('disclosure', 'Disclosure')}
                {tabBtn('report', 'Report')}
                {tabBtn('ai', 'AI Analysis')}
                {tabBtn('notes', 'Notes')}
                {tabBtn('history', 'History')}
              </div>
            </div>

            {/* ── Tab content ── */}
            <div style={{ flex: 1, overflow: 'auto', padding: '24px 28px' }}>

              {/* ── OVERVIEW TAB ── */}
              {tab === 'overview' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 22 }}>
                  {/* Meta grid */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: 10 }}>
                    {vuln.method && (
                      <MetaCard label="Function" value={<code style={{ fontSize: 12, color: 'var(--purple)' }}>{vuln.method}</code>} />
                    )}
                    {vuln.file && (
                      <MetaCard label="File" value={
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <code style={{ fontSize: 11, color: 'var(--blue)', wordBreak: 'break-all' }}>
                            {vuln.file}{vuln.line_number ? `:${vuln.line_number}` : ''}
                          </code>
                          <CopyButton text={`${vuln.file}${vuln.line_number ? `:${vuln.line_number}` : ''}`} />
                        </div>
                      } />
                    )}
                    {(vuln as any).confidence != null && (
                      <MetaCard label="Confidence" value={
                        <ConfidenceBadge value={(vuln as any).confidence} />
                      } />
                    )}
                    {(vuln as any).tool_name && (
                      <MetaCard label="Tool" value={<span style={{ fontSize: 12, color: 'var(--purple)' }}>{(vuln as any).tool_name}</span>} />
                    )}
                    {vuln.found_at && (
                      <MetaCard label="Found" value={<span style={{ fontSize: 12 }}>{new Date(vuln.found_at).toLocaleDateString()}</span>} />
                    )}
                    {vuln.updated_at && (
                      <MetaCard label="Updated" value={<span style={{ fontSize: 12 }}>{new Date(vuln.updated_at).toLocaleDateString()}</span>} />
                    )}
                  </div>

                  {/* Description */}
                  <Field label="What's the bug?">
                    {editing ? (
                      <textarea
                        value={editData.description ?? ''}
                        onChange={e => setEditData(p => ({ ...p, description: e.target.value }))}
                        style={{ ...inputStyle, minHeight: 90, resize: 'vertical' }}
                      />
                    ) : vuln.description ? (
                      // Render as markdown so imported audit docs
                      // (headings, fenced code, bullets, bold) remain
                      // readable instead of collapsing into one line.
                      <Markdown>{vuln.description}</Markdown>
                    ) : (
                      <span style={{ color: 'var(--muted)', fontSize: 13 }}>No description.</span>
                    )}
                  </Field>

                  {/* Impact */}
                  <Field label="Impact">
                    {editing ? (
                      <textarea
                        value={editData.impact ?? ''}
                        onChange={e => setEditData(p => ({ ...p, impact: e.target.value }))}
                        style={{ ...inputStyle, minHeight: 60, resize: 'vertical' }}
                      />
                    ) : vuln.impact ? (
                      <InfoBox color="var(--yellow)">{vuln.impact}</InfoBox>
                    ) : (
                      <span style={{ color: 'var(--muted)', fontSize: 13 }}>No impact assessment.</span>
                    )}
                  </Field>

                  {/* Affected code */}
                  {vuln.code_snippet && (
                    <Field label="Affected Code">
                      <CodeBlock code={vuln.code_snippet} language={(vuln as any).tool_name?.includes('py') ? 'python' : 'c'} />
                    </Field>
                  )}

                  {/* How it was found */}
                  {((vuln as any).method || (vuln as any).tool_name) && (
                    <Field label="How it was found">
                      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        {(vuln as any).tool_name && (
                          <span style={{ fontSize: 12, color: 'var(--purple)', background: 'var(--purple)11', padding: '4px 10px', borderRadius: 4, border: '1px solid var(--purple)33' }}>
                            {(vuln as any).tool_name}
                          </span>
                        )}
                        {(vuln as any).method && (
                          <span style={{ fontSize: 12, color: 'var(--muted)', background: 'var(--surface-2)', padding: '4px 10px', borderRadius: 4, border: '1px solid var(--border)', fontFamily: 'monospace' }}>
                            {(vuln as any).method}
                          </span>
                        )}
                      </div>
                    </Field>
                  )}

                  {/* CVSS vector */}
                  {vuln.cvss_vector && (
                    <Field label="CVSS Vector">
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <code style={{ fontSize: 11, color: 'var(--muted)' }}>{vuln.cvss_vector}</code>
                        <CopyButton text={vuln.cvss_vector} />
                      </div>
                    </Field>
                  )}
                </div>
              )}

              {/* ── FIX TAB ── */}
              {tab === 'fix' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 22 }}>
                  {/* Action buttons row */}
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    <button
                      onClick={handleSuggestFix}
                      disabled={suggestingFix}
                      style={{ ...actionBtn('var(--purple)'), display: 'flex', alignItems: 'center', gap: 6, color: '#fff', opacity: suggestingFix ? 0.7 : 1 }}
                    >
                      {suggestingFix ? <><Spinner size={12} /> Generating...</> : 'AI Suggest Fix'}
                    </button>
                    <button
                      onClick={() => toast('Apply Fix: coming soon - will apply the diff to the file', 'info')}
                      style={actionBtn('var(--surface-2)')}
                    >
                      Apply Fix
                    </button>
                    <button
                      onClick={() => toast('Create PR: coming soon - will create a git branch + commit + PR', 'info')}
                      style={actionBtn('var(--surface-2)')}
                    >
                      Create PR
                    </button>
                    <button
                      onClick={() => toast('Run Tests: coming soon - will run relevant tests after fix', 'info')}
                      style={actionBtn('var(--surface-2)')}
                    >
                      Run Tests
                    </button>
                  </div>

                  {/* Existing suggested fix from DB */}
                  {(suggestedFix || vuln.suggested_fix) && (
                    <Field label="Suggested Fix">
                      <InfoBox color="var(--green)">
                        {suggestedFix ?? vuln.suggested_fix}
                      </InfoBox>
                      {/* Shortcut to open the affected file with the
                          flagged lines highlighted - the fix makes a
                          lot more sense when you can see the
                          surrounding code it's patching. Only shown
                          when we have both a file path and a project
                          id to resolve it against. */}
                      {vuln.file && (vuln as any).project_id && (
                        <div style={{ marginTop: 8 }}>
                          <button
                            onClick={() => setFileViewerOpen(true)}
                            style={{
                              padding: '5px 12px', fontSize: 12,
                              border: '1px solid var(--border)', borderRadius: 5,
                              background: 'var(--surface-2)', color: 'var(--text)',
                              cursor: 'pointer',
                              display: 'inline-flex', alignItems: 'center', gap: 6,
                            }}
                          >
                            <span>&#128193;</span>
                            View {vuln.file.split(/[/\\]/).pop()}
                            {vuln.line_start ? ` : ${vuln.line_start}` : ''}
                            {' '}in full
                          </button>
                        </div>
                      )}
                    </Field>
                  )}

                  {/* Fix diff */}
                  {(suggestedDiff || (vuln as any).fix_diff) && (
                    <Field label="Fix Diff">
                      <DiffBlock diff={suggestedDiff ?? (vuln as any).fix_diff} />
                    </Field>
                  )}

                  {!suggestedFix && !vuln.suggested_fix && !suggestedDiff && !(vuln as any).fix_diff && !suggestingFix && (
                    <EmptyState>
                      No fix available yet. Click "AI Suggest Fix" to generate a fix.
                    </EmptyState>
                  )}

                  {suggestingFix && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: 20, color: 'var(--muted)', fontSize: 13 }}>
                      <Spinner />
                      Generating fix with AI...
                    </div>
                  )}
                </div>
              )}

              {/* ── REPORT TAB ── */}
              {tab === 'report' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
                  {/* Sub-tab bar */}
                  <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--border)' }}>
                    {(['email', 'advisory', 'summary'] as ReportSubTab[]).map(st => (
                      <button
                        key={st}
                        onClick={() => setReportSubTab(st)}
                        style={{
                          background: 'none',
                          border: 'none',
                          borderBottom: reportSubTab === st ? '2px solid var(--purple)' : '2px solid transparent',
                          color: reportSubTab === st ? 'var(--text)' : 'var(--muted)',
                          padding: '8px 16px',
                          cursor: 'pointer',
                          fontSize: 12,
                          fontWeight: reportSubTab === st ? 600 : 400,
                          textTransform: 'capitalize',
                        }}
                      >
                        {st === 'email' ? 'Email Disclosure' : st === 'advisory' ? 'GitHub Advisory' : 'Executive Summary'}
                      </button>
                    ))}
                  </div>

                  {/* Email sub-tab */}
                  {reportSubTab === 'email' && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                      <div style={{ display: 'flex', gap: 10, flexDirection: 'column' }}>
                        <div style={{ display: 'grid', gridTemplateColumns: '80px 1fr', gap: 8, alignItems: 'center' }}>
                          <span style={fieldLabelStyle}>To:</span>
                          <code style={{ fontSize: 12, color: 'var(--blue)' }}>
                            {(vuln as any).submit_email ?? 'security@' + (vuln.project ?? 'project').toLowerCase().replace(/[^a-z0-9]/g, '') + '.com'}
                          </code>
                        </div>
                        <div style={{ display: 'grid', gridTemplateColumns: '80px 1fr', gap: 8, alignItems: 'center' }}>
                          <span style={fieldLabelStyle}>Subject:</span>
                          <code style={{ fontSize: 12, color: 'var(--text)' }}>
                            [Security] {vuln.severity} severity vulnerability in {vuln.project}: {vuln.title}
                          </code>
                        </div>
                      </div>

                      <div style={{ display: 'flex', gap: 8 }}>
                        <button
                          onClick={() => handleGenerateReport('email')}
                          disabled={reportLoading === 'email'}
                          style={{ ...actionBtn('var(--blue)'), display: 'flex', alignItems: 'center', gap: 6, color: '#fff', opacity: reportLoading === 'email' ? 0.7 : 1 }}
                        >
                          {reportLoading === 'email' ? <><Spinner size={12} /> Generating...</> : 'Generate with AI'}
                        </button>
                        {reportContent.email && <CopyButton text={reportContent.email} label="Copy All" />}
                      </div>

                      {reportContent.email ? (
                        <pre style={reportPreStyle}>{reportContent.email}</pre>
                      ) : reportLoading === 'email' ? (
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: 20, color: 'var(--muted)', fontSize: 13 }}>
                          <Spinner /> Generating email disclosure...
                        </div>
                      ) : (
                        <EmptyState>Click "Generate with AI" to create the disclosure email.</EmptyState>
                      )}
                    </div>
                  )}

                  {/* GitHub Advisory sub-tab */}
                  {reportSubTab === 'advisory' && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                      <div style={{ display: 'flex', gap: 8 }}>
                        <button
                          onClick={() => handleGenerateReport('advisory')}
                          disabled={reportLoading === 'advisory'}
                          style={{ ...actionBtn('var(--blue)'), display: 'flex', alignItems: 'center', gap: 6, color: '#fff', opacity: reportLoading === 'advisory' ? 0.7 : 1 }}
                        >
                          {reportLoading === 'advisory' ? <><Spinner size={12} /> Generating...</> : 'Generate with AI'}
                        </button>
                        {vuln.advisory_url && (
                          <a
                            href={vuln.advisory_url}
                            target="_blank"
                            rel="noreferrer"
                            style={{ ...actionBtn('var(--surface-2)'), textDecoration: 'none', display: 'inline-flex', alignItems: 'center' }}
                          >
                            Open Advisory Page
                          </a>
                        )}
                        {reportContent.advisory && <CopyButton text={reportContent.advisory} label="Copy All" />}
                      </div>

                      {reportContent.advisory ? (
                        <pre style={reportPreStyle}>{reportContent.advisory}</pre>
                      ) : reportLoading === 'advisory' ? (
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: 20, color: 'var(--muted)', fontSize: 13 }}>
                          <Spinner /> Generating advisory...
                        </div>
                      ) : (
                        <EmptyState>Click "Generate with AI" to create the GitHub security advisory content.</EmptyState>
                      )}
                    </div>
                  )}

                  {/* Executive Summary sub-tab */}
                  {reportSubTab === 'summary' && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                      <div style={{ display: 'flex', gap: 8 }}>
                        <button
                          onClick={() => handleGenerateReport('summary')}
                          disabled={reportLoading === 'summary'}
                          style={{ ...actionBtn('var(--blue)'), display: 'flex', alignItems: 'center', gap: 6, color: '#fff', opacity: reportLoading === 'summary' ? 0.7 : 1 }}
                        >
                          {reportLoading === 'summary' ? <><Spinner size={12} /> Generating...</> : 'Generate with AI'}
                        </button>
                        {reportContent.summary && <CopyButton text={reportContent.summary} label="Copy All" />}
                      </div>

                      {reportContent.summary ? (
                        <div style={{ ...reportPreStyle as any, whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontFamily: 'inherit', fontSize: 13 }}>
                          {reportContent.summary}
                        </div>
                      ) : reportLoading === 'summary' ? (
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: 20, color: 'var(--muted)', fontSize: 13 }}>
                          <Spinner /> Generating executive summary...
                        </div>
                      ) : (
                        <EmptyState>Click "Generate with AI" to create a non-technical executive summary.</EmptyState>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* ── AI ANALYSIS TAB ── */}
              {tab === 'ai' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 22 }}>
                  {/* Triage result */}
                  {parsedTriage ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <div style={fieldLabelStyle}>AI Triage Assessment</div>
                        <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
                          <button
                            onClick={runTriage}
                            disabled={triaging}
                            style={{ ...actionBtn('var(--surface-2)'), display: 'flex', alignItems: 'center', gap: 6, opacity: triaging ? 0.6 : 1 }}
                          >
                            {triaging ? <><Spinner size={12} /> Triaging...</> : 'Re-analyze'}
                          </button>
                          <button
                            onClick={handleDeepAnalyze}
                            disabled={deepAnalyzing}
                            style={{ ...actionBtn('var(--purple)'), display: 'flex', alignItems: 'center', gap: 6, color: '#fff', opacity: deepAnalyzing ? 0.6 : 1 }}
                          >
                            {deepAnalyzing ? <><Spinner size={12} /> Analyzing...</> : 'Deep Analyze'}
                          </button>
                        </div>
                      </div>

                      {/* Structured badges */}
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                        {[
                          { label: 'Tier', value: parsedTriage.tier, color: 'var(--orange)' },
                          { label: 'Severity', value: parsedTriage.severity, color: 'var(--red)' },
                          { label: 'Exploitability', value: parsedTriage.exploitability, color: 'var(--yellow)' },
                          { label: 'FP Risk', value: parsedTriage.false_positive_risk, color: 'var(--muted)' },
                          { label: 'Confidence', value: parsedTriage.confidence != null ? `${Math.round(parsedTriage.confidence * 100)}%` : null, color: 'var(--green)' },
                        ].filter(b => b.value != null).map(b => (
                          <span key={b.label} style={{
                            fontSize: 12,
                            background: `${b.color}11`,
                            border: `1px solid ${b.color}44`,
                            borderRadius: 5,
                            padding: '4px 10px',
                            color: b.color,
                            fontWeight: 500,
                          }}>
                            <span style={{ color: 'var(--muted)', fontWeight: 400, fontSize: 10 }}>{b.label}: </span>
                            {String(b.value)}
                          </span>
                        ))}
                      </div>

                      {parsedTriage.summary && (
                        <Field label="Summary">
                          <p style={{ margin: 0, color: 'var(--text)', fontSize: 13, lineHeight: 1.7 }}>{parsedTriage.summary}</p>
                        </Field>
                      )}

                      {parsedTriage.reasoning && (
                        <Field label="Reasoning">
                          <p style={{ margin: 0, color: 'var(--muted)', fontSize: 13, lineHeight: 1.7, fontStyle: 'italic' }}>{parsedTriage.reasoning}</p>
                        </Field>
                      )}

                      {parsedTriage.suggested_fix && (
                        <Field label="Recommended Fix">
                          <InfoBox color="var(--green)">{parsedTriage.suggested_fix}</InfoBox>
                        </Field>
                      )}

                      <details>
                        <summary style={{ fontSize: 11, color: 'var(--muted)', cursor: 'pointer', userSelect: 'none' }}>Raw JSON</summary>
                        <div style={{ marginTop: 8 }}>
                          <CodeBlock code={JSON.stringify(parsedTriage, null, 2)} language="json" />
                        </div>
                      </details>
                    </div>
                  ) : vuln.ai_triage ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                      <div style={{ display: 'flex', gap: 8 }}>
                        <button onClick={runTriage} disabled={triaging} style={{ ...actionBtn('var(--surface-2)'), display: 'flex', alignItems: 'center', gap: 6, opacity: triaging ? 0.6 : 1 }}>
                          {triaging ? <><Spinner size={12} /> Triaging...</> : 'Re-analyze'}
                        </button>
                      </div>
                      <InfoBox color="var(--purple)">{vuln.ai_triage}</InfoBox>
                    </div>
                  ) : (
                    // Two buttons side-by-side, no paragraph. The user
                    // picks the path they want — nothing is implied
                    // about which is "default" or "preferred".
                    <div style={{ display: 'flex', gap: 10, padding: '24px 0', justifyContent: 'center' }}>
                      <button
                        onClick={runTriage}
                        disabled={triaging}
                        style={{ ...actionBtn('var(--purple)'), display: 'flex', alignItems: 'center', gap: 6, color: '#fff', opacity: triaging ? 0.6 : 1 }}
                      >
                        {triaging ? <><Spinner size={12} /> Triaging...</> : 'AI Triage'}
                      </button>
                      <button
                        onClick={() => setManualTriageOpenSignal((s) => s + 1)}
                        style={{
                          padding: '8px 18px', fontSize: 13, fontWeight: 600,
                          border: '1px solid var(--border)', borderRadius: 6,
                          background: 'var(--surface-2)', color: 'var(--text)', cursor: 'pointer',
                        }}
                      >
                        Write Manually
                      </button>
                    </div>
                  )}

                  {/* Manual Triage - always shown, always editable,
                      independent of any AI state. This is the "AI is
                      not required" UX escape hatch: any user can write
                      their own verdict without touching a provider. */}
                  <ManualTriageField
                    value={vuln.manual_triage || ''}
                    openSignal={manualTriageOpenSignal}
                    onSave={async (next) => {
                      try {
                        await updateVulnerability(vuln.id, { manual_triage: next } as any);
                        toast('Saved manual triage', 'success');
                        await load();
                      } catch (err: any) {
                        toast(`Failed to save: ${err.message}`, 'error');
                      }
                    }}
                  />

                  {/* Deep Analysis */}
                  {(deepAnalysis || deepAnalyzing) && (
                    <Field label="Deep Analysis">
                      {deepAnalyzing ? (
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: 16, color: 'var(--muted)', fontSize: 13 }}>
                          <Spinner /> Running deep analysis with full context...
                        </div>
                      ) : deepAnalysis ? (
                        <div style={{ ...reportPreStyle as any, whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontFamily: 'inherit', fontSize: 13 }}>
                          {deepAnalysis}
                        </div>
                      ) : null}
                    </Field>
                  )}

                  {/* Deep analyze button (when no triage yet or to add deep analysis) */}
                  {!deepAnalysis && !deepAnalyzing && vuln.ai_triage && (
                    <button
                      onClick={handleDeepAnalyze}
                      style={{ ...actionBtn('var(--purple)'), display: 'flex', alignItems: 'center', gap: 6, color: '#fff', alignSelf: 'flex-start' }}
                    >
                      Deep Analyze
                    </button>
                  )}

                  {/* Chat interface */}
                  <div style={{ borderTop: '1px solid var(--border)', paddingTop: 18 }}>
                    <div style={fieldLabelStyle}>Ask AI about this finding</div>
                    <div style={{
                      background: 'var(--bg)',
                      border: '1px solid var(--border)',
                      borderRadius: 8,
                      marginTop: 10,
                      display: 'flex',
                      flexDirection: 'column',
                      maxHeight: 360,
                      overflow: 'hidden',
                    }}>
                      {/* Messages */}
                      <div style={{ flex: 1, overflow: 'auto', padding: 14, display: 'flex', flexDirection: 'column', gap: 10, minHeight: 100 }}>
                        {chatMessages.length === 0 ? (
                          <div style={{ color: 'var(--muted)', fontSize: 12, fontStyle: 'italic' }}>
                            Ask anything about this vulnerability - exploitability, fix approaches, similar CVEs...
                          </div>
                        ) : (
                          chatMessages.map((m, i) => (
                            <div key={i} style={{
                              alignSelf: m.role === 'user' ? 'flex-end' : 'flex-start',
                              maxWidth: '85%',
                              background: m.role === 'user' ? 'var(--blue)22' : 'var(--surface-2)',
                              border: `1px solid ${m.role === 'user' ? 'var(--blue)44' : 'var(--border)'}`,
                              borderRadius: 8,
                              padding: '8px 12px',
                              fontSize: 12,
                              color: 'var(--text)',
                              lineHeight: 1.6,
                              whiteSpace: 'pre-wrap',
                              wordBreak: 'break-word',
                            }}>
                              {m.content}
                            </div>
                          ))
                        )}
                        {chatLoading && (
                          <div style={{ alignSelf: 'flex-start', display: 'flex', alignItems: 'center', gap: 8, color: 'var(--muted)', fontSize: 12 }}>
                            <Spinner size={12} /> Thinking...
                          </div>
                        )}
                        <div ref={chatEndRef} />
                      </div>
                      {/* Input */}
                      <div style={{ borderTop: '1px solid var(--border)', padding: 10, display: 'flex', gap: 8 }}>
                        <input
                          value={chatInput}
                          onChange={e => setChatInput(e.target.value)}
                          onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSendChat(); } }}
                          placeholder="Ask about exploitability, fix, similar CVEs..."
                          style={{ ...inputStyle, flex: 1, fontSize: 12 }}
                        />
                        <button
                          onClick={handleSendChat}
                          disabled={chatLoading || !chatInput.trim()}
                          style={{ ...actionBtn('var(--blue)'), color: '#fff', flexShrink: 0, opacity: chatLoading || !chatInput.trim() ? 0.5 : 1 }}
                        >
                          Send
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* ── EXPLOITS TAB ── */}
              {tab === 'exploits' && (
                <ExploitsTab findingId={vuln.id} />
              )}

              {/* ── RUNTIME TAB ── */}
              {tab === 'runtime' && (
                <RuntimeTab findingId={vuln.id} />
              )}

              {/* ── DISCLOSURE TAB ── */}
              {tab === 'disclosure' && (
                <DisclosureTab findingId={vuln.id} vulnTitle={vuln.title} />
              )}

              {/* ── NOTES TAB ── */}
              {tab === 'notes' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                  <NotesPanel findingId={vuln.id} initiallyOpen={true} />
                </div>
              )}

              {/* ── HISTORY TAB ── */}
              {tab === 'history' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
                  {/* Timeline */}
                  <Field label="Submission Timeline">
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
                      <TimelineItem
                        date={vuln.found_at}
                        label="Found"
                        color="var(--blue)"
                        active
                      />
                      <TimelineItem
                        date={(vuln as any).submitted_at}
                        label="Submitted"
                        color="var(--orange)"
                        active={!!(vuln as any).submitted_at}
                      />
                      <TimelineItem
                        date={(vuln as any).resolved_at}
                        label="Resolved"
                        color="var(--green)"
                        active={!!(vuln as any).resolved_at}
                      />
                    </div>
                  </Field>

                  {/* Links */}
                  <Field label="Links">
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                      {vuln.advisory_url && (
                        <LinkRow label="Advisory" url={vuln.advisory_url} />
                      )}
                      {(vuln as any).issue_url && (
                        <LinkRow label="Issue" url={(vuln as any).issue_url} />
                      )}
                      {(vuln as any).email_chain_url && (
                        <LinkRow label="Email Chain" url={(vuln as any).email_chain_url} />
                      )}
                      {!vuln.advisory_url && !(vuln as any).issue_url && !(vuln as any).email_chain_url && (
                        <span style={{ color: 'var(--muted)', fontSize: 13 }}>No links recorded.</span>
                      )}
                    </div>
                  </Field>

                  {/* Maintainer response */}
                  {(vuln as any).response && (
                    <Field label="Maintainer Response">
                      <InfoBox color="var(--green)">{(vuln as any).response}</InfoBox>
                    </Field>
                  )}

                  {(vuln as any).rejection_reason && (
                    <Field label="Rejection Reason">
                      <InfoBox color="var(--red)">{(vuln as any).rejection_reason}</InfoBox>
                    </Field>
                  )}

                  {/* Editable notes */}
                  <Field label="Notes">
                    {editing ? (
                      <textarea
                        value={(editData as any).notes ?? (vuln as any).notes ?? ''}
                        onChange={e => setEditData(p => ({ ...p, notes: e.target.value } as any))}
                        style={{ ...inputStyle, minHeight: 80, resize: 'vertical' }}
                        placeholder="Add notes about this finding..."
                      />
                    ) : (
                      <div style={{ fontSize: 13, color: (vuln as any).notes ? 'var(--text)' : 'var(--muted)', lineHeight: 1.6 }}>
                        {(vuln as any).notes ?? 'No notes. Click Edit to add notes.'}
                      </div>
                    )}
                  </Field>
                </div>
              )}
            </div>
          </>
        )}
      </div>

      {/* "View file in full" modal - opened from the Suggested Fix
          section so users can see the fix in its surrounding context. */}
      {fileViewerOpen && vuln?.file && (vuln as any).project_id && (
        <FileViewerModal
          projectId={(vuln as any).project_id}
          path={vuln.file}
          lineStart={vuln.line_start ?? null}
          lineEnd={vuln.line_end ?? null}
          onClose={() => setFileViewerOpen(false)}
        />
      )}

      <style>{`
        @keyframes slideInRight {
          from { transform: translateX(40px); opacity: 0; }
          to   { transform: translateX(0);    opacity: 1; }
        }
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
        @keyframes shimmer {
          0%   { opacity: 0.4; }
          50%  { opacity: 0.7; }
          100% { opacity: 0.4; }
        }
      `}</style>
    </div>
  );
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function MetaCard({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, padding: '10px 12px' }}>
      <div style={fieldLabelStyle}>{label}</div>
      {value}
    </div>
  );
}

function ConfidenceBadge({ value }: { value: number }) {
  const pct = value <= 1 ? Math.round(value * 100) : Math.round(value);
  const label = pct >= 75 ? 'High' : pct >= 40 ? 'Medium' : 'Low';
  const color = pct >= 75 ? 'var(--green)' : pct >= 40 ? 'var(--yellow)' : 'var(--red)';
  return (
    <span style={{ fontSize: 12, color, fontWeight: 600 }}>{label} ({pct}%)</span>
  );
}

function TimelineItem({ date, label, color, active }: { date?: string | null; label: string; color: string; active: boolean }) {
  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12, paddingBottom: 16 }}>
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0 }}>
        <div style={{
          width: 12,
          height: 12,
          borderRadius: '50%',
          background: active ? color : 'var(--border)',
          border: `2px solid ${active ? color : 'var(--border)'}`,
          marginTop: 2,
        }} />
        <div style={{ width: 1, height: 20, background: 'var(--border)', marginTop: 2 }} />
      </div>
      <div>
        <div style={{ fontSize: 12, fontWeight: 600, color: active ? 'var(--text)' : 'var(--muted)' }}>{label}</div>
        <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>
          {date ? new Date(date).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }) : 'Not yet'}
        </div>
      </div>
    </div>
  );
}

function LinkRow({ label, url }: { label: string; url: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      <span style={{ fontSize: 11, color: 'var(--muted)', width: 80, flexShrink: 0 }}>{label}</span>
      <a href={url} target="_blank" rel="noreferrer" style={{ fontSize: 12, color: 'var(--blue)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {url}
      </a>
    </div>
  );
}

// ── Styles ─────────────────────────────────────────────────────────────────────

const fieldLabelStyle: React.CSSProperties = {
  fontSize: 10,
  color: 'var(--muted)',
  textTransform: 'uppercase',
  letterSpacing: '0.6px',
  fontWeight: 600,
  marginBottom: 2,
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
  background: 'var(--surface-2)',
  border: '1px solid var(--border)',
  borderRadius: 5,
  padding: '4px 8px',
  color: 'var(--text)',
  fontSize: 12,
  outline: 'none',
  cursor: 'pointer',
};

const reportPreStyle: React.CSSProperties = {
  background: 'var(--bg)',
  border: '1px solid var(--border)',
  borderRadius: 6,
  padding: 16,
  fontSize: 12,
  overflow: 'auto',
  margin: 0,
  color: 'var(--text)',
  lineHeight: 1.6,
  fontFamily: 'monospace',
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-word',
  maxHeight: 480,
};

function actionBtn(bg: string): React.CSSProperties {
  return {
    background: bg,
    border: '1px solid var(--border)',
    borderRadius: 5,
    padding: '6px 12px',
    color: 'var(--text)',
    fontSize: 12,
    fontWeight: 500,
    cursor: 'pointer',
    whiteSpace: 'nowrap',
  };
}

function copyBtnStyle(copied: boolean): React.CSSProperties {
  return {
    background: copied ? 'var(--green)22' : 'var(--surface-2)',
    border: '1px solid var(--border)',
    borderRadius: 4,
    padding: '3px 10px',
    color: copied ? 'var(--green)' : 'var(--muted)',
    fontSize: 11,
    cursor: 'pointer',
    flexShrink: 0,
    whiteSpace: 'nowrap',
  };
}

// ── Exploits Tab ──────────────────────────────────────────────────────────────

function ExploitsTab({ findingId }: { findingId: number }) {
  const [exploits, setExploits] = useState<Exploit[]>([]);
  const [ladder, setLadder] = useState<ProofLadder | null>(null);
  const { toast } = useToast();

  useEffect(() => {
    listExploits({ finding_id: findingId }).then(r => setExploits(r.data)).catch(() => {});
    getProofLadder(findingId).then(setLadder).catch(() => {});
  }, [findingId]);

  const TIERS = ['pattern', 'manual', 'traced', 'poc', 'weaponized'] as const;
  const TIER_COLORS: Record<string, string> = {
    pattern: 'var(--muted)', manual: 'var(--blue)', traced: 'var(--yellow)',
    poc: 'var(--orange)', weaponized: 'var(--red)',
  };

  const advanceTier = async (tier: string) => {
    try {
      const updated = await setProofTier(findingId, tier);
      setLadder(updated);
      toast(`Advanced to ${tier}`, 'success');
    } catch (err: any) { toast(err.message, 'error'); }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Proof Ladder */}
      <div>
        <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 8 }}>
          Proof Ladder
        </div>
        <div style={{ display: 'flex', gap: 4 }}>
          {TIERS.map((t, i) => {
            const current = TIERS.indexOf((ladder?.current_tier || 'pattern') as any);
            const active = i <= current;
            return (
              <button key={t} onClick={() => advanceTier(t)} style={{
                flex: 1, padding: '8px 4px', borderRadius: 4, fontSize: 10, fontWeight: 600,
                textTransform: 'uppercase', cursor: 'pointer',
                background: active ? `${TIER_COLORS[t]}22` : 'var(--bg)',
                color: active ? TIER_COLORS[t] : 'var(--muted)',
                border: `1px solid ${active ? TIER_COLORS[t] : 'var(--border)'}`,
              }}>{t}</button>
            );
          })}
        </div>
      </div>

      {/* Exploits list */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
          <span style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
            Exploits ({exploits.length})
          </span>
          <button onClick={async () => {
            try {
              await createExploit({ title: `PoC for finding #${findingId}`, finding_id: findingId });
              const r = await listExploits({ finding_id: findingId });
              setExploits(r.data);
              toast('Exploit created', 'success');
            } catch (err: any) { toast(err.message, 'error'); }
          }} style={{
            padding: '4px 10px', fontSize: 10, fontWeight: 600, cursor: 'pointer',
            background: 'var(--green)22', color: 'var(--green)',
            border: '1px solid var(--green)44', borderRadius: 4,
          }}>+ New Exploit</button>
        </div>
        {exploits.length === 0 ? (
          <div style={{ color: 'var(--muted)', fontSize: 12, padding: 16, textAlign: 'center', border: '1px dashed var(--border)', borderRadius: 6 }}>
            No exploits yet. Create one to start building a PoC.
          </div>
        ) : (
          exploits.map(e => (
            <div key={e.id} style={{
              padding: '10px 12px', marginBottom: 6,
              background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6,
              borderLeft: `3px solid ${TIER_COLORS[e.tier] || 'var(--muted)'}`,
            }}>
              <div style={{ color: 'var(--text)', fontSize: 13, fontWeight: 600 }}>{e.title}</div>
              <div style={{ color: 'var(--muted)', fontSize: 11, marginTop: 2 }}>
                {e.language} · {e.tier} · updated {e.updated_at?.split('T')[0] || ''}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

// ── Runtime Tab ──────────────────────────────────────────────────────────────

function RuntimeTab({ findingId }: { findingId: number }) {
  const [jobs, setJobs] = useState<RuntimeJob[]>([]);
  const [crashes, setCrashes] = useState<FuzzCrash[]>([]);

  useEffect(() => {
    listRuntimeJobs({ finding_id: findingId }).then(r => setJobs(r.data)).catch(() => {});
  }, [findingId]);

  // Load crashes from any fuzz jobs linked to this finding
  useEffect(() => {
    const fuzzJobs = jobs.filter(j => j.type === 'fuzz');
    if (fuzzJobs.length > 0) {
      Promise.all(fuzzJobs.map(j => listCrashes(j.id).catch(() => ({ data: [] }))))
        .then(results => setCrashes(results.flatMap(r => r.data)));
    }
  }, [jobs]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
        Runtime Jobs for this Finding ({jobs.length})
      </div>

      {jobs.length === 0 ? (
        <div style={{ color: 'var(--muted)', fontSize: 12, padding: 16, textAlign: 'center', border: '1px dashed var(--border)', borderRadius: 6 }}>
          No runtime jobs linked. Start a fuzz campaign, debug session, or sandbox from the Runtime page.
        </div>
      ) : (
        jobs.map(j => (
          <div key={j.id} style={{
            padding: '10px 12px', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6,
            display: 'flex', gap: 10, alignItems: 'center',
          }}>
            <span style={{
              padding: '2px 8px', borderRadius: 10,
              background: j.status === 'completed' ? 'var(--green)22' : j.status === 'running' ? 'var(--blue)22' : 'var(--muted)22',
              color: j.status === 'completed' ? 'var(--green)' : j.status === 'running' ? 'var(--blue)' : 'var(--muted)',
              fontSize: 10, fontWeight: 600, textTransform: 'uppercase',
            }}>{j.status}</span>
            <span style={{ color: 'var(--text)', fontSize: 13 }}>{j.type}/{j.tool}</span>
            <span style={{ color: 'var(--muted)', fontSize: 11, marginLeft: 'auto' }}>{j.started_at?.split('T')[0]}</span>
          </div>
        ))
      )}

      {crashes.length > 0 && (
        <div>
          <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 6 }}>
            Fuzz Crashes ({crashes.length})
          </div>
          {crashes.slice(0, 5).map(c => (
            <div key={c.id} style={{
              padding: '6px 10px', marginBottom: 4,
              background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 4,
              fontSize: 11, display: 'flex', gap: 8,
            }}>
              <span style={{ color: c.exploitability === 'high' ? 'var(--red)' : 'var(--muted)', fontWeight: 600 }}>
                {c.exploitability}
              </span>
              <span style={{ color: 'var(--text)' }}>{c.signal || 'unknown'}</span>
              <span style={{ color: 'var(--muted)', fontFamily: 'monospace' }}>{c.stack_hash?.slice(0, 12)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Disclosure Tab ────────────────────────────────────────────────────────────

function DisclosureTab({ findingId, vulnTitle }: { findingId: number; vulnTitle: string }) {
  const [disclosures, setDisclosures] = useState<Disclosure[]>([]);
  const { toast } = useToast();

  useEffect(() => {
    listDisclosures({ finding_id: findingId }).then(r => setDisclosures(r.data)).catch(() => {});
  }, [findingId]);

  const STATUS_COLORS: Record<string, string> = {
    draft: 'var(--muted)', submitted: 'var(--blue)', acknowledged: 'var(--purple)',
    fixed: 'var(--yellow)', resolved: 'var(--green)', public: 'var(--green)', cancelled: 'var(--muted)',
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
          Disclosures ({disclosures.length})
        </span>
        <button onClick={async () => {
          try {
            await createDisclosure({ title: `Disclosure: ${vulnTitle}`, finding_id: findingId, status: 'draft' });
            const r = await listDisclosures({ finding_id: findingId });
            setDisclosures(r.data);
            toast('Disclosure created', 'success');
          } catch (err: any) { toast(err.message, 'error'); }
        }} style={{
          padding: '4px 10px', fontSize: 10, fontWeight: 600, cursor: 'pointer',
          background: 'var(--orange)22', color: 'var(--orange)',
          border: '1px solid var(--orange)44', borderRadius: 4,
        }}>+ New Disclosure</button>
      </div>

      {disclosures.length === 0 ? (
        <div style={{ color: 'var(--muted)', fontSize: 12, padding: 16, textAlign: 'center', border: '1px dashed var(--border)', borderRadius: 6 }}>
          No disclosures yet. File one when the finding is verified and ready.
        </div>
      ) : (
        disclosures.map(d => (
          <div key={d.id} style={{
            padding: '12px 14px', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <span style={{
                padding: '2px 8px', borderRadius: 10, fontSize: 10, fontWeight: 600, textTransform: 'uppercase',
                background: `${STATUS_COLORS[d.status]}22`, color: STATUS_COLORS[d.status],
              }}>{d.status}</span>
              <span style={{ color: 'var(--text)', fontSize: 13, fontWeight: 600 }}>{d.title}</span>
            </div>
            <div style={{ display: 'flex', gap: 16, fontSize: 11, color: 'var(--muted)' }}>
              {d.cve_id && <span>CVE: {d.cve_id}</span>}
              {d.sla_days_remaining !== undefined && d.sla_days_remaining !== null && (
                <span style={{
                  color: d.sla_status === 'overdue' ? 'var(--red)' : d.sla_status === 'warning' ? 'var(--yellow)' : 'var(--green)',
                }}>
                  {d.sla_days_remaining < 0 ? `${Math.abs(d.sla_days_remaining)}d overdue` : `${d.sla_days_remaining}d left`}
                </span>
              )}
              {d.bounty_amount && <span style={{ color: 'var(--green)' }}>${d.bounty_amount}</span>}
            </div>
          </div>
        ))
      )}
    </div>
  );
}

// ── Slide-over wrapper (replaces the old modal) ───────────────────────────────

export function FindingDetailModal({ vulnId, onClose }: FindingDetailProps) {
  if (vulnId == null) return null;
  return <FindingDetail vulnId={vulnId} onClose={onClose} />;
}
