import { useState, useEffect, useCallback } from 'react';
import {
  listRuntimeJobs,
  getRuntimeJob,
  startRuntimeJob,
  stopRuntimeJob,
  deleteRuntimeJob,
  getRuntimeJobOutput,
  listCrashes,
  type RuntimeJob,
  type FuzzCrash,
} from '@/lib/api';
import { useToast } from '@/components/Toast';

type SubTab = 'all' | 'fuzz' | 'debug' | 'capture' | 'portscan' | 'sandbox';

const TAB_FILTERS: Record<SubTab, string | undefined> = {
  all: undefined,
  fuzz: 'fuzz',
  debug: 'debug',
  capture: 'capture',
  portscan: 'portscan',
  sandbox: 'sandbox',
};

const TAB_LABELS: Record<SubTab, string> = {
  all: 'All',
  fuzz: 'Fuzzing',
  debug: 'Debugging',
  capture: 'Network',
  portscan: 'Port Scans',
  sandbox: 'Sandboxes',
};

function statusColor(status: string): string {
  switch (status) {
    case 'running': return 'var(--blue)';
    case 'completed': return 'var(--green)';
    case 'failed': return 'var(--red)';
    case 'cancelled': return 'var(--muted)';
    case 'queued': return 'var(--yellow)';
    default: return 'var(--muted)';
  }
}

function relativeTime(iso: string): string {
  if (!iso) return '—';
  const diff = Date.now() - new Date(iso).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export default function Runtime() {
  const { toast } = useToast() as { toast: (msg: string, type?: 'success' | 'error' | 'info') => void };
  const [tab, setTab] = useState<SubTab>('all');
  const [jobs, setJobs] = useState<RuntimeJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedJobId, setExpandedJobId] = useState<string | null>(null);
  const [newJobOpen, setNewJobOpen] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await listRuntimeJobs({ type: TAB_FILTERS[tab] });
      setJobs(res.data);
    } catch (err: any) {
      toast(`Failed to load: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  }, [tab, toast]);

  useEffect(() => { load(); }, [load]);

  // Auto-refresh every 3s for running jobs
  useEffect(() => {
    const hasRunning = jobs.some(j => j.status === 'running' || j.status === 'queued');
    if (!hasRunning) return;
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, [jobs, load]);

  const handleStop = async (id: string) => {
    try {
      await stopRuntimeJob(id);
      toast('Job stopped', 'info');
      load();
    } catch (err: any) {
      toast(err.message, 'error');
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this job and all its output?')) return;
    try {
      await deleteRuntimeJob(id);
      toast('Job deleted', 'info');
      load();
    } catch (err: any) {
      toast(err.message, 'error');
    }
  };

  return (
    <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h2 style={{ fontSize: 20, fontWeight: 700, margin: 0, color: 'var(--text)' }}>Runtime Analysis</h2>
          <p style={{ fontSize: 12, color: 'var(--muted)', margin: '4px 0 0' }}>
            Fuzzing, debugging, packet capture, port scans — all runtime tools unified.
          </p>
        </div>
        <button
          onClick={() => setNewJobOpen(true)}
          style={{
            background: 'var(--green)', color: '#000', border: 'none',
            borderRadius: 6, padding: '8px 16px', fontSize: 13, fontWeight: 700, cursor: 'pointer',
          }}
        >
          + New Job
        </button>
      </div>

      {/* Sub-tabs */}
      <div style={{ display: 'flex', gap: 4, borderBottom: '1px solid var(--border)' }}>
        {(Object.keys(TAB_LABELS) as SubTab[]).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            style={{
              background: 'none',
              border: 'none',
              borderBottom: `2px solid ${tab === t ? 'var(--blue)' : 'transparent'}`,
              color: tab === t ? 'var(--text)' : 'var(--muted)',
              padding: '8px 14px',
              fontSize: 13,
              fontWeight: tab === t ? 600 : 400,
              cursor: 'pointer',
            }}
          >
            {TAB_LABELS[t]}
          </button>
        ))}
      </div>

      {/* Jobs table */}
      {loading ? (
        <div style={{ padding: 24, textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>Loading...</div>
      ) : jobs.length === 0 ? (
        <div style={{
          padding: 40, textAlign: 'center', color: 'var(--muted)', fontSize: 13,
          border: '1px dashed var(--border)', borderRadius: 8,
        }}>
          No {TAB_LABELS[tab].toLowerCase()} jobs yet. Click "+ New Job" to start one.
        </div>
      ) : (
        <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['Status', 'Type / Tool', 'Started', 'Progress', 'Actions'].map(h => (
                  <th key={h} style={{
                    textAlign: 'left', padding: '10px 14px',
                    color: 'var(--muted)', fontSize: 11, fontWeight: 600,
                    textTransform: 'uppercase', letterSpacing: 0.5,
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {jobs.map(job => (
                <>
                  <tr
                    key={job.id}
                    style={{ borderBottom: '1px solid var(--border)', cursor: 'pointer' }}
                    onClick={() => setExpandedJobId(expandedJobId === job.id ? null : job.id)}
                  >
                    <td style={{ padding: '10px 14px' }}>
                      <span style={{
                        display: 'inline-block', padding: '2px 8px', borderRadius: 10,
                        background: `${statusColor(job.status)}22`, color: statusColor(job.status),
                        fontSize: 10, fontWeight: 600, textTransform: 'uppercase',
                      }}>{job.status}</span>
                    </td>
                    <td style={{ padding: '10px 14px', color: 'var(--text)' }}>
                      <div style={{ fontWeight: 600 }}>{job.type}</div>
                      <div style={{ fontSize: 11, color: 'var(--muted)' }}>{job.tool}</div>
                    </td>
                    <td style={{ padding: '10px 14px', color: 'var(--muted)', fontSize: 11 }}>
                      {relativeTime(job.started_at)}
                    </td>
                    <td style={{ padding: '10px 14px', color: 'var(--muted)', fontSize: 11, fontFamily: 'monospace' }}>
                      <StatsSummary job={job} />
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      <div style={{ display: 'flex', gap: 6 }}>
                        {job.type === 'sandbox' && job.status === 'running' && (
                          <button onClick={async (e) => {
                            e.stopPropagation();
                            const { pauseSandbox } = await import('@/lib/api');
                            await pauseSandbox(job.id);
                            load();
                          }} style={smallBtn('var(--blue)')}>Pause</button>
                        )}
                        {job.type === 'sandbox' && job.status === 'paused' && (
                          <button onClick={async (e) => {
                            e.stopPropagation();
                            const { resumeSandbox } = await import('@/lib/api');
                            await resumeSandbox(job.id);
                            load();
                          }} style={smallBtn('var(--green)')}>Resume</button>
                        )}
                        {(job.status === 'running' || job.status === 'queued') && (
                          <button onClick={(e) => { e.stopPropagation(); handleStop(job.id); }}
                            style={smallBtn('var(--yellow)')}>Stop</button>
                        )}
                        {(job.status === 'completed' || job.status === 'failed' || job.status === 'cancelled') && (
                          <button onClick={(e) => { e.stopPropagation(); handleDelete(job.id); }}
                            style={smallBtn('var(--red)')}>Delete</button>
                        )}
                      </div>
                    </td>
                  </tr>
                  {expandedJobId === job.id && (
                    <tr key={`${job.id}-detail`}>
                      <td colSpan={5} style={{ padding: 0, background: 'var(--bg)' }}>
                        <JobDetail job={job} />
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {newJobOpen && <NewJobModal onClose={() => setNewJobOpen(false)} onCreated={() => { setNewJobOpen(false); load(); }} />}
    </div>
  );
}

// ── Stats summary (inline) ─────────────────────────────────────────────────

function StatsSummary({ job }: { job: RuntimeJob }) {
  const stats = job.stats || {};

  if (job.type === 'fuzz') {
    return <>
      {stats.exec_count ? `${stats.exec_count.toLocaleString()} execs` : 'queued'}
      {stats.exec_per_sec ? ` · ${stats.exec_per_sec}/s` : ''}
      {stats.coverage ? ` · cov ${stats.coverage}` : ''}
      {stats.crashes ? ` · ${stats.crashes} crashes` : ''}
    </>;
  }

  if (job.type === 'capture') {
    return <>
      {stats.packet_count ? `${stats.packet_count} packets` : '—'}
      {stats.bytes ? ` · ${formatBytes(stats.bytes)}` : ''}
    </>;
  }

  if (job.type === 'portscan') {
    return <>
      {stats.open_ports !== undefined ? `${stats.open_ports} open / ${stats.total_ports || 0}` : '—'}
      {stats.up_hosts !== undefined ? ` · ${stats.up_hosts} up` : ''}
    </>;
  }

  if (job.type === 'debug') {
    return <>
      {stats.hit_breakpoint !== undefined ? (stats.hit_breakpoint ? 'breakpoint hit' : 'no hit') : '—'}
      {stats.signal ? ` · ${stats.signal}` : ''}
    </>;
  }

  if (job.type === 'sandbox') {
    return <>
      {stats.image || stats.sandbox_type || 'docker'}
      {stats.cpu_percent !== undefined ? ` · CPU ${stats.cpu_percent.toFixed(1)}%` : ''}
      {stats.memory_mb ? ` · ${stats.memory_mb.toFixed(0)}MB` : ''}
      {stats.paused ? ' · PAUSED' : ''}
      {stats.uptime_seconds ? ` · ${Math.floor(stats.uptime_seconds / 60)}m` : ''}
    </>;
  }

  return <>—</>;
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n}B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)}MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(1)}GB`;
}

// ── Job detail (expanded row) ──────────────────────────────────────────────

function JobDetail({ job }: { job: RuntimeJob }) {
  const [output, setOutput] = useState<string>('');
  const [crashes, setCrashes] = useState<FuzzCrash[]>([]);

  useEffect(() => {
    getRuntimeJobOutput(job.id, 200).then(setOutput).catch(() => {});
    if (job.type === 'fuzz') {
      listCrashes(job.id).then(r => setCrashes(r.data)).catch(() => {});
    }
    // refresh while running
    if (job.status === 'running') {
      const t = setInterval(() => {
        getRuntimeJobOutput(job.id, 200).then(setOutput).catch(() => {});
        if (job.type === 'fuzz') listCrashes(job.id).then(r => setCrashes(r.data)).catch(() => {});
      }, 3000);
      return () => clearInterval(t);
    }
  }, [job.id, job.status, job.type]);

  return (
    <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
      {/* Config */}
      <div>
        <div style={{ fontSize: 10, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 4 }}>Config</div>
        <pre style={{
          margin: 0, padding: 10, background: 'var(--surface)', border: '1px solid var(--border)',
          borderRadius: 4, fontSize: 11, color: 'var(--text)', fontFamily: 'monospace',
          overflow: 'auto', maxHeight: 120,
        }}>{JSON.stringify(job.config, null, 2)}</pre>
      </div>

      {/* Crashes (fuzz only) */}
      {job.type === 'fuzz' && crashes.length > 0 && (
        <div>
          <div style={{ fontSize: 10, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 4 }}>
            Crashes ({crashes.length})
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {crashes.slice(0, 10).map(c => (
              <div key={c.id} style={{
                padding: '6px 10px', background: 'var(--surface)', border: '1px solid var(--border)',
                borderRadius: 4, fontSize: 11, display: 'flex', gap: 10, alignItems: 'center',
              }}>
                <span style={{ color: c.exploitability === 'high' ? 'var(--red)' : c.exploitability === 'medium' ? 'var(--orange)' : 'var(--muted)', fontWeight: 600, textTransform: 'uppercase' }}>
                  {c.exploitability}
                </span>
                <span style={{ color: 'var(--text)' }}>{c.signal || 'unknown'}</span>
                <span style={{ color: 'var(--muted)', fontFamily: 'monospace' }}>{c.stack_hash}</span>
                <span style={{ color: 'var(--muted)', fontSize: 10, marginLeft: 'auto' }}>{c.input_size}B</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Output log */}
      <div>
        <div style={{ fontSize: 10, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 4 }}>
          Recent Output {job.status === 'running' ? '(live)' : ''}
        </div>
        <pre style={{
          margin: 0, padding: 10, background: '#000', color: '#0f0',
          borderRadius: 4, fontSize: 10, fontFamily: 'monospace',
          overflow: 'auto', maxHeight: 280, whiteSpace: 'pre-wrap',
        }}>{output || '(no output yet)'}</pre>
      </div>

      {/* Error */}
      {job.error && (
        <div style={{ padding: 10, background: 'var(--red)22', border: '1px solid var(--red)44', borderRadius: 4, fontSize: 12, color: 'var(--red)' }}>
          <strong>Error:</strong> {job.error}
        </div>
      )}
    </div>
  );
}

// ── New Job modal ──────────────────────────────────────────────────────────

function NewJobModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const { toast } = useToast() as { toast: (msg: string, type?: 'success' | 'error' | 'info') => void };
  const [jobType, setJobType] = useState<'fuzz' | 'debug' | 'capture' | 'portscan'>('fuzz');
  const [submitting, setSubmitting] = useState(false);
  const [formData, setFormData] = useState<Record<string, any>>({});

  const update = (key: string, val: any) => setFormData(prev => ({ ...prev, [key]: val }));

  const TOOL_MAP: Record<string, string> = { fuzz: 'libfuzzer', debug: 'gdb', capture: 'tcpdump', portscan: 'nmap', sandbox: 'docker' };

  const handleSubmit = async () => {
    setSubmitting(true);
    try {
      const tool = TOOL_MAP[jobType];
      await startRuntimeJob({ type: jobType, tool, config: formData });
      toast('Job started', 'success');
      onCreated();
    } catch (err: any) {
      toast(err.message, 'error');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div style={{
      position: 'fixed', inset: 0, background: '#0008', zIndex: 1000,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={onClose}>
      <div style={{
        background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 10,
        padding: 24, width: '90%', maxWidth: 560, maxHeight: '80vh', overflow: 'auto',
      }} onClick={e => e.stopPropagation()}>
        <h3 style={{ margin: '0 0 16px', color: 'var(--text)', fontSize: 16 }}>New Runtime Job</h3>

        {/* Type selector */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 8, marginBottom: 16 }}>
          {(['fuzz', 'debug', 'capture', 'portscan', 'sandbox'] as const).map(t => (
            <button
              key={t}
              onClick={() => { setJobType(t); setFormData({}); }}
              style={{
                padding: '10px 8px', borderRadius: 6, cursor: 'pointer', fontSize: 12, fontWeight: 600,
                background: jobType === t ? 'var(--blue)22' : 'var(--bg)',
                border: `1px solid ${jobType === t ? 'var(--blue)' : 'var(--border)'}`,
                color: jobType === t ? 'var(--blue)' : 'var(--text)',
              }}
            >
              {t}
            </button>
          ))}
        </div>

        {/* Type-specific form */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 16 }}>
          {jobType === 'fuzz' && <>
            <Field label="Harness path (libFuzzer binary)" required>
              <input value={formData.harness_path || ''} onChange={e => update('harness_path', e.target.value)}
                placeholder="/path/to/fuzz_target" style={inputStyle} />
            </Field>
            <Field label="Corpus directory (optional)">
              <input value={formData.corpus_dir || ''} onChange={e => update('corpus_dir', e.target.value)}
                placeholder="auto-created under job output dir" style={inputStyle} />
            </Field>
            <Field label="Max time (seconds, default 300)">
              <input type="number" value={formData.max_total_time || ''} onChange={e => update('max_total_time', Number(e.target.value) || undefined)} style={inputStyle} />
            </Field>
          </>}

          {jobType === 'debug' && <>
            <Field label="Binary path" required>
              <input value={formData.binary_path || ''} onChange={e => update('binary_path', e.target.value)} style={inputStyle} />
            </Field>
            <Field label="Breakpoint (file:line or function)">
              <input value={formData.breakpoint || ''} onChange={e => update('breakpoint', e.target.value)}
                placeholder="src/parser.c:234" style={inputStyle} />
            </Field>
            <Field label="Program args (space-separated)">
              <input value={(formData.args || []).join(' ')} onChange={e => update('args', e.target.value.split(/\s+/).filter(Boolean))} style={inputStyle} />
            </Field>
            <Field label="Check expression at breakpoint">
              <input value={formData.check_expr || ''} onChange={e => update('check_expr', e.target.value)} style={inputStyle} />
            </Field>
            <Field label="Core dump path (alternative to live debug)">
              <input value={formData.core_path || ''} onChange={e => update('core_path', e.target.value)} style={inputStyle} />
            </Field>
          </>}

          {jobType === 'capture' && <>
            <Field label="Interface" required>
              <input value={formData.interface || 'any'} onChange={e => update('interface', e.target.value)}
                placeholder="eth0, lo, any" style={inputStyle} />
            </Field>
            <Field label="BPF filter (optional)">
              <input value={formData.filter || ''} onChange={e => update('filter', e.target.value)}
                placeholder="port 443" style={inputStyle} />
            </Field>
            <Field label="Duration (seconds)">
              <input type="number" value={formData.duration || 60} onChange={e => update('duration', Number(e.target.value))} style={inputStyle} />
            </Field>
            <Field label="Max packets (optional)">
              <input type="number" value={formData.max_packets || ''} onChange={e => update('max_packets', Number(e.target.value) || undefined)} style={inputStyle} />
            </Field>
          </>}

          {jobType === 'portscan' && <>
            <Field label="Target" required>
              <input value={formData.target || ''} onChange={e => update('target', e.target.value)}
                placeholder="192.168.1.0/24 or hostname.com" style={inputStyle} />
            </Field>
            <Field label="Ports">
              <input value={formData.ports || '1-1000'} onChange={e => update('ports', e.target.value)} style={inputStyle} />
            </Field>
            <Field label="Scan type">
              <select value={formData.scan_type || 'version'} onChange={e => update('scan_type', e.target.value)} style={inputStyle}>
                <option value="connect">Connect (no root)</option>
                <option value="version">Version detection</option>
                <option value="script">Default scripts</option>
                <option value="syn">SYN (requires root)</option>
                <option value="udp">UDP</option>
              </select>
            </Field>
            <Field label="Timing (0-5)">
              <input type="number" min={0} max={5} value={formData.timing ?? 3} onChange={e => update('timing', Number(e.target.value))} style={inputStyle} />
            </Field>
          </>}

          {jobType === 'sandbox' && <>
            <Field label="Docker image" required>
              <input value={formData.image || 'ubuntu:22.04'} onChange={e => update('image', e.target.value)}
                placeholder="ubuntu:22.04, kalilinux/kali, python:3.12" style={inputStyle} />
            </Field>
            <Field label="Command (optional)">
              <input value={(formData.command || []).join(' ')} onChange={e => update('command', e.target.value.split(/\s+/).filter(Boolean))}
                placeholder="sleep 3600 (default: image entrypoint)" style={inputStyle} />
            </Field>
            <Field label="Memory limit">
              <input value={formData.memory_limit || '512m'} onChange={e => update('memory_limit', e.target.value)}
                placeholder="512m, 1g, 2g" style={inputStyle} />
            </Field>
            <Field label="CPU limit">
              <input type="number" step={0.5} value={formData.cpu_limit ?? 2} onChange={e => update('cpu_limit', Number(e.target.value) || undefined)} style={inputStyle} />
            </Field>
            <Field label="Network mode">
              <select value={formData.network_mode || 'bridge'} onChange={e => update('network_mode', e.target.value)} style={inputStyle}>
                <option value="bridge">Bridge (isolated, recommended)</option>
                <option value="host">Host (full host network access)</option>
                <option value="none">None (no network)</option>
              </select>
            </Field>
            <Field label="Timeout (seconds, 0 = unlimited)">
              <input type="number" value={formData.timeout ?? 0} onChange={e => update('timeout', Number(e.target.value))} style={inputStyle} />
            </Field>
          </>}
        </div>

        {/* Actions */}
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button onClick={onClose} style={{
            padding: '8px 16px', background: 'var(--surface-2)', color: 'var(--text)',
            border: '1px solid var(--border)', borderRadius: 5, cursor: 'pointer', fontSize: 13,
          }}>Cancel</button>
          <button onClick={handleSubmit} disabled={submitting} style={{
            padding: '8px 20px', background: 'var(--green)', color: '#000',
            border: 'none', borderRadius: 5, cursor: 'pointer', fontSize: 13, fontWeight: 700,
            opacity: submitting ? 0.6 : 1,
          }}>{submitting ? 'Starting...' : 'Start Job'}</button>
        </div>
      </div>
    </div>
  );
}

function Field({ label, required, children }: { label: string; required?: boolean; children: React.ReactNode }) {
  return (
    <div>
      <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>
        {label}{required ? ' *' : ''}
      </label>
      {children}
    </div>
  );
}

function smallBtn(color: string): React.CSSProperties {
  return {
    padding: '4px 10px', fontSize: 11, fontWeight: 600, cursor: 'pointer',
    background: `${color}22`, color, border: `1px solid ${color}66`, borderRadius: 4,
  };
}

const inputStyle: React.CSSProperties = {
  width: '100%', padding: '8px 10px', background: 'var(--bg)',
  border: '1px solid var(--border)', borderRadius: 5, color: 'var(--text)',
  fontSize: 13, outline: 'none', boxSizing: 'border-box', fontFamily: 'inherit',
};
