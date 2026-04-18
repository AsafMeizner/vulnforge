import { useState, useEffect, useCallback, Fragment } from 'react';
import {
  listRuntimeJobs,
  getRuntimeJob,
  startRuntimeJob,
  stopRuntimeJob,
  deleteRuntimeJob,
  getRuntimeJobOutput,
  listCrashes,
  generateHarness,
  apiFetch,
  type RuntimeJob,
  type FuzzCrash,
} from '@/lib/api';
import { useToast } from '@/components/Toast';
import { HelpIcon } from '@/components/HelpIcon';
import { FolderPickerInput } from '@/components/FolderPickerInput';

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
  if (!iso) return '-';
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
  const { toast } = useToast() as { toast: (a: string, b?: string) => void };
  const [tab, setTab] = useState<SubTab>('all');
  const [jobs, setJobs] = useState<RuntimeJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedJobId, setExpandedJobId] = useState<string | null>(null);
  const [newJobOpen, setNewJobOpen] = useState(false);
  // Prefill state for "Clone job": when the user hits the clone button
  // on a completed/failed row, we copy its type + config into this
  // state and open the New Job modal. null = start blank.
  const [cloneFrom, setCloneFrom] = useState<{ type: string; config: Record<string, any> } | null>(null);

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
            Fuzzing, debugging, packet capture, port scans - all runtime tools unified.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={async () => {
              const sig = prompt('Function signature (e.g. "int parse(uint8_t *data, size_t len)"):');
              if (!sig) return;
              try {
                const result = await generateHarness(sig, 'c');
                alert(`Generated harness:\n\n${result.harness_code}\n\nNotes: ${result.notes.join(', ')}`);
              } catch (err: any) { toast(err.message, 'error'); }
            }}
            style={{
              background: 'var(--purple)', color: '#fff', border: 'none',
              borderRadius: 6, padding: '8px 14px', fontSize: 12, fontWeight: 600, cursor: 'pointer',
            }}
          >
            Generate Harness
          </button>
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
                // The outer iteration element needs the React key - without
                // it React warns every render and reconciliation is wrong
                // for the expanded-detail row (the inner <tr key={job.id}>
                // used to be the key holder but a fragment parent gets
                // ignored).
                <Fragment key={job.id}>
                  <tr
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
                          <>
                            {/* Clone: pre-fill New Job modal with this
                                job's type + config so the user can
                                tweak a single field and relaunch
                                without re-entering everything. */}
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                let cfg: Record<string, any> = {};
                                try {
                                  cfg = typeof (job as any).config === 'string'
                                    ? JSON.parse((job as any).config)
                                    : ((job as any).config || {});
                                } catch { cfg = {}; }
                                setCloneFrom({ type: job.type, config: cfg });
                                setNewJobOpen(true);
                              }}
                              title="Clone this job's config into a new run"
                              style={smallBtn('var(--blue)')}
                            >
                              Clone
                            </button>
                            <button onClick={(e) => { e.stopPropagation(); handleDelete(job.id); }}
                              style={smallBtn('var(--red)')}>Delete</button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                  {expandedJobId === job.id && (
                    <tr>
                      <td colSpan={5} style={{ padding: 0, background: 'var(--bg)' }}>
                        <JobDetail job={job} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {newJobOpen && (
        <NewJobModal
          initial={cloneFrom}
          onClose={() => { setNewJobOpen(false); setCloneFrom(null); }}
          onCreated={() => { setNewJobOpen(false); setCloneFrom(null); load(); }}
        />
      )}
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
      {stats.packet_count ? `${stats.packet_count} packets` : '-'}
      {stats.bytes ? ` · ${formatBytes(stats.bytes)}` : ''}
    </>;
  }

  if (job.type === 'portscan') {
    return <>
      {stats.open_ports !== undefined ? `${stats.open_ports} open / ${stats.total_ports || 0}` : '-'}
      {stats.up_hosts !== undefined ? ` · ${stats.up_hosts} up` : ''}
    </>;
  }

  if (job.type === 'debug') {
    return <>
      {stats.hit_breakpoint !== undefined ? (stats.hit_breakpoint ? 'breakpoint hit' : 'no hit') : '-'}
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

  return <>-</>;
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

function NewJobModal({ initial, onClose, onCreated }: {
  initial?: { type: string; config: Record<string, any> } | null;
  onClose: () => void;
  onCreated: () => void;
}) {
  const { toast } = useToast() as { toast: (a: string, b?: string) => void };
  // When cloning, start with the source job's type + config so the
  // user can tweak a single field and relaunch without re-filling the
  // whole form.
  const [jobType, setJobType] = useState<'fuzz' | 'debug' | 'capture' | 'portscan' | 'sandbox' | 'vm'>(
    (initial?.type as any) || 'fuzz',
  );
  const [submitting, setSubmitting] = useState(false);
  const [formData, setFormData] = useState<Record<string, any>>(initial?.config || {});

  const update = (key: string, val: any) => setFormData(prev => ({ ...prev, [key]: val }));

  const TOOL_MAP: Record<string, string> = { fuzz: 'libfuzzer', debug: 'gdb', capture: 'tcpdump', portscan: 'nmap', sandbox: 'docker', vm: 'qemu' };

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
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 8, marginBottom: 16 }}>
          {(['fuzz', 'debug', 'capture', 'portscan', 'sandbox', 'vm'] as const).map(t => (
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
            <Field
              label="Harness path (libFuzzer binary)"
              required
              help={'A compiled libFuzzer binary that takes (uint8_t* data, size_t size) inputs and returns 0.\n\nBuild one with:\n  clang -fsanitize=fuzzer,address -o fuzz_target fuzz.c\n\nExisting examples live under your project\'s tests/fuzz or oss-fuzz directories if the project participates.'}
            >
              <FolderPickerInput
                kind="file"
                value={formData.harness_path || ''}
                onChange={(v) => update('harness_path', v)}
                placeholder="/path/to/fuzz_target"
                style={inputStyle}
              />
            </Field>
            <Field
              label="Corpus directory (optional)"
              help={'Directory of seed inputs the fuzzer starts from. Each file in this directory is treated as one test case.\n\nLeave blank and VulnForge auto-creates an empty corpus under the job\'s output dir. A good starting corpus (valid sample inputs) makes fuzzing *much* more effective.'}
            >
              <FolderPickerInput
                kind="directory"
                value={formData.corpus_dir || ''}
                onChange={(v) => update('corpus_dir', v)}
                placeholder="auto-created under job output dir"
                style={inputStyle}
              />
            </Field>
            <Field
              label="Max time (seconds, default 300)"
              help={'Wall-clock cap on the fuzz run. libFuzzer loops forever by default - set this to something sane (300-3600) so the job terminates on its own.\n\nThe job will stop earlier if a crash is found.'}
            >
              <input type="number" value={formData.max_total_time || ''} onChange={e => update('max_total_time', Number(e.target.value) || undefined)} style={inputStyle} />
            </Field>
          </>}

          {jobType === 'debug' && <>
            <Field
              label="Binary path"
              required
              help={'Executable to run under GDB. If you have a core dump already, fill in Core Dump Path instead and leave this as just the binary that produced the dump (needed for symbols).'}
            >
              <FolderPickerInput
                kind="file"
                value={formData.binary_path || ''}
                onChange={(v) => update('binary_path', v)}
                style={inputStyle}
              />
            </Field>
            <Field
              label="Breakpoint (file:line or function)"
              help={'Where GDB halts. Accepted formats:\n  src/parser.c:234   (file + line)\n  parse_input        (function name)\n  0x7fffffffd8a0     (address)\n\nLeave blank to just run to completion (useful with core dumps).'}
            >
              <input value={formData.breakpoint || ''} onChange={e => update('breakpoint', e.target.value)}
                placeholder="src/parser.c:234" style={inputStyle} />
            </Field>
            <Field
              label="Program args (space-separated)"
              help={'Arguments passed to the binary on the GDB command line: `run <these args>`.\n\nNo shell expansion - you cannot use globs or environment variables.'}
            >
              <input value={(formData.args || []).join(' ')} onChange={e => update('args', e.target.value.split(/\s+/).filter(Boolean))} style={inputStyle} />
            </Field>
            <Field
              label="Check expression at breakpoint"
              help={'GDB expression evaluated when the breakpoint is hit. The result is stored in the job artifacts.\n\nExamples:\n  *buf            (dereference pointer)\n  argv[1]\n  p->next->data\n  ($rsp+8):4      (memory read)'}
            >
              <input value={formData.check_expr || ''} onChange={e => update('check_expr', e.target.value)} style={inputStyle} />
            </Field>
            <Field
              label="Core dump path (alternative to live debug)"
              help={'Post-mortem mode: instead of running the binary, load this core file into GDB and inspect the state at the moment it crashed. Useful when you already reproduced a crash outside VulnForge.'}
            >
              <FolderPickerInput
                kind="file"
                value={formData.core_path || ''}
                onChange={(v) => update('core_path', v)}
                style={inputStyle}
              />
            </Field>
          </>}

          {jobType === 'capture' && <>
            <Field
              label="Interface"
              required
              help={'The network interface tshark listens on. `any` listens on all interfaces at once.\n\nPick the one matching the traffic you want:\n  eth0 / en0        - Ethernet\n  wlan0 / en1        - Wi-Fi\n  lo / loopback      - local-only traffic (127.0.0.1)\n  any                - all interfaces'}
            >
              <InterfaceSelect value={formData.interface || 'any'} onChange={(v) => update('interface', v)} />
            </Field>
            <Field
              label="BPF filter (optional)"
              help={'Berkeley Packet Filter expression - tshark only records packets matching this.\n\nExamples:\n  port 443                     HTTPS only\n  host 192.168.1.5              traffic to/from one host\n  tcp and not port 22           all TCP except SSH\n  udp port 53                   DNS only\n\nLeave blank to capture everything.'}
            >
              <input value={formData.filter || ''} onChange={e => update('filter', e.target.value)}
                placeholder="port 443" style={inputStyle} />
            </Field>
            <Field
              label="Duration (seconds)"
              help={'Capture stops automatically after this many seconds. 60-600 is typical for debugging a single interaction.'}
            >
              <input type="number" value={formData.duration || 60} onChange={e => update('duration', Number(e.target.value))} style={inputStyle} />
            </Field>
            <Field
              label="Max packets (optional)"
              help={'Hard limit on packet count. Whichever limit (duration or max packets) fires first wins.\n\nUseful on noisy interfaces where the pcap would grow huge.'}
            >
              <input type="number" value={formData.max_packets || ''} onChange={e => update('max_packets', Number(e.target.value) || undefined)} style={inputStyle} />
            </Field>
          </>}

          {jobType === 'portscan' && <>
            <Field
              label="Target"
              required
              help={'nmap target specifier. Accepts:\n  192.168.1.5              single host\n  192.168.1.0/24            CIDR range\n  10.0.0.1-50               IP range\n  hostname.example.com      DNS name\n  host1 host2 host3         space-separated list\n\nOnly scan targets you are authorised to scan.'}
            >
              <input value={formData.target || ''} onChange={e => update('target', e.target.value)}
                placeholder="192.168.1.0/24 or hostname.com" style={inputStyle} />
            </Field>
            <Field
              label="Ports"
              help={'Ports to probe.\n  1-1000           port range (default 1000 most-common)\n  80,443,8080      explicit list\n  -                all 65535 ports (slow!)\n  U:53,T:80-443    UDP + TCP mix'}
            >
              <input value={formData.ports || '1-1000'} onChange={e => update('ports', e.target.value)} style={inputStyle} />
            </Field>
            <Field
              label="Scan type"
              help={'Probe strategy:\n  Connect - finishes the TCP handshake; works without root but is loud.\n  Version - also fingerprints service versions (adds ~minutes).\n  Script - runs nmap\'s default NSE scripts for richer info.\n  SYN - half-open; stealthier but needs root/admin.\n  UDP - slow but the only way to find UDP services.'}
            >
              <select value={formData.scan_type || 'version'} onChange={e => update('scan_type', e.target.value)} style={inputStyle}>
                <option value="connect">Connect (no root)</option>
                <option value="version">Version detection</option>
                <option value="script">Default scripts</option>
                <option value="syn">SYN (requires root)</option>
                <option value="udp">UDP</option>
              </select>
            </Field>
            <Field
              label="Timing (0-5)"
              help={'Speed vs stealth trade-off (nmap -T flag).\n  0 paranoid   - one probe every 5 min (IDS-evasion)\n  1 sneaky     - serialised, 15s between probes\n  2 polite     - light load\n  3 normal     - default\n  4 aggressive - reasonable for a fast LAN\n  5 insane     - assume the target won\'t notice or mind'}
            >
              <input type="number" min={0} max={5} value={formData.timing ?? 3} onChange={e => update('timing', Number(e.target.value))} style={inputStyle} />
            </Field>
          </>}

          {jobType === 'sandbox' && <>
            <Field
              label="Docker image"
              required
              help={'Image name to spin up.\n\nCommon choices for security work:\n  ubuntu:22.04 / debian:12    general-purpose analysis\n  kalilinux/kali-rolling        pre-installed security tools\n  python:3.12                   quick scripting env\n  alpine:3.20                   minimal footprint\n\nThe image is pulled from Docker Hub on first use.'}
            >
              <input value={formData.image || 'ubuntu:22.04'} onChange={e => update('image', e.target.value)}
                placeholder="ubuntu:22.04, kalilinux/kali, python:3.12" style={inputStyle} />
            </Field>
            <Field
              label="Command (optional)"
              help={'Overrides the image\'s default entrypoint/CMD. Space-separated tokens become argv.\n\nLeave blank to run the image as shipped (usually a shell or the tool\'s main binary).'}
            >
              <input value={(formData.command || []).join(' ')} onChange={e => update('command', e.target.value.split(/\s+/).filter(Boolean))}
                placeholder="sleep 3600 (default: image entrypoint)" style={inputStyle} />
            </Field>
            <Field
              label="Memory limit"
              help={'Cap RAM the container can use. Formats: `512m`, `1g`, `2g`.\n\nContainer is killed if it exceeds this.'}
            >
              <input value={formData.memory_limit || '512m'} onChange={e => update('memory_limit', e.target.value)}
                placeholder="512m, 1g, 2g" style={inputStyle} />
            </Field>
            <Field
              label="CPU limit"
              help={'Number of CPU cores the container may use. Fractional values allowed (0.5 = half a core).'}
            >
              <input type="number" step={0.5} value={formData.cpu_limit ?? 2} onChange={e => update('cpu_limit', Number(e.target.value) || undefined)} style={inputStyle} />
            </Field>
            <Field
              label="Network mode"
              help={'Docker networking policy.\n  Bridge - isolated subnet + NAT. Recommended for analysis of untrusted code.\n  Host - shares the host\'s network namespace. Faster but container can see/attack your LAN.\n  None - no network at all. Strictest sandbox for truly untrusted binaries.'}
            >
              <select value={formData.network_mode || 'bridge'} onChange={e => update('network_mode', e.target.value)} style={inputStyle}>
                <option value="bridge">Bridge (isolated, recommended)</option>
                <option value="host">Host (full host network access)</option>
                <option value="none">None (no network)</option>
              </select>
            </Field>
            <Field
              label="Timeout (seconds, 0 = unlimited)"
              help={'Hard wall-clock limit. Container is killed after this. 0 means no timeout (use with care).'}
            >
              <input type="number" value={formData.timeout ?? 0} onChange={e => update('timeout', Number(e.target.value))} style={inputStyle} />
            </Field>
          </>}

          {jobType === 'vm' && <>
            <Field
              label="Disk image (.qcow2, .img, .iso)"
              required
              help={'Path to the VM disk file. QEMU accepts:\n  .qcow2  - copy-on-write, compressible (recommended)\n  .img/.raw - full-size flat image\n  .iso     - bootable install media (boots the installer)\n  .vmdk    - VMware disk\n\nPoint at a pre-built VM snapshot so boots are fast.'}
            >
              <FolderPickerInput
                kind="file"
                value={formData.disk_image || ''}
                onChange={(v) => update('disk_image', v)}
                placeholder="C:\\VMs\\ubuntu-22.04.qcow2"
                style={inputStyle}
              />
            </Field>
            <Field
              label="Architecture"
              help={'CPU QEMU emulates. Match the guest OS\'s target arch.\n\nx86_64 is standard PC. Pick ARM/AArch64 for IoT firmware, MIPS/RISC-V for embedded research. Cross-arch emulation is *much* slower than matched-host virtualisation.'}
            >
              <select value={(formData as any).arch || 'x86_64'} onChange={e => update('arch', e.target.value)} style={inputStyle}>
                <option value="x86_64">x86_64 (Intel/AMD 64-bit)</option>
                <option value="i386">i386 (32-bit)</option>
                <option value="aarch64">AArch64 (ARM 64-bit)</option>
                <option value="arm">ARM (32-bit)</option>
                <option value="mips">MIPS</option>
                <option value="riscv64">RISC-V 64-bit</option>
              </select>
            </Field>
            <Field
              label="Memory"
              help={'Guest RAM allocation. Formats: `1G`, `2048M`, `4G`.\n\nMust fit in host RAM. 2G is enough for most Linux guests; Windows guests want 4G+.'}
            >
              <input value={formData.memory || '2G'} onChange={e => update('memory', e.target.value)}
                placeholder="1G, 2G, 4G" style={inputStyle} />
            </Field>
            <Field
              label="CPU cores"
              help={'Virtual CPUs exposed to the guest. Don\'t exceed your host\'s physical core count or the guest will starve.'}
            >
              <input type="number" value={formData.cpus ?? 2} onChange={e => update('cpus', Number(e.target.value))} style={inputStyle} />
            </Field>
            <Field
              label="Snapshot mode (discard changes on shutdown)"
              help={'When ON, the VM boots from a copy-on-write snapshot and all guest writes are discarded when the VM stops. Useful for repeatable analysis where you always start from a clean state.\n\nWhen OFF, disk writes persist to the image file.'}
            >
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                <input type="checkbox" checked={formData.snapshot_mode ?? false}
                  onChange={e => update('snapshot_mode', e.target.checked)} />
                <span style={{ fontSize: 12, color: 'var(--muted)' }}>Volatile - changes lost on shutdown</span>
              </label>
            </Field>
            <Field
              label="Timeout (seconds, 0 = unlimited)"
              help={'Hard wall-clock limit. VM is shut down after this. 0 means no timeout.'}
            >
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

function Field({
  label,
  required,
  help,
  children,
}: {
  label: string;
  required?: boolean;
  /** Optional help text shown via a ? icon (hover tooltip + click modal). */
  help?: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label style={{ fontSize: 11, color: 'var(--muted)', display: 'flex', alignItems: 'center', marginBottom: 4 }}>
        <span>
          {label}{required ? ' *' : ''}
        </span>
        {help && <HelpIcon title={label} body={help} size={12} />}
      </label>
      {children}
    </div>
  );
}

/**
 * Interface picker for packet capture. Fetches the host's real NICs
 * from /api/system/network-interfaces and renders them as a combobox.
 * Falls back to a plain text input if the endpoint is unreachable.
 */
function InterfaceSelect({
  value,
  onChange,
}: {
  value: string;
  onChange: (v: string) => void;
}) {
  const [ifs, setIfs] = useState<Array<{ name: string; addresses: string[]; family: string; internal: boolean }> | null>(null);
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await apiFetch('/api/system/network-interfaces');
        if (!res.ok) return;
        const body = await res.json();
        if (!cancelled) setIfs(body.data || []);
      } catch { /* keep null - falls through to text input */ }
    })();
    return () => { cancelled = true; };
  }, []);

  if (!ifs) {
    // Endpoint hasn't responded yet (dev without server, or ignored
    // failure). Show a plain text input so the page still works.
    return (
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder="eth0, lo, any"
        style={inputStyle}
      />
    );
  }

  return (
    <select value={value || 'any'} onChange={(e) => onChange(e.target.value)} style={inputStyle}>
      {ifs.map((i) => {
        const label = i.addresses.length > 0
          ? `${i.name}  -  ${i.addresses.slice(0, 2).join(', ')}${i.internal ? '  (loopback)' : ''}`
          : `${i.name}${i.name === 'any' ? '  (all interfaces)' : ''}`;
        return <option key={i.name} value={i.name}>{label}</option>;
      })}
    </select>
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
