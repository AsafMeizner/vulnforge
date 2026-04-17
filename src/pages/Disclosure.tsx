import { useState, useEffect, useCallback } from 'react';
import {
  listDisclosures,
  listVendors,
  createDisclosure,
  updateDisclosure,
  deleteDisclosure,
  createVendor,
  getDisclosureAnalytics,
  type Disclosure,
  type Vendor,
} from '@/lib/api';
import { useToast } from '@/components/Toast';

type Tab = 'pipeline' | 'vendors' | 'analytics';

const STATUS_COLORS: Record<string, string> = {
  draft: 'var(--muted)',
  submitted: 'var(--blue)',
  acknowledged: 'var(--purple)',
  fixed: 'var(--yellow)',
  resolved: 'var(--green)',
  public: 'var(--green)',
  cancelled: 'var(--muted)',
};

const SLA_COLORS = {
  on_track: 'var(--green)',
  warning: 'var(--yellow)',
  overdue: 'var(--red)',
  n_a: 'var(--muted)',
} as const;

export default function DisclosurePage() {
  const { toast } = useToast() as { toast: (a: string, b?: string) => void };
  const [tab, setTab] = useState<Tab>('pipeline');
  const [disclosures, setDisclosures] = useState<Disclosure[]>([]);
  const [vendors, setVendors] = useState<Vendor[]>([]);
  const [analytics, setAnalytics] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [newDisclosureOpen, setNewDisclosureOpen] = useState(false);
  const [newVendorOpen, setNewVendorOpen] = useState(false);
  const [selected, setSelected] = useState<Disclosure | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [dr, vr, ar] = await Promise.all([
        listDisclosures(),
        listVendors(),
        getDisclosureAnalytics(),
      ]);
      setDisclosures(dr.data);
      setVendors(vr.data);
      setAnalytics(ar);
    } catch (err: any) {
      toast(`Load failed: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => { load(); }, [load]);

  const vendorName = (id?: number) => id ? (vendors.find(v => v.id === id)?.name || `#${id}`) : '—';

  const handleStatusChange = async (d: Disclosure, status: string) => {
    try {
      await updateDisclosure(d.id, { status });
      toast(`Marked as ${status}`, 'success');
      load();
    } catch (err: any) { toast(err.message, 'error'); }
  };

  const handleDelete = async (id: number) => {
    if (!confirm('Delete this disclosure?')) return;
    try {
      await deleteDisclosure(id);
      load();
    } catch (err: any) { toast(err.message, 'error'); }
  };

  return (
    <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h2 style={{ fontSize: 20, fontWeight: 700, margin: 0, color: 'var(--text)' }}>Disclosure & Bounty Ops</h2>
          <p style={{ fontSize: 12, color: 'var(--muted)', margin: '4px 0 0' }}>
            Track vendor disclosure timelines, SLAs, and bounty payouts.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          {tab === 'vendors' && (
            <button onClick={() => setNewVendorOpen(true)} style={primaryBtn}>+ New Vendor</button>
          )}
          {tab === 'pipeline' && (
            <button onClick={() => setNewDisclosureOpen(true)} style={primaryBtn}>+ New Disclosure</button>
          )}
        </div>
      </div>

      {/* Analytics cards */}
      {analytics && tab === 'analytics' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 10 }}>
          <StatCard label="Total Disclosures" value={analytics.total_disclosures} color="var(--blue)" />
          <StatCard label="Resolved" value={analytics.by_status.resolved || 0} color="var(--green)" />
          <StatCard label="In Progress" value={(analytics.by_status.submitted || 0) + (analytics.by_status.acknowledged || 0)} color="var(--yellow)" />
          <StatCard label="Total Bounty" value={`$${(analytics.total_bounty_usd || 0).toLocaleString()}`} color="var(--orange)" />
          <StatCard label="Average Bounty" value={`$${(analytics.average_bounty_usd || 0).toLocaleString()}`} color="var(--purple)" />
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 4, borderBottom: '1px solid var(--border)' }}>
        {(['pipeline', 'vendors', 'analytics'] as Tab[]).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            style={{
              background: 'none', border: 'none',
              borderBottom: `2px solid ${tab === t ? 'var(--blue)' : 'transparent'}`,
              color: tab === t ? 'var(--text)' : 'var(--muted)',
              padding: '8px 14px', fontSize: 13, fontWeight: tab === t ? 600 : 400, cursor: 'pointer',
            }}
          >
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {loading ? (
        <div style={{ padding: 24, textAlign: 'center', color: 'var(--muted)' }}>Loading...</div>
      ) : (
        <>
          {tab === 'pipeline' && (
            disclosures.length === 0 ? (
              <div style={{ padding: 40, textAlign: 'center', color: 'var(--muted)', fontSize: 13, border: '1px dashed var(--border)', borderRadius: 8 }}>
                No disclosures yet. Click "+ New Disclosure" to track your first one.
              </div>
            ) : (
              <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border)' }}>
                      {['Title', 'Vendor', 'Status', 'SLA', 'CVE', 'Bounty', 'Actions'].map(h => (
                        <th key={h} style={thStyle}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {disclosures.map(d => (
                      <tr key={d.id} style={{ borderBottom: '1px solid var(--border)' }}>
                        <td style={{ ...tdStyle, color: 'var(--text)', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {d.title}
                        </td>
                        <td style={{ ...tdStyle, color: 'var(--muted)' }}>{vendorName(d.vendor_id)}</td>
                        <td style={tdStyle}>
                          <select
                            value={d.status}
                            onChange={e => handleStatusChange(d, e.target.value)}
                            style={{
                              padding: '3px 8px', borderRadius: 10,
                              background: `${STATUS_COLORS[d.status]}22`,
                              color: STATUS_COLORS[d.status],
                              border: `1px solid ${STATUS_COLORS[d.status]}66`,
                              fontSize: 10, fontWeight: 600, textTransform: 'uppercase', cursor: 'pointer',
                            }}
                          >
                            {Object.keys(STATUS_COLORS).map(s => <option key={s} value={s}>{s}</option>)}
                          </select>
                        </td>
                        <td style={tdStyle}>
                          {d.sla_status && d.sla_status !== 'n_a' ? (
                            <span style={{
                              padding: '2px 8px', borderRadius: 10,
                              background: `${SLA_COLORS[d.sla_status]}22`,
                              color: SLA_COLORS[d.sla_status],
                              fontSize: 10, fontWeight: 600,
                            }}>
                              {d.sla_days_remaining! < 0
                                ? `${Math.abs(d.sla_days_remaining!)}d overdue`
                                : `${d.sla_days_remaining}d left`}
                            </span>
                          ) : <span style={{ color: 'var(--muted)' }}>—</span>}
                        </td>
                        <td style={{ ...tdStyle, fontFamily: 'monospace', color: 'var(--blue)', fontSize: 11 }}>
                          {d.cve_id || '—'}
                        </td>
                        <td style={{ ...tdStyle, color: 'var(--green)', fontWeight: 600 }}>
                          {d.bounty_amount ? `$${d.bounty_amount}` : '—'}
                        </td>
                        <td style={tdStyle}>
                          <button onClick={() => setSelected(d)} style={smallBtn('var(--blue)')}>View</button>
                          <button onClick={() => handleDelete(d.id)} style={{ ...smallBtn('var(--red)'), marginLeft: 4 }}>Delete</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          )}

          {tab === 'vendors' && (
            vendors.length === 0 ? (
              <div style={{ padding: 40, textAlign: 'center', color: 'var(--muted)', fontSize: 13, border: '1px dashed var(--border)', borderRadius: 8 }}>
                No vendors yet. Add your first vendor to track disclosures.
              </div>
            ) : (
              <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border)' }}>
                      {['Name', 'Platform', 'Security Email', 'Response Time', 'Notes'].map(h => (
                        <th key={h} style={thStyle}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {vendors.map(v => (
                      <tr key={v.id} style={{ borderBottom: '1px solid var(--border)' }}>
                        <td style={{ ...tdStyle, color: 'var(--text)', fontWeight: 600 }}>{v.name}</td>
                        <td style={{ ...tdStyle, color: 'var(--muted)' }}>{v.platform || '—'}</td>
                        <td style={{ ...tdStyle, color: 'var(--muted)', fontFamily: 'monospace', fontSize: 11 }}>
                          {v.security_email || '—'}
                        </td>
                        <td style={{ ...tdStyle, color: 'var(--muted)' }}>
                          {v.typical_response_days ? `${v.typical_response_days}d` : '—'}
                        </td>
                        <td style={{ ...tdStyle, color: 'var(--muted)', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {v.notes || '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          )}

          {tab === 'analytics' && analytics && (
            <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 20 }}>
              <h3 style={{ margin: '0 0 14px', color: 'var(--text)', fontSize: 15 }}>Status Breakdown</h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {Object.entries(analytics.by_status || {}).map(([status, count]) => (
                  <div key={status} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <span style={{
                      width: 120, textTransform: 'capitalize', color: STATUS_COLORS[status] || 'var(--text)',
                      fontSize: 12, fontWeight: 600,
                    }}>{status}</span>
                    <div style={{ flex: 1, height: 16, background: 'var(--bg)', borderRadius: 2, overflow: 'hidden' }}>
                      <div style={{
                        width: `${Math.min(100, ((count as number) / Math.max(1, analytics.total_disclosures)) * 100)}%`,
                        height: '100%',
                        background: STATUS_COLORS[status] || 'var(--blue)',
                      }} />
                    </div>
                    <span style={{ width: 40, textAlign: 'right', color: 'var(--text)', fontSize: 12 }}>{count as number}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      {newDisclosureOpen && <NewDisclosureModal vendors={vendors} onClose={() => setNewDisclosureOpen(false)} onCreated={() => { setNewDisclosureOpen(false); load(); }} />}
      {newVendorOpen && <NewVendorModal onClose={() => setNewVendorOpen(false)} onCreated={() => { setNewVendorOpen(false); load(); }} />}
      {selected && <DisclosureDetailModal disclosure={selected} vendor={vendors.find(v => v.id === selected.vendor_id) || null} onClose={() => setSelected(null)} />}
    </div>
  );
}

function NewDisclosureModal({ vendors, onClose, onCreated }: {
  vendors: Vendor[]; onClose: () => void; onCreated: () => void;
}) {
  const { toast } = useToast() as { toast: (a: string, b?: string) => void };
  const [title, setTitle] = useState('');
  const [vendorId, setVendorId] = useState<number | ''>('');
  const [findingId, setFindingId] = useState('');
  const [slaDays, setSlaDays] = useState(90);

  const handleCreate = async () => {
    if (!title.trim()) { toast('Title required', 'error'); return; }
    try {
      await createDisclosure({
        title: title.trim(),
        vendor_id: vendorId ? Number(vendorId) : undefined,
        finding_id: findingId ? Number(findingId) : undefined,
        sla_days: slaDays,
        status: 'draft',
      });
      onCreated();
    } catch (err: any) { toast(err.message, 'error'); }
  };

  return (
    <ModalShell title="New Disclosure" onClose={onClose}>
      <Field label="Title (required)"><input value={title} onChange={e => setTitle(e.target.value)} autoFocus style={inputStyle} /></Field>
      <Field label="Vendor">
        <select value={vendorId} onChange={e => setVendorId(e.target.value ? Number(e.target.value) : '')} style={inputStyle}>
          <option value="">— select vendor —</option>
          {vendors.map(v => <option key={v.id} value={v.id}>{v.name}</option>)}
        </select>
      </Field>
      <Field label="Linked finding ID"><input value={findingId} onChange={e => setFindingId(e.target.value)} style={inputStyle} /></Field>
      <Field label="SLA (days)"><input type="number" value={slaDays} onChange={e => setSlaDays(Number(e.target.value))} style={inputStyle} /></Field>
      <ModalActions onCancel={onClose} onConfirm={handleCreate} confirmLabel="Create" />
    </ModalShell>
  );
}

function NewVendorModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const { toast } = useToast() as { toast: (a: string, b?: string) => void };
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [platform, setPlatform] = useState('direct');
  const [responseDays, setResponseDays] = useState(14);

  const handleCreate = async () => {
    if (!name.trim()) { toast('Name required', 'error'); return; }
    try {
      await createVendor({
        name: name.trim(),
        security_email: email,
        platform,
        typical_response_days: responseDays,
      });
      onCreated();
    } catch (err: any) { toast(err.message, 'error'); }
  };

  return (
    <ModalShell title="New Vendor" onClose={onClose}>
      <Field label="Name"><input value={name} onChange={e => setName(e.target.value)} autoFocus style={inputStyle} /></Field>
      <Field label="Security Email"><input value={email} onChange={e => setEmail(e.target.value)} placeholder="security@example.com" style={inputStyle} /></Field>
      <Field label="Platform">
        <select value={platform} onChange={e => setPlatform(e.target.value)} style={inputStyle}>
          <option value="direct">Direct (email)</option>
          <option value="hackerone">HackerOne</option>
          <option value="bugcrowd">Bugcrowd</option>
          <option value="intigriti">Intigriti</option>
          <option value="cve">CVE Numbering Authority</option>
        </select>
      </Field>
      <Field label="Typical response (days)"><input type="number" value={responseDays} onChange={e => setResponseDays(Number(e.target.value))} style={inputStyle} /></Field>
      <ModalActions onCancel={onClose} onConfirm={handleCreate} confirmLabel="Create" />
    </ModalShell>
  );
}

function DisclosureDetailModal({ disclosure, vendor, onClose }: {
  disclosure: Disclosure;
  vendor: Vendor | null;
  onClose: () => void;
}) {
  return (
    <ModalShell title={disclosure.title} onClose={onClose}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 10, marginBottom: 14 }}>
        <Info label="Status" value={disclosure.status} />
        <Info label="Vendor" value={vendor?.name || '—'} />
        <Info label="CVE" value={disclosure.cve_id || '—'} />
        <Info label="Tracking ID" value={disclosure.tracking_id || '—'} />
        <Info label="Submitted" value={disclosure.submission_date?.split('T')[0] || '—'} />
        <Info label="SLA" value={disclosure.sla_days ? `${disclosure.sla_days} days` : '—'} />
        <Info label="Bounty" value={disclosure.bounty_amount ? `$${disclosure.bounty_amount}` : '—'} />
        <Info label="Paid" value={disclosure.bounty_paid_date?.split('T')[0] || '—'} />
      </div>
      {disclosure.notes && (
        <div>
          <div style={{ fontSize: 10, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 4 }}>Notes</div>
          <div style={{ color: 'var(--text)', fontSize: 13, lineHeight: 1.5, whiteSpace: 'pre-wrap' }}>{disclosure.notes}</div>
        </div>
      )}
      <ModalActions onCancel={onClose} confirmLabel="" />
    </ModalShell>
  );
}

function ModalShell({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  return (
    <div style={{
      position: 'fixed', inset: 0, background: '#0008', zIndex: 1000,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={onClose}>
      <div style={{
        background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 10,
        padding: 24, width: '90%', maxWidth: 560, maxHeight: '80vh', overflow: 'auto',
      }} onClick={e => e.stopPropagation()}>
        <h3 style={{ margin: '0 0 16px', color: 'var(--text)' }}>{title}</h3>
        {children}
      </div>
    </div>
  );
}

function ModalActions({ onCancel, onConfirm, confirmLabel }: { onCancel: () => void; onConfirm?: () => void; confirmLabel: string }) {
  return (
    <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 16 }}>
      <button onClick={onCancel} style={{
        padding: '8px 16px', background: 'var(--surface-2)', border: '1px solid var(--border)',
        borderRadius: 5, color: 'var(--text)', fontSize: 13, cursor: 'pointer',
      }}>Cancel</button>
      {confirmLabel && onConfirm && (
        <button onClick={onConfirm} style={primaryBtn}>{confirmLabel}</button>
      )}
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>{label}</label>
      {children}
    </div>
  );
}

function Info({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div style={{ fontSize: 10, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 2 }}>{label}</div>
      <div style={{ color: 'var(--text)', fontSize: 13 }}>{value}</div>
    </div>
  );
}

function StatCard({ label, value, color }: { label: string; value: number | string; color: string }) {
  return (
    <div style={{
      background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8,
      padding: '14px 18px', borderTop: `3px solid ${color}`,
    }}>
      <div style={{ fontSize: 22, fontWeight: 700, color }}>{value}</div>
      <div style={{ fontSize: 10, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5, marginTop: 4 }}>
        {label}
      </div>
    </div>
  );
}

function smallBtn(color: string): React.CSSProperties {
  return {
    padding: '4px 10px', fontSize: 11, fontWeight: 600, cursor: 'pointer',
    background: `${color}22`, color, border: `1px solid ${color}44`, borderRadius: 4,
  };
}

const primaryBtn: React.CSSProperties = {
  padding: '8px 16px', background: 'var(--green)', color: '#000',
  border: 'none', borderRadius: 6, fontSize: 13, fontWeight: 700, cursor: 'pointer',
};

const thStyle: React.CSSProperties = {
  textAlign: 'left', padding: '10px 14px',
  color: 'var(--muted)', fontSize: 11, fontWeight: 600,
  textTransform: 'uppercase', letterSpacing: 0.5,
};

const tdStyle: React.CSSProperties = {
  padding: '10px 14px', verticalAlign: 'middle',
};

const inputStyle: React.CSSProperties = {
  width: '100%', padding: '8px 10px', background: 'var(--bg)',
  border: '1px solid var(--border)', borderRadius: 5, color: 'var(--text)',
  fontSize: 13, outline: 'none', boxSizing: 'border-box', fontFamily: 'inherit',
};
