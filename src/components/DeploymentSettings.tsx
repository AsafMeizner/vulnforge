/**
 * Settings → Deployment panel.
 *
 * Lets the user:
 *   - See current mode (solo / team) + server URL + device id
 *   - Switch solo ↔ team (with confirmation - no data loss either way)
 *   - Set default row scope for new rows (private / team / pool)
 *   - Revoke team-server session (logout from server while staying in team mode)
 *   - See outbox size + current WS status
 */
import { useEffect, useState } from 'react';
import type { ConnectionStatus } from '../lib/sync';
import { apiFetch } from '../lib/api';

interface Props {
  /** Inject sync status from top-level app shell. */
  wsStatus?: ConnectionStatus;
  outboxSize?: number;
  onSwitchToSolo?: () => void;
  onReconnect?: () => void;
}

const row: React.CSSProperties = {
  display: 'grid',
  gridTemplateColumns: '160px 1fr',
  gap: 12,
  padding: '10px 0',
  borderBottom: '1px solid var(--border, #eee)',
  fontSize: 14,
};
const label: React.CSSProperties = { color: '#666', fontSize: 13, paddingTop: 2 };
const btn: React.CSSProperties = {
  padding: '6px 12px',
  border: '1px solid var(--border, #ccc)',
  borderRadius: 6,
  background: 'var(--bg, #fafafa)',
  cursor: 'pointer',
  fontSize: 13,
  marginRight: 8,
};
const warn: React.CSSProperties = {
  ...btn,
  background: '#fff5f5',
  color: '#900',
  borderColor: '#fcc',
};

interface Settings {
  deployment_client_mode?: string;
  team_server_url?: string;
  team_server_device_id?: string;
  team_server_device_name?: string;
  default_row_scope?: string;
}

export default function DeploymentSettings({
  wsStatus = 'disconnected',
  outboxSize = 0,
  onSwitchToSolo,
  onReconnect,
}: Props) {
  const [settings, setSettings] = useState<Settings>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const resp = await apiFetch('/api/settings');
        if (!resp.ok) return;
        const data = await resp.json() as { data?: Array<{ key: string; value: string }>; };
        const map: Settings = {};
        for (const r of data.data ?? []) (map as any)[r.key] = r.value;
        if (!cancelled) setSettings(map);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  async function save(key: keyof Settings, value: string) {
    setSaving(true);
    try {
      await apiFetch('/api/settings/' + encodeURIComponent(String(key)), {
        method: 'PUT',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ value }),
      });
      setSettings(s => ({ ...s, [key]: value }));
    } finally { setSaving(false); }
  }

  if (loading) return <div style={{ padding: 20 }}>Loading…</div>;

  const mode = settings.deployment_client_mode ?? 'solo';
  const isTeam = mode === 'team';

  return (
    <div style={{ padding: 20, maxWidth: 780, fontFamily: 'system-ui' }}>
      <h2 style={{ marginTop: 0 }}>Deployment</h2>
      <p style={{ color: '#666', fontSize: 13 }}>
        Controls how this desktop behaves relative to a team server.
        <a href="/docs/architecture/deployment-topology.md" style={{ marginLeft: 6 }}>Architecture doc</a>
      </p>

      <div style={row}>
        <div style={label}>Mode</div>
        <div>
          <strong style={{ fontSize: 15 }}>{isTeam ? 'Team' : 'Solo'}</strong>
          {isTeam && (
            <button style={warn} disabled={saving} onClick={() => {
              if (confirm('Switch to Solo? Team-scoped rows remain on this device but stop syncing.')) {
                onSwitchToSolo?.();
                save('deployment_client_mode', 'solo');
              }
            }}>Switch to Solo</button>
          )}
        </div>
      </div>

      {isTeam && (
        <>
          <div style={row}>
            <div style={label}>Server URL</div>
            <div><code>{settings.team_server_url ?? '-'}</code></div>
          </div>
          <div style={row}>
            <div style={label}>Device ID</div>
            <div><code style={{ fontSize: 12 }}>{settings.team_server_device_id ?? '-'}</code></div>
          </div>
          <div style={row}>
            <div style={label}>Sync status</div>
            <div>
              <span style={{
                fontWeight: 600,
                color: wsStatus === 'live' ? '#2c7' :
                       wsStatus === 'backfilling' ? '#c80' :
                       wsStatus === 'connecting' ? '#888' :
                       wsStatus === 'error' ? '#c33' : '#888',
              }}>
                {wsStatus}
              </span>
              {wsStatus !== 'live' && (
                <button style={btn} onClick={() => onReconnect?.()}>Reconnect</button>
              )}
            </div>
          </div>
          <div style={row}>
            <div style={label}>Outbox</div>
            <div>
              {outboxSize === 0 ? '0 pending pushes' : `${outboxSize} pending`}
              {outboxSize > 0 && <span style={{ color: '#888', marginLeft: 8 }}>- will flush on reconnect</span>}
            </div>
          </div>
        </>
      )}

      <div style={row}>
        <div style={label}>Default row scope</div>
        <div>
          <select
            value={settings.default_row_scope ?? 'private'}
            onChange={e => save('default_row_scope', e.target.value)}
            disabled={saving}
            style={{ padding: 6, borderRadius: 4 }}
          >
            <option value="private">Private (stays on this device)</option>
            <option value="team" disabled={!isTeam}>Team (syncs to server)</option>
            <option value="pool" disabled={!isTeam}>Pool (anonymized shared)</option>
          </select>
          <div style={{ fontSize: 12, color: '#888', marginTop: 4 }}>
            Applies to newly created rows. You can always change per-row via the scope pill.
          </div>
        </div>
      </div>

      <p style={{ marginTop: 24, fontSize: 13, color: '#666' }}>
        More deployment docs: see <a href="/docs/user/privacy-scopes.md">privacy scopes</a>,
        <a href="/docs/user/team-mode-switching.md" style={{ marginLeft: 4 }}>mode switching</a>,
        <a href="/docs/user/ai-providers.md" style={{ marginLeft: 4 }}>AI providers</a>.
      </p>
    </div>
  );
}
