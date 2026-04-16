/**
 * First-launch wizard. Shown when no `deployment_client_mode` setting
 * exists yet. Writes the setting on completion and navigates to Hunt.
 *
 * Two paths:
 *   - Solo:  one click, writes deployment_client_mode='solo'.
 *   - Team:  enter server URL → try /api/health → either sign in or bootstrap.
 */
import { useState } from 'react';

type Step =
  | 'choose'
  | 'team-url'
  | 'team-bootstrap'
  | 'team-login'
  | 'done';

interface Props {
  onFinished: () => void;
}

const card: React.CSSProperties = {
  maxWidth: 560,
  margin: '80px auto',
  padding: 28,
  border: '1px solid var(--border, #ddd)',
  borderRadius: 10,
  fontFamily: 'system-ui, -apple-system, sans-serif',
  lineHeight: 1.5,
};
const btn: React.CSSProperties = {
  padding: '10px 16px',
  borderRadius: 6,
  border: '1px solid var(--border, #ccc)',
  background: 'var(--bg, #fafafa)',
  cursor: 'pointer',
  fontSize: 14,
  marginRight: 8,
  marginTop: 8,
};
const primary: React.CSSProperties = {
  ...btn,
  background: 'var(--accent, #0a66c2)',
  color: 'white',
  borderColor: 'transparent',
};
const input: React.CSSProperties = {
  width: '100%',
  padding: '10px 12px',
  borderRadius: 6,
  border: '1px solid var(--border, #ccc)',
  fontSize: 14,
  marginTop: 6,
  boxSizing: 'border-box',
};
const errStyle: React.CSSProperties = {
  background: '#fff5f5',
  border: '1px solid #fcc',
  color: '#900',
  padding: 10,
  borderRadius: 6,
  marginTop: 10,
  fontSize: 13,
};

export default function FirstLaunch({ onFinished }: Props) {
  const [step, setStep] = useState<Step>('choose');
  const [serverUrl, setServerUrl] = useState('');
  const [bootstrapToken, setBootstrapToken] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [email, setEmail] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function writeSettings(body: Record<string, string>) {
    await fetch('/api/settings/bulk', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
  }

  async function pickSolo() {
    setBusy(true);
    try {
      await writeSettings({ deployment_client_mode: 'solo' });
      onFinished();
    } catch (e: any) {
      setErr(e.message);
    } finally { setBusy(false); }
  }

  async function checkHealth() {
    setErr(null); setBusy(true);
    try {
      const u = serverUrl.replace(/\/$/, '') + '/api/health';
      const r = await fetch(u);
      if (!r.ok) throw new Error(`health ${r.status}`);
      // Try session/bootstrap path first — if bootstrap is pending server replies 503.
      setStep('team-login');
    } catch (e: any) {
      setErr(`Cannot reach ${serverUrl} — ${e.message}`);
    } finally { setBusy(false); }
  }

  async function doBootstrap() {
    setErr(null); setBusy(true);
    try {
      const r = await fetch(serverUrl.replace(/\/$/, '') + '/api/session/bootstrap', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ bootstrap_token: bootstrapToken, username, password, email }),
      });
      if (!r.ok) { const j = await r.json().catch(() => ({ error: `HTTP ${r.status}` })); throw new Error(j.error || 'bootstrap failed'); }
      const j = await r.json();
      await writeSettings({
        deployment_client_mode: 'team',
        team_server_url: serverUrl,
        team_server_device_id: j.device_id,
        jwt_refresh_token: j.refresh_token,
      });
      onFinished();
    } catch (e: any) {
      setErr(e.message);
    } finally { setBusy(false); }
  }

  async function doLogin() {
    setErr(null); setBusy(true);
    try {
      const r = await fetch(serverUrl.replace(/\/$/, '') + '/api/session/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username, password, device_name: navigator.userAgent.slice(0, 64) }),
      });
      if (!r.ok) { const j = await r.json().catch(() => ({ error: `HTTP ${r.status}` })); throw new Error(j.error || 'login failed'); }
      const j = await r.json();
      await writeSettings({
        deployment_client_mode: 'team',
        team_server_url: serverUrl,
        team_server_device_id: j.device_id,
        jwt_refresh_token: j.refresh_token,
      });
      onFinished();
    } catch (e: any) {
      setErr(e.message);
    } finally { setBusy(false); }
  }

  return (
    <div style={card}>
      <img
        src="/brand/logo-wide-white.svg"
        alt="VulnForge"
        style={{ display: 'block', width: '100%', maxWidth: 360, height: 'auto', margin: '0 auto 18px' }}
      />
      <h1 style={{ marginTop: 0, textAlign: 'center' }}>Welcome to VulnForge</h1>

      {step === 'choose' && (
        <>
          <p>Pick how you want to run VulnForge. You can switch later from Settings → Deployment.</p>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginTop: 20 }}>
            <button style={btn} disabled={busy} onClick={pickSolo}>
              <strong>Solo</strong><br /><span style={{ fontSize: 12, color: '#666' }}>
                Single user. Everything runs on this machine. No network required.
              </span>
            </button>
            <button style={primary} disabled={busy} onClick={() => setStep('team-url')}>
              <strong>Team</strong><br /><span style={{ fontSize: 12, opacity: 0.85 }}>
                Connect to your company's VulnForge server. Local-first with sync.
              </span>
            </button>
          </div>
          {err && <div style={errStyle}>{err}</div>}
        </>
      )}

      {step === 'team-url' && (
        <>
          <h2>Server URL</h2>
          <p>Paste the public URL your admin gave you.</p>
          <input
            style={input}
            placeholder="https://vulnforge.acme.corp"
            value={serverUrl}
            onChange={e => setServerUrl(e.target.value)}
          />
          {err && <div style={errStyle}>{err}</div>}
          <div style={{ marginTop: 14 }}>
            <button style={btn} disabled={busy} onClick={() => setStep('choose')}>Back</button>
            <button style={primary} disabled={busy || !serverUrl} onClick={checkHealth}>
              {busy ? 'Checking…' : 'Continue'}
            </button>
            <button style={btn} disabled={busy} onClick={() => setStep('team-bootstrap')}>
              I'm the first admin
            </button>
          </div>
        </>
      )}

      {step === 'team-bootstrap' && (
        <>
          <h2>Bootstrap first admin</h2>
          <p>Paste the one-time token your install script printed. Create the admin account.</p>
          <input style={input} placeholder="Bootstrap token" value={bootstrapToken} onChange={e => setBootstrapToken(e.target.value)} />
          <input style={input} placeholder="Admin username" value={username} onChange={e => setUsername(e.target.value)} />
          <input style={input} placeholder="Admin email" value={email} onChange={e => setEmail(e.target.value)} />
          <input style={input} type="password" placeholder="Password (min 8)" value={password} onChange={e => setPassword(e.target.value)} />
          {err && <div style={errStyle}>{err}</div>}
          <div style={{ marginTop: 14 }}>
            <button style={btn} disabled={busy} onClick={() => setStep('team-url')}>Back</button>
            <button style={primary} disabled={busy || !bootstrapToken || !username || password.length < 8} onClick={doBootstrap}>
              {busy ? 'Creating…' : 'Create admin + sign in'}
            </button>
          </div>
        </>
      )}

      {step === 'team-login' && (
        <>
          <h2>Sign in</h2>
          <p>Reached <code>{serverUrl}</code>. Enter your VulnForge credentials.</p>
          <input style={input} placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} />
          <input style={input} type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} />
          {err && <div style={errStyle}>{err}</div>}
          <div style={{ marginTop: 14 }}>
            <button style={btn} disabled={busy} onClick={() => setStep('team-url')}>Back</button>
            <button style={primary} disabled={busy || !username || !password} onClick={doLogin}>
              {busy ? 'Signing in…' : 'Sign in'}
            </button>
          </div>
        </>
      )}
    </div>
  );
}
