import { useState, useEffect } from 'react';
import { apiFetch } from '@/lib/api';

interface LoginProps {
  onAuthenticated: (token: string, user: { id: number; username: string; role: string }) => void;
}

export default function Login({ onAuthenticated }: LoginProps) {
  const [mode, setMode] = useState<'login' | 'setup' | 'checking'>('checking');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // Check if setup is needed
  useEffect(() => {
    apiFetch('/api/auth/status')
      .then(r => r.json())
      .then(data => {
        setMode(data.setup_required ? 'setup' : 'login');
      })
      .catch(() => setMode('login'));
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) {
      setError('Username and password required');
      return;
    }
    setError('');
    setLoading(true);

    try {
      const endpoint = mode === 'setup' ? '/api/auth/setup' : '/api/auth/login';
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({ error: res.statusText }));
        throw new Error(body.error || 'Authentication failed');
      }

      const data = await res.json();
      // Store token
      localStorage.setItem('vf_token', data.token);
      localStorage.setItem('vf_user', JSON.stringify(data.user));
      onAuthenticated(data.token, data.user);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  if (mode === 'checking') {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', background: 'var(--bg)' }}>
        <div style={{ color: 'var(--muted)', fontSize: 14 }}>Connecting...</div>
      </div>
    );
  }

  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      height: '100vh', background: 'var(--bg)',
    }}>
      <form onSubmit={handleSubmit} style={{
        width: '100%', maxWidth: 400, padding: 36,
        background: 'var(--surface)', border: '1px solid var(--border)',
        borderRadius: 12,
      }}>
        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: 28 }}>
          <h1 style={{ color: 'var(--blue)', fontSize: 24, fontWeight: 700, margin: 0 }}>VulnForge</h1>
          <p style={{ color: 'var(--muted)', fontSize: 12, margin: '6px 0 0' }}>
            {mode === 'setup'
              ? 'Create your admin account to get started'
              : 'Sign in to your research workspace'}
          </p>
        </div>

        {/* Setup notice */}
        {mode === 'setup' && (
          <div style={{
            background: 'var(--blue)11', border: '1px solid var(--blue)44',
            borderRadius: 6, padding: '10px 14px', marginBottom: 20, fontSize: 12,
            color: 'var(--blue)',
          }}>
            First-time setup. This will be your admin account.
          </div>
        )}

        {/* Username */}
        <div style={{ marginBottom: 14 }}>
          <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4, textTransform: 'uppercase', letterSpacing: 0.5 }}>
            Username
          </label>
          <input
            value={username}
            onChange={e => setUsername(e.target.value)}
            autoFocus
            autoComplete="username"
            style={inputStyle}
          />
        </div>

        {/* Password */}
        <div style={{ marginBottom: 20 }}>
          <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4, textTransform: 'uppercase', letterSpacing: 0.5 }}>
            Password
          </label>
          <input
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            autoComplete={mode === 'setup' ? 'new-password' : 'current-password'}
            style={inputStyle}
          />
          {mode === 'setup' && (
            <div style={{ fontSize: 10, color: 'var(--muted)', marginTop: 4 }}>Minimum 6 characters</div>
          )}
        </div>

        {/* Error */}
        {error && (
          <div style={{
            background: 'var(--red)11', border: '1px solid var(--red)44',
            borderRadius: 6, padding: '8px 12px', marginBottom: 14,
            fontSize: 12, color: 'var(--red)',
          }}>
            {error}
          </div>
        )}

        {/* Submit */}
        <button type="submit" disabled={loading} style={{
          width: '100%', padding: '12px 0',
          background: loading ? 'var(--muted)' : 'var(--blue)', color: '#fff',
          border: 'none', borderRadius: 6, fontSize: 14, fontWeight: 700,
          cursor: loading ? 'wait' : 'pointer',
        }}>
          {loading ? 'Please wait...' : mode === 'setup' ? 'Create Account' : 'Sign In'}
        </button>

        {/* Skip auth hint */}
        <div style={{ textAlign: 'center', marginTop: 16, fontSize: 11, color: 'var(--muted)' }}>
          Single-user mode: works without auth when no users exist
        </div>
      </form>
    </div>
  );
}

const inputStyle: React.CSSProperties = {
  width: '100%', padding: '10px 12px',
  background: 'var(--bg)', border: '1px solid var(--border)',
  borderRadius: 6, color: 'var(--text)', fontSize: 14,
  outline: 'none', boxSizing: 'border-box',
};
