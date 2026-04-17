/**
 * Setup wizard — the multi-step modal shown on first launch (after
 * `FirstLaunch` has resolved the deployment mode) or on demand from
 * Settings -> Onboarding.
 *
 * Steps:
 *   1. Welcome / product tour placeholder
 *   2. Deployment mode (solo vs team — if the user is on server mode we
 *      defer to FirstLaunch and just show a placeholder)
 *   3. AI provider config (pick one, paste key, test via /api/ai/chat)
 *   4. Language + theme quick-pick (if Track M / Track N primitives are
 *      present on the window we render them; otherwise disabled placeholders)
 *   5. Sample project to explore
 *
 * Completion is recorded in `localStorage['vulnforge.setup.complete']`.
 * The wizard may also persist intermediate state under `vulnforge.setup.draft`.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { apiFetch } from '@/lib/api';

export const SETUP_COMPLETE_KEY = 'vulnforge.setup.complete';
export const SETUP_DRAFT_KEY = 'vulnforge.setup.draft';

type ProviderKey = 'claude' | 'openai' | 'gemini' | 'ollama' | 'claude_cli' | 'skip';

interface ProviderOption {
  key: ProviderKey;
  label: string;
  /** User-facing hint about where to get the key. */
  hint: string;
  /** Whether the provider expects an API key (Ollama does not). */
  requiresKey: boolean;
  /** Placeholder shown in the key input. */
  keyPlaceholder?: string;
}

const PROVIDERS: ProviderOption[] = [
  { key: 'claude', label: 'Anthropic Claude', hint: 'console.anthropic.com', requiresKey: true, keyPlaceholder: 'sk-ant-...' },
  { key: 'openai', label: 'OpenAI', hint: 'platform.openai.com', requiresKey: true, keyPlaceholder: 'sk-...' },
  { key: 'gemini', label: 'Google Gemini', hint: 'aistudio.google.com', requiresKey: true, keyPlaceholder: 'AI...' },
  { key: 'ollama', label: 'Local Ollama', hint: 'runs locally — no key required', requiresKey: false },
  { key: 'claude_cli', label: 'Claude CLI', hint: 'delegates to the `claude` binary on PATH', requiresKey: false },
  { key: 'skip' as any, label: 'Skip — manual review only', hint: 'review raw scanner findings by hand; add AI later', requiresKey: false },
];

export type DeploymentPick = 'solo' | 'team' | 'skip';

export interface WizardDraft {
  deployment?: DeploymentPick;
  provider?: ProviderKey;
  apiKey?: string;
  language?: string;
  theme?: string;
  finishedSteps: number[];
}

export interface SetupWizardProps {
  /**
   * Controlled open flag. Defaults to auto (show on first launch if the
   * `SETUP_COMPLETE_KEY` flag is not set).
   */
  open?: boolean;
  /** Called when the user dismisses the wizard (any exit route). */
  onClose?: () => void;
  /** Called when the user presses "Get started" on the final step. */
  onComplete?: (draft: WizardDraft) => void;
  /** When true, re-show the wizard even if previously completed. */
  force?: boolean;
  /**
   * Override the test-provider call. Primarily for tests — defaults to a
   * fetch against `/api/ai/chat`.
   */
  testProvider?: (provider: ProviderKey, apiKey: string) => Promise<{ ok: boolean; message: string }>;
}

/** Read the persisted completion flag. Safe in non-browser environments. */
export function isSetupComplete(): boolean {
  try {
    return typeof localStorage !== 'undefined' && localStorage.getItem(SETUP_COMPLETE_KEY) === '1';
  } catch {
    return false;
  }
}

/** Mark the wizard complete. */
export function markSetupComplete(): void {
  try {
    if (typeof localStorage !== 'undefined') localStorage.setItem(SETUP_COMPLETE_KEY, '1');
  } catch {
    /* ignore */
  }
}

/** Clear the completion flag — called from Settings -> "Run onboarding again". */
export function clearSetupComplete(): void {
  try {
    if (typeof localStorage !== 'undefined') localStorage.removeItem(SETUP_COMPLETE_KEY);
  } catch {
    /* ignore */
  }
}

function loadDraft(): WizardDraft {
  try {
    if (typeof localStorage === 'undefined') return { finishedSteps: [] };
    const raw = localStorage.getItem(SETUP_DRAFT_KEY);
    if (!raw) return { finishedSteps: [] };
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return { finishedSteps: [] };
    return {
      deployment: parsed.deployment,
      provider: parsed.provider,
      apiKey: parsed.apiKey,
      language: parsed.language,
      theme: parsed.theme,
      finishedSteps: Array.isArray(parsed.finishedSteps) ? parsed.finishedSteps.filter((n: unknown) => typeof n === 'number') : [],
    };
  } catch {
    return { finishedSteps: [] };
  }
}

function saveDraft(draft: WizardDraft): void {
  try {
    if (typeof localStorage === 'undefined') return;
    localStorage.setItem(SETUP_DRAFT_KEY, JSON.stringify(draft));
  } catch {
    /* ignore */
  }
}

/** Default test handler — POSTs a short prompt to /api/ai/chat. */
async function defaultTestProvider(
  _provider: ProviderKey,
  _apiKey: string,
): Promise<{ ok: boolean; message: string }> {
  try {
    const res = await apiFetch('/api/ai/chat', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        messages: [
          { role: 'user', content: 'Respond with only the word OK if you are configured correctly.' },
        ],
      }),
    });
    if (!res.ok) {
      return { ok: false, message: `Server returned HTTP ${res.status}` };
    }
    const data = (await res.json().catch(() => null)) as { response?: string } | null;
    const response = (data?.response ?? '').trim();
    if (!response) return { ok: false, message: 'No response text returned.' };
    return { ok: true, message: response.slice(0, 80) };
  } catch (err: any) {
    return { ok: false, message: err?.message ?? 'Network error' };
  }
}

// ────────────────────────────────────────────────────────────────────────
// Track-M / Track-N hand-off points.
//
// These tracks own `src/i18n/` and `src/themes/` respectively. If those
// modules have been mounted on `window.__vulnforgeOnboarding` by the
// integrator, the wizard uses them. Otherwise we render disabled placeholders.
// ────────────────────────────────────────────────────────────────────────

interface OnboardingHooks {
  listLanguages?: () => Array<{ code: string; label: string }>;
  setLanguage?: (code: string) => void;
  listThemes?: () => Array<{ id: string; label: string }>;
  setTheme?: (id: string) => void;
}

function getHooks(): OnboardingHooks {
  if (typeof window === 'undefined') return {};
  return ((window as any).__vulnforgeOnboarding as OnboardingHooks | undefined) || {};
}

// ────────────────────────────────────────────────────────────────────────

type StepId = 0 | 1 | 2 | 3 | 4;

export function SetupWizard(props: SetupWizardProps) {
  const {
    open: openProp,
    onClose,
    onComplete,
    force = false,
    testProvider = defaultTestProvider,
  } = props;

  // Controlled vs auto-open. When uncontrolled, we auto-open on first load
  // unless the completion flag is already set (or `force` is true).
  const [internalOpen, setInternalOpen] = useState<boolean>(() => force || !isSetupComplete());
  const open = typeof openProp === 'boolean' ? openProp : internalOpen;

  const [step, setStep] = useState<StepId>(0);
  const [draft, setDraft] = useState<WizardDraft>(() => loadDraft());
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string } | null>(null);
  const closedRef = useRef(false);

  // Persist draft on every change.
  useEffect(() => {
    saveDraft(draft);
  }, [draft]);

  // Reset transient per-session state whenever we (re)open.
  useEffect(() => {
    if (open) {
      setStep(0);
      setTestResult(null);
      closedRef.current = false;
    }
  }, [open]);

  const close = useCallback(
    (finished: boolean) => {
      if (closedRef.current) return;
      closedRef.current = true;
      if (finished) {
        markSetupComplete();
        onComplete?.(draft);
      }
      if (typeof openProp !== 'boolean') setInternalOpen(false);
      onClose?.();
    },
    [draft, onClose, onComplete, openProp],
  );

  const finishLater = useCallback(() => {
    // "Finish later" closes but does NOT mark complete — so we also write
    // the flag so we don't pester the user on every reload. The spec says
    // the wizard is only re-shown when re-invoked from Settings, so we
    // mark complete here and surface the "re-run" affordance elsewhere.
    markSetupComplete();
    close(false);
  }, [close]);

  const goto = useCallback((next: StepId) => {
    setStep(next);
    setTestResult(null);
  }, []);

  const markStepDone = useCallback(
    (id: StepId) => {
      setDraft(prev => {
        if (prev.finishedSteps.includes(id)) return prev;
        return { ...prev, finishedSteps: [...prev.finishedSteps, id] };
      });
    },
    [setDraft],
  );

  const next = useCallback(() => {
    markStepDone(step);
    if (step < 4) goto((step + 1) as StepId);
    else close(true);
  }, [step, goto, close, markStepDone]);

  const prev = useCallback(() => {
    if (step > 0) goto((step - 1) as StepId);
  }, [step, goto]);

  const runTest = useCallback(async () => {
    if (!draft.provider) {
      setTestResult({ ok: false, message: 'Pick a provider first.' });
      return;
    }
    // "skip" = no AI. Mark the test as a pseudo-success so the wizard
    // lets the user move on. The actual skip is recorded when the user
    // clicks Finish - no provider row is inserted.
    if (draft.provider === 'skip') {
      setTestResult({ ok: true, message: 'Running without AI — findings will come back as pending for manual review.' });
      return;
    }
    const pOpt = PROVIDERS.find(p => p.key === draft.provider);
    if (pOpt?.requiresKey && !draft.apiKey) {
      setTestResult({ ok: false, message: 'Paste the API key first.' });
      return;
    }
    setTesting(true);
    setTestResult(null);
    try {
      const r = await testProvider(draft.provider, draft.apiKey ?? '');
      setTestResult(r);
    } catch (e: any) {
      setTestResult({ ok: false, message: e?.message ?? 'Test failed' });
    } finally {
      setTesting(false);
    }
  }, [draft.provider, draft.apiKey, testProvider]);

  // Esc-to-close (finish later)
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        finishLater();
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [open, finishLater]);

  const canGoNext = useMemo(() => {
    if (step === 2) {
      // Must have picked a provider to proceed, but a successful test is
      // not required — we respect the user's "my key works, trust me" choice.
      return !!draft.provider;
    }
    return true;
  }, [step, draft.provider]);

  if (!open) return null;

  return (
    <div
      data-testid="setup-wizard-root"
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.72)',
        zIndex: 2300,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 24,
      }}
    >
      <div
        role="dialog"
        aria-labelledby="setup-wizard-title"
        style={{
          background: 'var(--surface)',
          border: '1px solid var(--border)',
          borderRadius: 14,
          width: '100%',
          maxWidth: 720,
          maxHeight: '90vh',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: '18px 24px',
            borderBottom: '1px solid var(--border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div>
            <h2 id="setup-wizard-title" style={{ margin: 0, fontSize: 18, color: 'var(--text)' }}>
              Get started with VulnForge
            </h2>
            <div style={{ marginTop: 4, fontSize: 11, color: 'var(--muted)' }}>
              Step {step + 1} of 5
            </div>
          </div>
          <button
            type="button"
            onClick={finishLater}
            style={{
              padding: '6px 12px',
              background: 'transparent',
              border: '1px solid var(--border)',
              borderRadius: 6,
              color: 'var(--muted)',
              fontSize: 12,
              cursor: 'pointer',
            }}
          >
            Finish later
          </button>
        </div>

        {/* Progress bar */}
        <Progress step={step} />

        {/* Body */}
        <div style={{ padding: 24, overflow: 'auto', flex: 1 }}>
          {step === 0 && <StepWelcome />}
          {step === 1 && (
            <StepDeployment
              value={draft.deployment}
              onChange={dep => setDraft(prev => ({ ...prev, deployment: dep }))}
            />
          )}
          {step === 2 && (
            <StepProvider
              draft={draft}
              onProviderChange={p => setDraft(prev => ({ ...prev, provider: p }))}
              onKeyChange={k => setDraft(prev => ({ ...prev, apiKey: k }))}
              onTest={runTest}
              testing={testing}
              testResult={testResult}
            />
          )}
          {step === 3 && (
            <StepLookAndFeel
              language={draft.language}
              theme={draft.theme}
              onLanguage={lang => setDraft(prev => ({ ...prev, language: lang }))}
              onTheme={theme => setDraft(prev => ({ ...prev, theme }))}
            />
          )}
          {step === 4 && <StepSampleProject />}
        </div>

        {/* Footer */}
        <div
          style={{
            padding: '14px 24px',
            borderTop: '1px solid var(--border)',
            display: 'flex',
            justifyContent: 'space-between',
            gap: 12,
          }}
        >
          <button
            type="button"
            onClick={prev}
            disabled={step === 0}
            style={{
              ...secondaryButtonStyle,
              opacity: step === 0 ? 0.5 : 1,
              cursor: step === 0 ? 'not-allowed' : 'pointer',
            }}
          >
            Previous
          </button>
          <div style={{ display: 'flex', gap: 10 }}>
            <button
              type="button"
              onClick={finishLater}
              style={secondaryButtonStyle}
            >
              Skip
            </button>
            <button
              type="button"
              onClick={next}
              disabled={!canGoNext}
              style={{
                ...primaryButtonStyle,
                opacity: canGoNext ? 1 : 0.5,
                cursor: canGoNext ? 'pointer' : 'not-allowed',
              }}
            >
              {step === 4 ? 'Get started' : 'Next'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────────
// Sub-step renderers
// ────────────────────────────────────────────────────────────────────────

function Progress({ step }: { step: StepId }) {
  const pct = ((step + 1) / 5) * 100;
  return (
    <div style={{ height: 3, background: 'var(--surface-2)' }}>
      <div
        style={{
          width: `${pct}%`,
          height: '100%',
          background: 'var(--blue)',
          transition: 'width 0.2s',
        }}
      />
    </div>
  );
}

function StepWelcome() {
  return (
    <div>
      <h3 style={h3Style}>Welcome to VulnForge.</h3>
      <p style={pStyle}>
        VulnForge is an AI-powered vulnerability research platform. It clones
        a codebase, runs 48 static analysers, and uses AI to triage and verify
        the results — so you spend your time on real bugs, not noise.
      </p>
      <div
        data-testid="setup-product-tour-placeholder"
        style={{
          marginTop: 18,
          padding: 24,
          border: '1px dashed var(--border)',
          borderRadius: 8,
          background: 'var(--surface-2)',
          color: 'var(--muted)',
          fontSize: 12,
          textAlign: 'center',
        }}
      >
        [ product-tour video placeholder — wired later by the integrator ]
      </div>
      <ul style={{ marginTop: 18, color: 'var(--text)', fontSize: 13, lineHeight: 1.7, paddingLeft: 18 }}>
        <li>Deployment mode — solo or team</li>
        <li>AI provider — Claude, OpenAI, Gemini, Ollama, or Claude CLI</li>
        <li>Language and theme</li>
        <li>A sample project to get you started</li>
      </ul>
    </div>
  );
}

function StepDeployment({
  value,
  onChange,
}: {
  value: DeploymentPick | undefined;
  onChange: (v: DeploymentPick) => void;
}) {
  return (
    <div>
      <h3 style={h3Style}>Deployment mode</h3>
      <p style={pStyle}>
        Solo runs everything on this machine with no network dependencies.
        Team mode connects this app to a shared VulnForge server. The full
        server bootstrap flow lives in the existing First-Launch wizard — if
        you pick Team here, we will hand off to it.
      </p>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginTop: 14 }}>
        <Choice
          selected={value === 'solo'}
          onClick={() => onChange('solo')}
          title="Solo"
          description="One user, one machine. No network required. Best for independent researchers."
        />
        <Choice
          selected={value === 'team'}
          onClick={() => onChange('team')}
          title="Team"
          description="Connect to a shared VulnForge server. Detailed bootstrap handled by FirstLaunch."
        />
      </div>
      {value === 'team' && (
        <div
          data-testid="setup-deployment-team-placeholder"
          style={{
            marginTop: 16,
            padding: 14,
            border: '1px solid var(--border)',
            borderRadius: 8,
            background: 'var(--surface-2)',
            fontSize: 12,
            color: 'var(--muted)',
          }}
        >
          Team-mode bootstrap (server URL, admin account, sign-in) is handled
          by the existing FirstLaunch wizard. When you close this dialog the
          integrator will route you there.
        </div>
      )}
    </div>
  );
}

function Choice({
  selected,
  onClick,
  title,
  description,
}: {
  selected: boolean;
  onClick: () => void;
  title: string;
  description: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        textAlign: 'left',
        padding: 14,
        borderRadius: 8,
        border: `1px solid ${selected ? 'var(--blue)' : 'var(--border)'}`,
        background: selected ? 'rgba(88,166,255,0.08)' : 'var(--surface-2)',
        color: 'var(--text)',
        cursor: 'pointer',
      }}
    >
      <div style={{ fontWeight: 600, marginBottom: 4 }}>{title}</div>
      <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.5 }}>{description}</div>
    </button>
  );
}

function StepProvider({
  draft,
  onProviderChange,
  onKeyChange,
  onTest,
  testing,
  testResult,
}: {
  draft: WizardDraft;
  onProviderChange: (p: ProviderKey) => void;
  onKeyChange: (k: string) => void;
  onTest: () => void;
  testing: boolean;
  testResult: { ok: boolean; message: string } | null;
}) {
  const selected = PROVIDERS.find(p => p.key === draft.provider);
  return (
    <div>
      <h3 style={h3Style}>Pick an AI provider</h3>
      <p style={pStyle}>
        VulnForge uses AI for triage, verification and chat. You can add
        multiple providers later under the AI page — for now, pick one to
        get up and running.
      </p>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 10, marginTop: 14 }}>
        {PROVIDERS.map(p => (
          <Choice
            key={p.key}
            selected={draft.provider === p.key}
            onClick={() => onProviderChange(p.key)}
            title={p.label}
            description={p.hint}
          />
        ))}
      </div>
      {selected && selected.requiresKey && (
        <div style={{ marginTop: 18 }}>
          <label style={labelStyle}>API key</label>
          <input
            type="password"
            placeholder={selected.keyPlaceholder ?? 'API key'}
            value={draft.apiKey ?? ''}
            onChange={e => onKeyChange(e.target.value)}
            style={inputStyle}
          />
        </div>
      )}
      <div style={{ marginTop: 14, display: 'flex', alignItems: 'center', gap: 12 }}>
        <button
          type="button"
          onClick={onTest}
          disabled={testing || !draft.provider}
          style={{
            ...secondaryButtonStyle,
            opacity: testing || !draft.provider ? 0.5 : 1,
            cursor: testing || !draft.provider ? 'not-allowed' : 'pointer',
          }}
        >
          {testing ? 'Testing…' : 'Test connection'}
        </button>
        {testResult && (
          <span
            data-testid="setup-provider-test-result"
            style={{
              fontSize: 12,
              color: testResult.ok ? 'var(--green)' : 'var(--red)',
            }}
          >
            {testResult.ok ? 'Works — ' : 'Failed — '}
            {testResult.message}
          </span>
        )}
      </div>
    </div>
  );
}

function StepLookAndFeel({
  language,
  theme,
  onLanguage,
  onTheme,
}: {
  language: string | undefined;
  theme: string | undefined;
  onLanguage: (code: string) => void;
  onTheme: (id: string) => void;
}) {
  const hooks = getHooks();
  const languages = hooks.listLanguages?.() ?? null;
  const themes = hooks.listThemes?.() ?? null;

  return (
    <div>
      <h3 style={h3Style}>Language and theme</h3>
      <p style={pStyle}>
        You can change these anytime from the Settings page. We have picked
        sensible defaults for you.
      </p>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 18, marginTop: 14 }}>
        <div>
          <label style={labelStyle}>Language</label>
          {languages ? (
            <select
              value={language ?? ''}
              onChange={e => {
                onLanguage(e.target.value);
                hooks.setLanguage?.(e.target.value);
              }}
              style={inputStyle}
            >
              <option value="">(system default)</option>
              {languages.map(l => (
                <option key={l.code} value={l.code}>
                  {l.label}
                </option>
              ))}
            </select>
          ) : (
            <DisabledPlaceholder label="Language picker" hint="Install Track M (i18n) to enable." />
          )}
        </div>
        <div>
          <label style={labelStyle}>Theme</label>
          {themes ? (
            <select
              value={theme ?? ''}
              onChange={e => {
                onTheme(e.target.value);
                hooks.setTheme?.(e.target.value);
              }}
              style={inputStyle}
            >
              <option value="">(system default)</option>
              {themes.map(t => (
                <option key={t.id} value={t.id}>
                  {t.label}
                </option>
              ))}
            </select>
          ) : (
            <DisabledPlaceholder label="Theme picker" hint="Install Track N (themes) to enable." />
          )}
        </div>
      </div>
    </div>
  );
}

function DisabledPlaceholder({ label, hint }: { label: string; hint: string }) {
  return (
    <div
      data-testid="setup-lookandfeel-placeholder"
      style={{
        padding: 12,
        border: '1px dashed var(--border)',
        borderRadius: 6,
        background: 'var(--surface-2)',
        color: 'var(--muted)',
        fontSize: 12,
      }}
    >
      <div style={{ fontWeight: 600, color: 'var(--text)', marginBottom: 2 }}>{label}</div>
      <div>{hint}</div>
    </div>
  );
}

function StepSampleProject() {
  return (
    <div>
      <h3 style={h3Style}>Explore a sample project</h3>
      <p style={pStyle}>
        The quickest way to learn VulnForge is to kick off a scan on a
        deliberately-vulnerable codebase. We recommend OWASP Juice Shop —
        it ships with a rich spread of issues that exercise every detector.
      </p>
      <div
        style={{
          marginTop: 14,
          padding: 16,
          border: '1px solid var(--border)',
          borderRadius: 10,
          background: 'var(--surface-2)',
        }}
      >
        <div style={{ fontWeight: 600, marginBottom: 6, color: 'var(--text)' }}>Suggested: OWASP Juice Shop</div>
        <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 10 }}>
          Clone URL: <code style={codeStyle}>https://github.com/juice-shop/juice-shop.git</code>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <a
            href="#scanner"
            style={{ ...primaryButtonStyle, textDecoration: 'none', display: 'inline-block' }}
          >
            Open Scanner page
          </a>
          <a
            href="https://github.com/juice-shop/juice-shop"
            target="_blank"
            rel="noopener noreferrer"
            style={{ ...secondaryButtonStyle, textDecoration: 'none', display: 'inline-block' }}
          >
            View project on GitHub
          </a>
        </div>
      </div>
      <p style={{ ...pStyle, marginTop: 16, fontSize: 12 }}>
        Prefer your own code? Any local directory or git URL works —
        everything runs on this machine in solo mode.
      </p>
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────────
// Shared styles
// ────────────────────────────────────────────────────────────────────────

const h3Style: React.CSSProperties = {
  margin: 0,
  marginBottom: 6,
  fontSize: 16,
  color: 'var(--text)',
};

const pStyle: React.CSSProperties = {
  margin: 0,
  fontSize: 13,
  color: 'var(--muted)',
  lineHeight: 1.55,
};

const labelStyle: React.CSSProperties = {
  display: 'block',
  fontSize: 11,
  color: 'var(--muted)',
  textTransform: 'uppercase',
  letterSpacing: 0.5,
  marginBottom: 6,
};

const inputStyle: React.CSSProperties = {
  width: '100%',
  padding: '9px 12px',
  borderRadius: 6,
  border: '1px solid var(--border)',
  background: 'var(--bg)',
  color: 'var(--text)',
  fontSize: 13,
  boxSizing: 'border-box',
};

const primaryButtonStyle: React.CSSProperties = {
  padding: '8px 18px',
  background: 'var(--blue)',
  color: 'var(--bg)',
  border: '1px solid var(--blue)',
  borderRadius: 6,
  fontSize: 13,
  fontWeight: 600,
  cursor: 'pointer',
};

const secondaryButtonStyle: React.CSSProperties = {
  padding: '8px 18px',
  background: 'transparent',
  color: 'var(--text)',
  border: '1px solid var(--border)',
  borderRadius: 6,
  fontSize: 13,
  cursor: 'pointer',
};

const codeStyle: React.CSSProperties = {
  padding: '2px 6px',
  background: 'var(--bg)',
  borderRadius: 4,
  fontFamily: 'monospace',
  fontSize: 11,
  color: 'var(--text)',
};

export default SetupWizard;
