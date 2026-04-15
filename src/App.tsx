import { useState, useEffect, useCallback } from 'react';
import { ToastProvider } from '@/components/Toast';
import { ErrorBoundary } from '@/components/ErrorBoundary';
import Dashboard from '@/pages/Dashboard';
import Findings from '@/pages/Findings';
import Scanner from '@/pages/Scanner';
import Projects from '@/pages/Projects';
import Tools from '@/pages/Tools';
import Checklists from '@/pages/Checklists';
import AIPage from '@/pages/AIPage';
import Plugins from '@/pages/Plugins';
import Settings from '@/pages/Settings';
import Hunt from '@/pages/Hunt';
import ReviewQueue from '@/pages/ReviewQueue';
import HypothesisBoard from '@/pages/HypothesisBoard';
import Runtime from '@/pages/Runtime';
import History from '@/pages/History';
import Exploits from '@/pages/Exploits';
import Investigate from '@/pages/Investigate';
import Disclosure from '@/pages/Disclosure';
import { QuickCapture } from '@/components/QuickCapture';
import { CommandPalette, type Command } from '@/components/CommandPalette';
import { ShortcutOverlay } from '@/components/ShortcutOverlay';

type Page = 'dashboard' | 'findings' | 'scanner' | 'projects' | 'tools' | 'checklists' | 'ai' | 'plugins' | 'settings' | 'hunt' | 'review' | 'hypotheses' | 'runtime' | 'history' | 'exploits' | 'investigate' | 'disclosure';

const VALID_PAGES = new Set<Page>(['dashboard', 'findings', 'scanner', 'projects', 'tools', 'checklists', 'ai', 'plugins', 'settings', 'hunt', 'review', 'hypotheses', 'runtime', 'history', 'exploits', 'investigate', 'disclosure']);

function hashToPage(hash: string): Page {
  const raw = hash.replace(/^#/, '') as Page;
  return VALID_PAGES.has(raw) ? raw : 'dashboard';
}

// ── Inline SVG icons (16×16 viewBox) ─────────────────────────────────────

const ICONS: Record<Page, React.ReactElement> = {
  dashboard: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect x="1" y="1" width="6" height="6" rx="1" stroke="currentColor" strokeWidth="1.4"/>
      <rect x="9" y="1" width="6" height="6" rx="1" stroke="currentColor" strokeWidth="1.4"/>
      <rect x="1" y="9" width="6" height="6" rx="1" stroke="currentColor" strokeWidth="1.4"/>
      <rect x="9" y="9" width="6" height="6" rx="1" stroke="currentColor" strokeWidth="1.4"/>
    </svg>
  ),
  findings: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M8 1.5a6.5 6.5 0 100 13A6.5 6.5 0 008 1.5z" stroke="currentColor" strokeWidth="1.4"/>
      <path d="M8 5v3.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"/>
      <circle cx="8" cy="11" r="0.75" fill="currentColor"/>
    </svg>
  ),
  scanner: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="7" cy="7" r="4.5" stroke="currentColor" strokeWidth="1.4"/>
      <path d="M10.5 10.5L14 14" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"/>
    </svg>
  ),
  projects: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M1.5 4.5a1 1 0 011-1H6l1.5 2H13.5a1 1 0 011 1v6a1 1 0 01-1 1h-11a1 1 0 01-1-1V4.5z" stroke="currentColor" strokeWidth="1.4"/>
    </svg>
  ),
  tools: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M10.5 2a3.5 3.5 0 00-3.3 4.6L2 11.8A1.2 1.2 0 003.7 13.5l5.2-5.2A3.5 3.5 0 0010.5 2z" stroke="currentColor" strokeWidth="1.3" strokeLinejoin="round"/>
      <circle cx="10.5" cy="5.5" r="1" fill="currentColor"/>
    </svg>
  ),
  checklists: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect x="2" y="2" width="12" height="12" rx="1.5" stroke="currentColor" strokeWidth="1.4"/>
      <path d="M5 8l2 2 4-4" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  ),
  ai: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="8" cy="8" r="3" stroke="currentColor" strokeWidth="1.4"/>
      <path d="M8 1v2M8 13v2M1 8h2M13 8h2" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"/>
      <path d="M3.5 3.5l1.4 1.4M11.1 11.1l1.4 1.4M3.5 12.5l1.4-1.4M11.1 4.9l1.4-1.4" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/>
    </svg>
  ),
  plugins: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect x="2" y="5" width="8" height="7" rx="1" stroke="currentColor" strokeWidth="1.4"/>
      <path d="M10 7.5h1.5a1.5 1.5 0 000-3H10" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"/>
      <path d="M5 5V3.5a1.5 1.5 0 013 0V5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"/>
    </svg>
  ),
  hunt: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="1.4"/>
      <circle cx="8" cy="8" r="3" stroke="currentColor" strokeWidth="1.2"/>
      <circle cx="8" cy="8" r="0.8" fill="currentColor"/>
    </svg>
  ),
  review: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect x="2" y="2" width="12" height="12" rx="1.5" stroke="currentColor" strokeWidth="1.4"/>
      <path d="M5 8h6M5 5.5h6M5 10.5h3" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/>
    </svg>
  ),
  hypotheses: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M8 1.8c-2.4 0-4.3 1.9-4.3 4.3 0 1.5.7 2.8 1.9 3.6v1.2c0 .4.3.7.7.7h3.4c.4 0 .7-.3.7-.7v-1.2c1.2-.8 1.9-2.1 1.9-3.6 0-2.4-1.9-4.3-4.3-4.3z" stroke="currentColor" strokeWidth="1.3" strokeLinejoin="round"/>
      <path d="M6.3 13.5h3.4M7 15h2" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/>
    </svg>
  ),
  runtime: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect x="1.5" y="2.5" width="13" height="10" rx="1" stroke="currentColor" strokeWidth="1.3"/>
      <path d="M4 6l2 2-2 2M7.5 10h4.5" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  ),
  history: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="1.3"/>
      <path d="M8 4.5V8l2.5 2" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/>
    </svg>
  ),
  exploits: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M2 14l4-4M6 10l4-4M10 6l4-4" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"/>
      <path d="M10 2l4 4-2 2-4-4 2-2z" stroke="currentColor" strokeWidth="1.3" strokeLinejoin="round"/>
    </svg>
  ),
  investigate: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="7" cy="7" r="4.5" stroke="currentColor" strokeWidth="1.4"/>
      <path d="M10.5 10.5L14 14" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"/>
      <circle cx="7" cy="7" r="1" fill="currentColor"/>
    </svg>
  ),
  disclosure: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M2 3h12v10H2z" stroke="currentColor" strokeWidth="1.3"/>
      <path d="M2 4l6 5 6-5" stroke="currentColor" strokeWidth="1.3" strokeLinejoin="round"/>
    </svg>
  ),
  settings: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="8" cy="8" r="2" stroke="currentColor" strokeWidth="1.4"/>
      <path d="M8 1.5V3M8 13v1.5M1.5 8H3M13 8h1.5M3.2 3.2l1.1 1.1M11.7 11.7l1.1 1.1M3.2 12.8l1.1-1.1M11.7 4.3l1.1-1.1" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/>
    </svg>
  ),
};

interface NavItem { id: Page; label: string }

const navItems: NavItem[] = [
  { id: 'hunt',       label: 'Hunt'       },
  { id: 'dashboard',  label: 'Dashboard'  },
  { id: 'findings',   label: 'Findings'   },
  { id: 'hypotheses', label: 'Hypotheses' },
  { id: 'review',     label: 'Review'     },
  { id: 'runtime',    label: 'Runtime'    },
  { id: 'exploits',   label: 'Exploits'   },
  { id: 'investigate',label: 'Investigate'},
  { id: 'disclosure', label: 'Disclosure' },
  { id: 'history',    label: 'History'    },
  { id: 'scanner',    label: 'Scanner'    },
  { id: 'projects',   label: 'Projects'   },
  { id: 'tools',      label: 'Tools'      },
  { id: 'checklists', label: 'Checklists' },
  { id: 'ai',         label: 'AI'         },
  { id: 'plugins',    label: 'Plugins'    },
  { id: 'settings',   label: 'Settings'   },
];

export default function App() {
  const [page, setPage] = useState<Page>(() => hashToPage(window.location.hash));
  const [searchQuery, setSearchQuery] = useState('');
  const [navExtra, setNavExtra] = useState<unknown>(null);
  const [quickCaptureOpen, setQuickCaptureOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [shortcutOverlayOpen, setShortcutOverlayOpen] = useState(false);

  // ── Hash-based routing ─────────────────────────────────────────────────

  // Keep hash in sync when page state changes (e.g. from navigate())
  useEffect(() => {
    const next = `#${page}`;
    if (window.location.hash !== next) {
      window.location.hash = next;
    }
  }, [page]);

  // React to back/forward and direct URL changes
  useEffect(() => {
    const onHashChange = () => {
      setPage(hashToPage(window.location.hash));
      setNavExtra(null);
    };
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  // ── Navigation helpers ─────────────────────────────────────────────────

  const navigate = useCallback((target: string, extra?: unknown) => {
    setPage(target as Page);
    setNavExtra(extra ?? null);
  }, []);

  const handleNav = (id: Page) => {
    setPage(id);
    setNavExtra(null);
    setSearchQuery('');
  };

  // ── Global keyboard shortcuts ──────────────────────────────────────────

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const inInput = e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement;
      if (e.key === '/' && !inInput) {
        e.preventDefault();
        document.getElementById('global-search')?.focus();
      }
      if (e.key === 'Escape') {
        setSearchQuery('');
        (document.getElementById('global-search') as HTMLInputElement | null)?.blur();
      }
      // Global Ctrl/Cmd+N -> open QuickCapture. Works even inside inputs.
      if ((e.ctrlKey || e.metaKey) && (e.key === 'n' || e.key === 'N')) {
        e.preventDefault();
        setQuickCaptureOpen(true);
      }
      // Ctrl/Cmd+K -> command palette
      if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault();
        setPaletteOpen(true);
      }
      // ? -> shortcut overlay (only outside inputs)
      if (e.key === '?' && !inInput && !e.ctrlKey && !e.metaKey) {
        e.preventDefault();
        setShortcutOverlayOpen(true);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  return (
    <ToastProvider>
      <div style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
        {/* Sidebar */}
        <nav style={{
          width: 200,
          background: 'var(--surface)',
          borderRight: '1px solid var(--border)',
          display: 'flex',
          flexDirection: 'column',
          padding: '16px 0',
          flexShrink: 0,
        }}>
          {/* Brand */}
          <div style={{ padding: '0 16px 20px', borderBottom: '1px solid var(--border)', marginBottom: 8 }}>
            <h1 style={{ color: 'var(--blue)', fontSize: 17, fontWeight: 700, margin: 0, letterSpacing: '-0.3px' }}>
              VulnForge
            </h1>
            <p style={{ color: 'var(--muted)', fontSize: 10, margin: '3px 0 0', letterSpacing: '0.3px', textTransform: 'uppercase' }}>
              Security Research
            </p>
          </div>

          {/* Nav items */}
          {navItems.map(item => (
            <button
              key={item.id}
              onClick={() => handleNav(item.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 9,
                padding: '8px 16px',
                border: 'none',
                background: page === item.id ? 'var(--surface-2)' : item.id === 'hunt' ? 'var(--green)11' : 'transparent',
                color: page === item.id ? 'var(--text)' : item.id === 'hunt' ? 'var(--green)' : 'var(--muted)',
                cursor: 'pointer',
                fontSize: 13,
                textAlign: 'left',
                width: '100%',
                borderLeft: page === item.id ? '2px solid var(--blue)' : '2px solid transparent',
                transition: 'color 0.12s, background 0.12s',
              }}
              onMouseEnter={e => {
                if (page !== item.id) (e.currentTarget as HTMLButtonElement).style.color = 'var(--text)';
              }}
              onMouseLeave={e => {
                if (page !== item.id) (e.currentTarget as HTMLButtonElement).style.color = 'var(--muted)';
              }}
            >
              <span style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                width: 16,
                height: 16,
                flexShrink: 0,
                color: 'inherit',
                opacity: page === item.id ? 1 : 0.7,
              }}>
                {ICONS[item.id]}
              </span>
              <span>{item.label}</span>
            </button>
          ))}

          {/* Bottom version */}
          <div style={{ marginTop: 'auto', padding: '12px 16px', borderTop: '1px solid var(--border)' }}>
            <span style={{ fontSize: 10, color: 'var(--muted)', letterSpacing: '0.3px' }}>v0.1.0</span>
          </div>
        </nav>

        {/* Main content */}
        <main style={{ flex: 1, overflow: 'auto', display: 'flex', flexDirection: 'column' }}>
          {/* Header */}
          <header style={{
            padding: '10px 24px',
            borderBottom: '1px solid var(--border)',
            display: 'flex',
            alignItems: 'center',
            gap: 16,
            background: 'var(--surface)',
            position: 'sticky',
            top: 0,
            zIndex: 10,
            flexShrink: 0,
          }}>
            <input
              id="global-search"
              type="text"
              placeholder="Search findings... (press /)"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              onKeyDown={e => {
                if (e.key === 'Enter' && searchQuery.trim()) {
                  navigate('findings');
                }
              }}
              style={{
                flex: 1,
                maxWidth: 440,
                background: 'var(--bg)',
                border: '1px solid var(--border)',
                borderRadius: 6,
                padding: '7px 12px',
                color: 'var(--text)',
                fontSize: 13,
                outline: 'none',
              }}
            />
            <div style={{ marginLeft: 'auto', display: 'flex', gap: 10, alignItems: 'center' }}>
              <span style={{ fontSize: 10, color: 'var(--muted)', letterSpacing: '0.3px' }}>
                Press <kbd style={kbdStyle}>/</kbd> to search, <kbd style={kbdStyle}>Esc</kbd> to dismiss
              </span>
            </div>
          </header>

          {/* Page content */}
          <div style={{ flex: 1, padding: 24, overflow: 'auto' }}>
            <ErrorBoundary>
              <PageContent
                page={page}
                searchQuery={searchQuery}
                navExtra={navExtra}
                onNavigate={navigate}
              />
            </ErrorBoundary>
          </div>
        </main>
      </div>

      {/* Global QuickCapture — opened via Ctrl/Cmd+N from anywhere */}
      <QuickCapture
        open={quickCaptureOpen}
        onClose={() => setQuickCaptureOpen(false)}
      />

      {/* Command palette — Ctrl/Cmd+K */}
      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        commands={buildCommands(setQuickCaptureOpen, setShortcutOverlayOpen, navigate)}
      />

      {/* Shortcut overlay — ? key */}
      <ShortcutOverlay
        open={shortcutOverlayOpen}
        onClose={() => setShortcutOverlayOpen(false)}
      />
    </ToastProvider>
  );
}

function buildCommands(
  setQuickCaptureOpen: (v: boolean) => void,
  setShortcutOverlayOpen: (v: boolean) => void,
  navigate: (page: string, extra?: unknown) => void,
): Command[] {
  const nav = (page: Page): Command => ({
    id: `nav-${page}`,
    title: `Go to ${navItems.find(n => n.id === page)?.label || page}`,
    category: 'Navigate',
    action: () => navigate(page),
  });

  return [
    // Navigation
    nav('hunt'),
    nav('dashboard'),
    nav('findings'),
    nav('hypotheses'),
    nav('review'),
    nav('runtime'),
    nav('exploits'),
    nav('investigate'),
    nav('history'),
    nav('scanner'),
    nav('projects'),
    nav('tools'),
    nav('checklists'),
    nav('ai'),
    nav('plugins'),
    nav('settings'),

    // Actions
    {
      id: 'new-note',
      title: 'Quick-capture note',
      category: 'Actions',
      shortcut: 'Ctrl+N',
      action: () => setQuickCaptureOpen(true),
    },
    {
      id: 'shortcuts',
      title: 'Show keyboard shortcuts',
      category: 'Help',
      shortcut: '?',
      action: () => setShortcutOverlayOpen(true),
    },
  ];
}

interface PageContentProps {
  page: Page;
  searchQuery: string;
  navExtra: unknown;
  onNavigate: (page: string, extra?: unknown) => void;
}

function PageContent({ page, searchQuery, navExtra, onNavigate }: PageContentProps) {
  switch (page) {
    case 'dashboard':
      return <Dashboard onNavigate={onNavigate} />;

    case 'findings':
      return (
        <Findings
          initialVulnId={typeof navExtra === 'number' ? navExtra : null}
          searchQuery={searchQuery}
        />
      );

    case 'scanner': {
      const preSelectedTool =
        navExtra != null && typeof navExtra === 'object' && 'tool' in (navExtra as object)
          ? (navExtra as { tool: string }).tool
          : undefined;
      return (
        <Scanner
          initialTool={preSelectedTool}
          onNavigateToFinding={(id: number) => onNavigate('findings', id)}
        />
      );
    }

    case 'projects':
      return <Projects />;

    case 'tools':
      return (
        <Tools
          onNavigateToScanner={(toolId: string) => onNavigate('scanner', { tool: toolId })}
        />
      );

    case 'checklists':
      return <Checklists />;

    case 'ai':
      return <AIPage />;

    case 'plugins':
      return <Plugins />;

    case 'settings':
      return <Settings />;

    case 'hunt':
      return <Hunt onNavigate={onNavigate} />;

    case 'hypotheses':
      return <HypothesisBoard />;

    case 'runtime':
      return <Runtime />;

    case 'history':
      return <History />;

    case 'exploits':
      return <Exploits />;

    case 'investigate':
      return <Investigate />;

    case 'disclosure':
      return <Disclosure />;

    case 'review': {
      const pipelineId =
        navExtra != null && typeof navExtra === 'object' && 'pipelineId' in (navExtra as object)
          ? (navExtra as { pipelineId: string }).pipelineId
          : undefined;
      return <ReviewQueue pipelineId={pipelineId} onNavigate={onNavigate} />;
    }

    default:
      return null;
  }
}

const kbdStyle: React.CSSProperties = {
  background: 'var(--surface-2)',
  border: '1px solid var(--border)',
  borderRadius: 3,
  padding: '1px 5px',
  fontSize: 10,
  fontFamily: 'monospace',
  color: 'var(--muted)',
};
