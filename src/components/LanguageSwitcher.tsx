import { useState, useEffect, useRef, type CSSProperties } from 'react';
import i18n from '@/i18n';
import manifest from '@/locales/manifest.json';
import { applyDocumentDirection } from '@/i18n/rtl';

/**
 * LanguageSwitcher - compact dropdown for picking the UI language.
 * On selection: persists to localStorage, calls i18next.changeLanguage,
 * and updates document.dir for RTL locales.
 */

const STORAGE_KEY = 'vulnforge.lang';

interface LanguageMeta {
  code: string;
  name: string;
  flag: string;
  dir: 'ltr' | 'rtl';
}

export function LanguageSwitcher() {
  const [open, setOpen] = useState(false);
  const [current, setCurrent] = useState<string>(() => {
    try {
      return localStorage.getItem(STORAGE_KEY) || i18n.language || 'en';
    } catch {
      return i18n.language || 'en';
    }
  });
  const buttonRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function onDocClick(e: MouseEvent): void {
      if (!buttonRef.current || !menuRef.current) return;
      if (
        buttonRef.current.contains(e.target as Node) ||
        menuRef.current.contains(e.target as Node)
      ) {
        return;
      }
      setOpen(false);
    }
    function onKey(e: KeyboardEvent): void {
      if (e.key === 'Escape') setOpen(false);
    }
    document.addEventListener('mousedown', onDocClick);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDocClick);
      document.removeEventListener('keydown', onKey);
    };
  }, []);

  const languages = manifest as LanguageMeta[];
  const currentLang = languages.find((l) => l.code === current) || languages[0];

  async function handleChange(code: string): Promise<void> {
    setCurrent(code);
    setOpen(false);
    try {
      localStorage.setItem(STORAGE_KEY, code);
    } catch {
      /* storage disabled */
    }
    try {
      await i18n.changeLanguage(code);
    } catch (e) {
      console.warn('[LanguageSwitcher] changeLanguage failed:', (e as Error).message);
    }
    applyDocumentDirection(code);
  }

  const button: CSSProperties = {
    background: 'transparent',
    color: 'var(--fg, inherit)',
    border: '1px solid var(--border, #444)',
    padding: '4px 8px',
    borderRadius: 4,
    cursor: 'pointer',
    fontSize: 13,
    display: 'inline-flex',
    alignItems: 'center',
    gap: 6,
  };
  const menu: CSSProperties = {
    position: 'absolute',
    top: '100%',
    insetInlineEnd: 0,
    marginTop: 4,
    background: 'var(--bg, #0b0d12)',
    border: '1px solid var(--border, #444)',
    borderRadius: 4,
    minWidth: 160,
    zIndex: 50,
    boxShadow: '0 4px 12px rgba(0,0,0,0.25)',
  };
  const item: CSSProperties = {
    display: 'flex',
    width: '100%',
    alignItems: 'center',
    gap: 8,
    padding: '6px 10px',
    background: 'transparent',
    border: 'none',
    color: 'var(--fg, inherit)',
    cursor: 'pointer',
    fontSize: 13,
    textAlign: 'start',
  };

  return (
    <div style={{ position: 'relative', display: 'inline-block' }}>
      <button
        ref={buttonRef}
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={`Language: ${currentLang.name}`}
        style={button}
      >
        <span aria-hidden="true">{currentLang.flag}</span>
        <span>{currentLang.name}</span>
      </button>
      {open && (
        <div ref={menuRef} role="listbox" style={menu}>
          {languages.map((lang) => (
            <button
              key={lang.code}
              role="option"
              aria-selected={lang.code === current}
              onClick={() => handleChange(lang.code)}
              style={{
                ...item,
                background: lang.code === current ? 'var(--surface, #222)' : 'transparent',
              }}
            >
              <span aria-hidden="true">{lang.flag}</span>
              <span>{lang.name}</span>
              {lang.code === current && (
                <span aria-hidden="true" style={{ marginInlineStart: 'auto' }}>
                  ✓
                </span>
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export default LanguageSwitcher;
