/**
 * Single source of truth for highlight.js configuration in VulnForge.
 *
 * We pull `highlight.js/lib/common` (~35 languages, includes C/C++,
 * Python, JS/TS, Go, Rust, Java, Ruby, PHP, SQL, shell, diff, yaml,
 * json, xml, markdown) instead of the full bundle or per-language
 * registrations — it's the sweet spot between bundle size and "the
 * language I need is probably there".
 *
 * The github-dark CSS theme ships with highlight.js and matches
 * VulnForge's existing palette exactly (background #0d1117, same
 * accent colours), so no custom theme CSS is needed.
 *
 * Usage:
 *   import { highlight, detectLanguage } from '@/lib/hljs';
 *   const html = highlight(code, 'c');        // single language
 *   const auto = highlight(code);             // auto-detect
 *   const lang = detectLanguage('foo.tsx');   // path → language hint
 *
 * Safety: `highlight()` HTML-escapes the input code inside hljs (then
 * wraps classified tokens in <span class="hljs-..."> tags). Its output
 * is safe to render via React's raw-HTML injection attribute as long
 * as you pass it to a read-only <pre><code> pair. Do NOT render into
 * a <div> with contentEditable or into an attribute value.
 */
import hljs from 'highlight.js/lib/common';
import 'highlight.js/styles/github-dark.css';

// Filename extension → hljs language identifier. Only the ones in
// `common` are useful here; everything else falls back to auto-detect.
const EXT_TO_LANG: Record<string, string> = {
  c: 'c', h: 'c',
  cc: 'cpp', cpp: 'cpp', cxx: 'cpp', hpp: 'cpp', hh: 'cpp',
  py: 'python', pyi: 'python',
  js: 'javascript', mjs: 'javascript', cjs: 'javascript',
  ts: 'typescript', tsx: 'typescript', jsx: 'javascript',
  go: 'go',
  rs: 'rust',
  java: 'java',
  rb: 'ruby',
  php: 'php',
  sql: 'sql',
  sh: 'bash', bash: 'bash', zsh: 'bash',
  ps1: 'powershell',
  yml: 'yaml', yaml: 'yaml',
  json: 'json',
  xml: 'xml', html: 'xml', htm: 'xml',
  md: 'markdown', markdown: 'markdown',
  diff: 'diff', patch: 'diff',
  css: 'css', scss: 'scss',
  kt: 'kotlin', kts: 'kotlin',
  swift: 'swift',
  cs: 'csharp',
  scala: 'scala',
  pl: 'perl',
  lua: 'lua',
  makefile: 'makefile',
  dockerfile: 'dockerfile',
};

/**
 * Derive a language name from a filename (extension) or basename.
 * Returns undefined when nothing obvious matches — callers should
 * then fall back to hljs auto-detect.
 */
export function detectLanguage(pathOrName: string | null | undefined): string | undefined {
  if (!pathOrName) return undefined;
  const base = pathOrName.replace(/\\/g, '/').split('/').pop() || '';
  const lower = base.toLowerCase();
  // Well-known filenames (no extension)
  if (lower === 'makefile' || lower.startsWith('makefile.')) return 'makefile';
  if (lower === 'dockerfile' || lower.startsWith('dockerfile.')) return 'dockerfile';
  const dot = lower.lastIndexOf('.');
  if (dot < 0) return undefined;
  return EXT_TO_LANG[lower.slice(dot + 1)];
}

/**
 * Highlight a chunk of code. Accepts an optional language hint; when
 * omitted or unknown, falls back to hljs auto-detect.
 *
 * Returns an HTML string containing <span class="hljs-..."> tokens.
 * hljs escapes the raw input internally — the string only ever
 * contains safe tag characters, so it's fine to inject into a
 * <pre><code> via React's raw-HTML attribute.
 */
export function highlight(code: string, language?: string): string {
  if (!code) return '';
  try {
    if (language && hljs.getLanguage(language)) {
      return hljs.highlight(code, { language, ignoreIllegals: true }).value;
    }
    return hljs.highlightAuto(code).value;
  } catch {
    // Defensive: escape raw text so a broken tokenizer never falls
    // through to unescaped HTML.
    return code
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }
}

/**
 * Convert the HTML hljs emits into a React element tree. We do this
 * so the Markdown/CodeViewer components can render highlighted code
 * without touching raw-HTML injection APIs. hljs outputs only
 * <span class="hljs-..."> wrappers around pre-escaped text, so the
 * conversion is simple: walk the parsed nodes, emit <span> elements
 * with className set, and recurse into children.
 *
 * Browser-only (uses DOMParser). VulnForge is a Vite SPA so this
 * is fine; if we ever add SSR, this path needs a Node-side parser.
 */
import { createElement, type ReactNode } from 'react';

function nodeToReact(node: ChildNode, key: number): ReactNode {
  if (node.nodeType === 3 /* Node.TEXT_NODE */) {
    // textContent is already decoded HTML entities by the parser,
    // and React will re-escape it when it renders. Safe.
    return node.textContent;
  }
  if (node.nodeType === 1 /* Node.ELEMENT_NODE */) {
    const el = node as Element;
    const tag = el.tagName.toLowerCase();
    const className = el.className || undefined;
    const children: ReactNode[] = [];
    el.childNodes.forEach((child, i) => {
      const rendered = nodeToReact(child, i);
      if (rendered !== null) children.push(rendered);
    });
    return createElement(
      tag === 'span' ? 'span' : tag,
      { key, className },
      ...children,
    );
  }
  return null;
}

/**
 * Highlight code and return it as a React element tree (an array of
 * nodes to drop into a <code> or <pre>). No raw-HTML injection
 * required — all elements are constructed via createElement.
 */
export function highlightReact(code: string, language?: string): ReactNode[] {
  if (!code) return [];
  const html = highlight(code, language);
  try {
    const parser = new DOMParser();
    const doc = parser.parseFromString(
      `<!doctype html><body><div id="root">${html}</div></body>`,
      'text/html',
    );
    const root = doc.getElementById('root');
    if (!root) return [code];
    const out: ReactNode[] = [];
    root.childNodes.forEach((child, i) => {
      const r = nodeToReact(child, i);
      if (r !== null) out.push(r);
    });
    return out;
  } catch {
    // If anything goes sideways in parsing, fall back to the plain
    // source so the user still sees their code — unstyled, but not
    // corrupted or missing.
    return [code];
  }
}

export { hljs };
