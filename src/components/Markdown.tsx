import type { CSSProperties, ReactNode } from 'react';
import { highlightReact } from '@/lib/hljs';

/**
 * Minimal, dependency-free markdown renderer. Built so finding
 * descriptions imported from real audit docs (which contain headings,
 * code blocks, bullet lists, emphasis) render as structured text
 * instead of an unreadable wall.
 *
 * We intentionally stay away from react-markdown / remark: they pull
 * in ~60 KB of ESM that VulnForge doesn't need, and we don't want to
 * render untrusted HTML. Only these tokens are supported:
 *
 *   #, ##, ###, ####   headings
 *   - item              unordered list
 *   1. item             ordered list
 *   > quoted            blockquote
 *   **bold**            bold
 *   *italic* or _it_    italic
 *   `inline code`       inline code
 *   ```fenced```        fenced code block (any language, kept verbatim)
 *   [text](url)         link (opens in new tab)
 *   blank line          paragraph break
 *   --- or ***          horizontal rule
 *
 * Anything not matched renders as plain text. Raw HTML in the input is
 * not interpreted - we only emit React element trees, never
 * dangerouslySetInnerHTML, so angle brackets show up as literal text.
 */

interface MarkdownProps {
  children: string | null | undefined;
  /** Override base font size. Default: 13. */
  fontSize?: number;
  /** Wrapper style passthrough. */
  style?: CSSProperties;
}

export function Markdown({ children, fontSize = 13, style }: MarkdownProps) {
  if (!children) return null;
  const blocks = splitBlocks(children);
  return (
    <div style={{ fontSize, lineHeight: 1.6, color: 'var(--text)', ...style }}>
      {blocks.map((b, i) => renderBlock(b, i))}
    </div>
  );
}

// ── Block parsing ─────────────────────────────────────────────────────────

type Block =
  | { kind: 'code'; lang: string; text: string }
  | { kind: 'heading'; level: number; text: string }
  | { kind: 'list'; ordered: boolean; items: string[] }
  | { kind: 'quote'; text: string }
  | { kind: 'hr' }
  | { kind: 'para'; text: string };

/**
 * Split the source into an array of blocks. Honours fenced code
 * blocks (everything between triple-backtick fences stays verbatim,
 * regardless of inner formatting), then groups remaining non-empty
 * lines into paragraphs / lists / headings / quotes.
 */
function splitBlocks(src: string): Block[] {
  const out: Block[] = [];
  const lines = src.replace(/\r\n/g, '\n').split('\n');
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];

    // Fenced code block
    const fence = line.match(/^```\s*([\w-]*)\s*$/);
    if (fence) {
      const lang = fence[1] || '';
      const body: string[] = [];
      i++;
      while (i < lines.length && !/^```\s*$/.test(lines[i])) {
        body.push(lines[i]);
        i++;
      }
      if (i < lines.length) i++;  // skip closing fence
      out.push({ kind: 'code', lang, text: body.join('\n') });
      continue;
    }

    // Blank line → separator
    if (!line.trim()) { i++; continue; }

    // Horizontal rule
    if (/^\s*(?:-{3,}|\*{3,}|_{3,})\s*$/.test(line)) {
      out.push({ kind: 'hr' });
      i++;
      continue;
    }

    // Heading
    const heading = line.match(/^(#{1,4})\s+(.+?)\s*#*\s*$/);
    if (heading) {
      out.push({ kind: 'heading', level: heading[1].length, text: heading[2] });
      i++;
      continue;
    }

    // Blockquote (consecutive `> ` lines)
    if (/^>\s?/.test(line)) {
      const qlines: string[] = [];
      while (i < lines.length && /^>\s?/.test(lines[i])) {
        qlines.push(lines[i].replace(/^>\s?/, ''));
        i++;
      }
      out.push({ kind: 'quote', text: qlines.join('\n') });
      continue;
    }

    // Unordered or ordered list (consecutive list items)
    if (/^\s*(?:[-*+]|\d+\.)\s+/.test(line)) {
      const ordered = /^\s*\d+\./.test(line);
      const items: string[] = [];
      while (
        i < lines.length
        && /^\s*(?:[-*+]|\d+\.)\s+/.test(lines[i])
      ) {
        items.push(lines[i].replace(/^\s*(?:[-*+]|\d+\.)\s+/, ''));
        i++;
      }
      out.push({ kind: 'list', ordered, items });
      continue;
    }

    // Paragraph - keep grabbing non-empty non-special lines.
    const paras: string[] = [];
    while (
      i < lines.length
      && lines[i].trim()
      && !/^```/.test(lines[i])
      && !/^#{1,4}\s+/.test(lines[i])
      && !/^>\s?/.test(lines[i])
      && !/^\s*(?:[-*+]|\d+\.)\s+/.test(lines[i])
    ) {
      paras.push(lines[i]);
      i++;
    }
    if (paras.length) out.push({ kind: 'para', text: paras.join('\n') });
  }
  return out;
}

// ── Block rendering ───────────────────────────────────────────────────────

function renderBlock(b: Block, key: number): ReactNode {
  switch (b.kind) {
    case 'code': {
      // Fenced blocks render with syntax colouring via highlight.js.
      // highlightReact() returns React elements rather than raw HTML,
      // so we don't need to use any raw-HTML injection attribute.
      const tokens = highlightReact(b.text, b.lang);
      return (
        <pre
          key={key}
          style={{
            margin: '10px 0',
            padding: '10px 12px',
            borderRadius: 6,
            background: 'var(--bg)',
            border: '1px solid var(--border)',
            fontFamily: 'ui-monospace, SF Mono, Menlo, Consolas, monospace',
            fontSize: 12,
            lineHeight: 1.5,
            color: 'var(--text)',
            overflow: 'auto',
            whiteSpace: 'pre',
          }}
        >
          {b.lang && (
            <div style={{ color: 'var(--muted)', fontSize: 10, marginBottom: 6 }}>{b.lang}</div>
          )}
          <code className={b.lang ? `language-${b.lang} hljs` : 'hljs'}>
            {tokens}
          </code>
        </pre>
      );
    }
    case 'heading': {
      const size = [0, 18, 16, 14, 13][b.level] || 13;
      return (
        <div
          key={key}
          style={{
            fontSize: size,
            fontWeight: 700,
            margin: '14px 0 6px',
            color: 'var(--text)',
          }}
        >
          {renderInline(b.text)}
        </div>
      );
    }
    case 'list': {
      const Tag = b.ordered ? 'ol' : 'ul';
      return (
        <Tag key={key} style={{ margin: '6px 0', paddingLeft: 22 }}>
          {b.items.map((it, i) => (
            <li key={i} style={{ margin: '2px 0' }}>{renderInline(it)}</li>
          ))}
        </Tag>
      );
    }
    case 'quote':
      return (
        <div
          key={key}
          style={{
            margin: '8px 0',
            padding: '6px 12px',
            borderLeft: '3px solid var(--border)',
            color: 'var(--muted)',
            background: 'color-mix(in srgb, var(--surface-2) 50%, transparent)',
          }}
        >
          {b.text.split('\n').map((l, i) => (
            <div key={i}>{renderInline(l)}</div>
          ))}
        </div>
      );
    case 'hr':
      return <hr key={key} style={{ border: 0, borderTop: '1px solid var(--border)', margin: '12px 0' }} />;
    case 'para':
      // Preserve hard line-breaks inside a paragraph.
      return (
        <p key={key} style={{ margin: '8px 0' }}>
          {b.text.split('\n').map((line, i, arr) => (
            <span key={i}>
              {renderInline(line)}
              {i < arr.length - 1 && <br />}
            </span>
          ))}
        </p>
      );
  }
}

// ── Inline markup ─────────────────────────────────────────────────────────

/**
 * Tokenise a single line for inline markdown. Order matters: we
 * consume code spans first (so backticks don't trigger bold/italic
 * inside them), then bold, italic, links.
 */
function renderInline(text: string): ReactNode[] {
  const out: ReactNode[] = [];
  let rest = text;
  let key = 0;
  // Precedence: `code` > **bold** > *italic* > [link](url)
  const patterns: Array<{ re: RegExp; render: (m: RegExpExecArray) => ReactNode }> = [
    {
      re: /`([^`\n]+)`/,
      render: (m) => (
        <code
          key={key++}
          style={{
            fontFamily: 'ui-monospace, SF Mono, Menlo, Consolas, monospace',
            fontSize: '0.92em',
            background: 'var(--surface-2)',
            padding: '1px 5px',
            borderRadius: 3,
          }}
        >{m[1]}</code>
      ),
    },
    {
      re: /\*\*([^*\n]+)\*\*/,
      render: (m) => <strong key={key++}>{m[1]}</strong>,
    },
    {
      re: /(?:\*|_)([^*_\n]+)(?:\*|_)/,
      render: (m) => <em key={key++}>{m[1]}</em>,
    },
    {
      re: /\[([^\]\n]+)\]\((https?:\/\/[^\s)]+)\)/,
      render: (m) => (
        <a
          key={key++}
          href={m[2]}
          target="_blank"
          rel="noopener noreferrer"
          style={{ color: 'var(--blue)', textDecoration: 'underline' }}
        >{m[1]}</a>
      ),
    },
  ];

  // Find the earliest match across all patterns; emit the text before
  // it as a plain string, then the matched element, then loop on the
  // remainder until nothing matches.
  while (rest) {
    let bestIdx = -1;
    let bestMatch: RegExpExecArray | null = null;
    let bestRender: ((m: RegExpExecArray) => ReactNode) | null = null;
    for (const p of patterns) {
      const m = p.re.exec(rest);
      if (m && (bestIdx === -1 || m.index < bestIdx)) {
        bestIdx = m.index;
        bestMatch = m;
        bestRender = p.render;
      }
    }
    if (!bestMatch || !bestRender) {
      out.push(rest);
      break;
    }
    if (bestIdx > 0) out.push(rest.slice(0, bestIdx));
    out.push(bestRender(bestMatch));
    rest = rest.slice(bestIdx + bestMatch[0].length);
  }
  return out;
}
