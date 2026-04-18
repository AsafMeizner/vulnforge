import { useEffect, useRef } from 'react';

/**
 * Render a file's contents with line numbers and highlight the lines
 * marked by the scanner. Used by the Review UI when a user clicks
 * "View in file" on a finding - it gives the finding enough context
 * (surrounding code) to actually judge whether it's real.
 *
 * Styling is intentionally minimal - monospace font, muted line
 * numbers, accent colour on highlighted lines. Plugging a real
 * syntax-highlighter (prism, shiki) later is a one-file swap.
 */
export interface CodeViewerProps {
  /** Full file contents. Pass an empty string while loading. */
  content: string;
  /** 1-based start line of the vulnerable region. */
  lineStart?: number | null;
  /** 1-based end line (inclusive). Defaults to lineStart. */
  lineEnd?: number | null;
  /** Path label shown in the header (informational only). */
  path?: string;
  /** Extra styling for the outer container. */
  style?: React.CSSProperties;
  /** How many lines of context to show above/below the highlight. Default: all. */
  contextLines?: number;
}

export function CodeViewer({
  content,
  lineStart,
  lineEnd,
  path,
  style,
  contextLines,
}: CodeViewerProps) {
  const highlightRef = useRef<HTMLTableRowElement | null>(null);

  // Auto-scroll the highlighted line into view after mount so the user
  // doesn't need to hunt for it in a long file.
  useEffect(() => {
    if (highlightRef.current) {
      highlightRef.current.scrollIntoView({ block: 'center', behavior: 'smooth' });
    }
  }, [content, lineStart]);

  if (!content) {
    return (
      <div style={{ padding: 16, color: 'var(--muted)', fontSize: 13, ...style }}>
        Loading file&hellip;
      </div>
    );
  }

  const lines = content.split(/\r?\n/);
  const start = lineStart ?? 0;
  const end = lineEnd ?? lineStart ?? 0;

  // If contextLines is set, slice the displayed range so we don't render
  // a 10k-line file blob for a bug on line 42. Otherwise show everything.
  let visibleFrom = 1;
  let visibleTo = lines.length;
  if (contextLines && contextLines > 0 && start > 0) {
    visibleFrom = Math.max(1, start - contextLines);
    visibleTo = Math.min(lines.length, end + contextLines);
  }

  const truncated = visibleFrom > 1 || visibleTo < lines.length;
  const gutterWidth = String(visibleTo).length;

  return (
    <div
      style={{
        border: '1px solid var(--border)',
        borderRadius: 6,
        background: 'var(--bg)',
        overflow: 'hidden',
        fontFamily: 'ui-monospace, SF Mono, Menlo, Consolas, monospace',
        fontSize: 12,
        ...style,
      }}
    >
      {path && (
        <div
          style={{
            padding: '6px 10px',
            borderBottom: '1px solid var(--border)',
            background: 'var(--surface-2)',
            color: 'var(--muted)',
            fontSize: 11,
            display: 'flex',
            justifyContent: 'space-between',
          }}
        >
          <span>{path}</span>
          {truncated && (
            <span>showing lines {visibleFrom}&ndash;{visibleTo} of {lines.length}</span>
          )}
        </div>
      )}
      <div style={{ overflow: 'auto', maxHeight: 520 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', tableLayout: 'fixed' }}>
          <colgroup>
            <col style={{ width: `${gutterWidth + 2}ch` }} />
            <col />
          </colgroup>
          <tbody>
            {lines.slice(visibleFrom - 1, visibleTo).map((line, i) => {
              const lineNumber = visibleFrom + i;
              const highlighted = start > 0 && lineNumber >= start && lineNumber <= end;
              return (
                <tr
                  key={lineNumber}
                  ref={highlighted && lineNumber === start ? highlightRef : undefined}
                  style={{
                    background: highlighted ? 'color-mix(in srgb, var(--yellow) 20%, transparent)' : 'transparent',
                  }}
                >
                  <td
                    style={{
                      textAlign: 'right',
                      padding: '0 10px',
                      color: highlighted ? 'var(--yellow)' : 'var(--muted)',
                      borderRight: '1px solid var(--border)',
                      userSelect: 'none',
                      whiteSpace: 'nowrap',
                      verticalAlign: 'top',
                    }}
                  >
                    {lineNumber}
                  </td>
                  <td
                    style={{
                      padding: '0 10px',
                      whiteSpace: 'pre',
                      color: 'var(--text)',
                      verticalAlign: 'top',
                    }}
                  >
                    {line || '\u00a0'}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
