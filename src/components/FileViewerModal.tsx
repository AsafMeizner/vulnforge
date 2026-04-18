import { useEffect, useState } from 'react';
import { CodeViewer } from '@/components/CodeViewer';
import { getProjectFile } from '@/lib/api';

/**
 * Fetches a file from the server via `/projects/:id/file` and renders
 * it in the line-numbered CodeViewer with the vulnerable lines
 * highlighted. Closes on Escape or backdrop click.
 *
 * Lives in its own file so both the Review queue and the Finding
 * Detail page (Suggested Fix -> "View full file" button) can share
 * one implementation instead of copy-pasting.
 */
export function FileViewerModal({
  projectId, path, lineStart, lineEnd, onClose,
}: {
  projectId: number;
  path: string;
  lineStart: number | null;
  lineEnd: number | null;
  onClose: () => void;
}) {
  const [content, setContent] = useState<string>('');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getProjectFile(projectId, path)
      .then((r) => { if (!cancelled) setContent(r.content); })
      .catch((e) => { if (!cancelled) setError(e.message || String(e)); });
    return () => { cancelled = true; };
  }, [projectId, path]);

  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [onClose]);

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)', zIndex: 10000,
        display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: 'var(--surface)', border: '1px solid var(--border)',
          borderRadius: 10, width: 'min(1100px, 95vw)', maxHeight: '88vh',
          overflow: 'hidden', display: 'flex', flexDirection: 'column',
        }}
      >
        <div style={{
          padding: '12px 16px', borderBottom: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <div>
            <strong style={{ color: 'var(--text)' }}>{path}</strong>
            {lineStart && (
              <span style={{ color: 'var(--muted)', marginLeft: 8, fontSize: 12 }}>
                :{lineStart}{lineEnd && lineEnd !== lineStart ? `-${lineEnd}` : ''}
              </span>
            )}
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'transparent', border: 'none', color: 'var(--muted)',
              fontSize: 20, cursor: 'pointer', lineHeight: 1, padding: 0,
            }}
            aria-label="Close"
          >&times;</button>
        </div>
        <div style={{ flex: 1, overflow: 'auto', padding: 16 }}>
          {error ? (
            <div style={{ color: 'var(--red)', fontSize: 13 }}>{error}</div>
          ) : (
            <CodeViewer
              content={content}
              path={path}
              lineStart={lineStart}
              lineEnd={lineEnd}
              contextLines={60}
            />
          )}
        </div>
      </div>
    </div>
  );
}
