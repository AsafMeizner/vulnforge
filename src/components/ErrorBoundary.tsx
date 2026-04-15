import { Component, type ErrorInfo, type ReactNode } from 'react';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  info: ErrorInfo | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null, info: null };

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('[ErrorBoundary] Caught render error:', error, info);
    this.setState({ info });
  }

  reset = () => {
    this.setState({ hasError: false, error: null, info: null });
  };

  render() {
    if (!this.state.hasError) return this.props.children;

    if (this.props.fallback) return this.props.fallback;

    const { error, info } = this.state;

    return (
      <div style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: 300,
        padding: 40,
        gap: 16,
      }}>
        <div style={{
          background: 'var(--surface)',
          border: '1px solid var(--red)',
          borderRadius: 10,
          padding: '28px 32px',
          maxWidth: 600,
          width: '100%',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
            <span style={{ fontSize: 20 }}>!</span>
            <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--red)', margin: 0 }}>
              Something went wrong
            </h3>
          </div>

          <p style={{ fontSize: 13, color: 'var(--text)', margin: '0 0 8px', lineHeight: 1.6 }}>
            This part of the UI hit an unexpected error and could not render.
          </p>

          {error && (
            <pre style={{
              background: 'var(--bg)',
              border: '1px solid var(--border)',
              borderRadius: 6,
              padding: '10px 14px',
              fontSize: 11,
              color: 'var(--red)',
              overflow: 'auto',
              marginBottom: 16,
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word',
              maxHeight: 140,
            }}>
              {error.message}
              {info?.componentStack && (
                '\n\nComponent stack:' + info.componentStack.split('\n').slice(0, 6).join('\n')
              )}
            </pre>
          )}

          <button
            onClick={this.reset}
            style={{
              background: 'var(--blue)',
              border: 'none',
              borderRadius: 6,
              padding: '8px 18px',
              color: '#fff',
              fontSize: 13,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Try again
          </button>
        </div>
      </div>
    );
  }
}

/** Convenience wrapper for inline use */
export function withErrorBoundary(children: ReactNode, fallback?: ReactNode) {
  return <ErrorBoundary fallback={fallback}>{children}</ErrorBoundary>;
}
