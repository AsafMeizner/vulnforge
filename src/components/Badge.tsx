import type { Severity, VulnStatus } from '@/lib/types';

interface BadgeProps {
  children: React.ReactNode;
  color: string;
  bg?: string;
}

function Badge({ children, color, bg }: BadgeProps) {
  return (
    <span style={{
      display: 'inline-block',
      padding: '2px 8px',
      borderRadius: 4,
      fontSize: 11,
      fontWeight: 600,
      letterSpacing: '0.4px',
      textTransform: 'uppercase',
      color,
      background: bg ?? `${color}22`,
      border: `1px solid ${color}44`,
      whiteSpace: 'nowrap',
    }}>
      {children}
    </span>
  );
}

const SEVERITY_COLORS: Record<Severity, string> = {
  Critical: 'var(--red)',
  High: 'var(--orange)',
  Medium: 'var(--yellow)',
  Low: 'var(--muted)',
  Info: 'var(--blue)',
};

const STATUS_COLORS: Record<VulnStatus, string> = {
  New: 'var(--blue)',
  Triaged: 'var(--purple)',
  Submitted: 'var(--orange)',
  Fixed: 'var(--green)',
  Rejected: 'var(--red)',
  'Wont Fix': 'var(--muted)',
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge color={SEVERITY_COLORS[severity] ?? 'var(--muted)'}>{severity}</Badge>;
}

export function StatusBadge({ status }: { status: VulnStatus }) {
  return <Badge color={STATUS_COLORS[status] ?? 'var(--muted)'}>{status}</Badge>;
}

export function CvssScore({ score }: { score: number | string | null | undefined }) {
  const num = typeof score === 'string' ? parseFloat(score) : score;
  if (num === null || num === undefined || isNaN(num) || num === 0) {
    return <span style={{ color: 'var(--muted)' }}>-</span>;
  }
  let color = 'var(--muted)';
  if (num >= 9.0) color = 'var(--red)';
  else if (num >= 7.0) color = 'var(--orange)';
  else if (num >= 4.0) color = 'var(--yellow)';
  else if (num > 0) color = 'var(--green)';
  return (
    <span style={{ color, fontWeight: 700, fontFamily: 'monospace' }}>
      {num.toFixed(1)}
    </span>
  );
}
