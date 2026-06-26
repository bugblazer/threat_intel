// components/ui/index.jsx — Reusable UI primitives

export function SeverityBadge({ severity }) {
  if (!severity) return null;
  const s = severity.toLowerCase();
  return <span className={`badge badge-${s}`}>{severity}</span>;
}

export function TypeBadge({ type }) {
  return <span className="badge badge-cyan">{type}</span>;
}

export function Spinner({ size = 20 }) {
  return (
    <div
      className="spinner"
      style={{ width: size, height: size }}
      role="status"
      aria-label="Loading"
    />
  );
}

export function EmptyState({ icon: Icon, message, sub }) {
  return (
    <div className="state-container">
      {Icon && <Icon size={40} />}
      <div className="state-message">{message}</div>
      {sub && <div style={{ fontSize: 12 }}>{sub}</div>}
    </div>
  );
}

export function LoadingState() {
  return (
    <div className="state-container">
      <Spinner size={28} />
      <div className="state-message">Loading…</div>
    </div>
  );
}

export function Pagination({ page, total, limit, onPage }) {
  const totalPages = Math.ceil(total / limit);
  if (totalPages <= 1) return null;

  return (
    <div className="pagination">
      <span>
        {(page - 1) * limit + 1}–{Math.min(page * limit, total)} of {total.toLocaleString()}
      </span>
      <div className="pagination-controls">
        <button
          className="btn btn-ghost"
          style={{ padding: '4px 10px', fontSize: 12 }}
          onClick={() => onPage(page - 1)}
          disabled={page === 1}
        >
          ← Prev
        </button>
        <button
          className="btn btn-ghost"
          style={{ padding: '4px 10px', fontSize: 12 }}
          onClick={() => onPage(page + 1)}
          disabled={page >= totalPages}
        >
          Next →
        </button>
      </div>
    </div>
  );
}

export function CvssScore({ score }) {
  if (score == null) return <span style={{ color: 'var(--text-muted)' }}>—</span>;
  const color =
    score >= 9 ? 'var(--critical)' :
    score >= 7 ? 'var(--high)' :
    score >= 4 ? 'var(--medium)' : 'var(--low)';
  return (
    <span
      className="mono"
      style={{ color, fontWeight: 700, fontSize: 13 }}
    >
      {Number(score).toFixed(1)}
    </span>
  );
}

export function MonoId({ children }) {
  return (
    <span className="mono" style={{ color: 'var(--cyan)', fontSize: 12 }}>
      {children}
    </span>
  );
}
