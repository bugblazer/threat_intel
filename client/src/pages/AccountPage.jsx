import { useState, useEffect } from 'react';
import { api } from '../lib/api.js';
import { useAuth } from '../hooks/useAuth.jsx';
import { LoadingState, Spinner } from '../components/ui/index.jsx';
import { ArrowUpCircle } from 'lucide-react';

function StatusBadge({ status }) {
  const colors = {
    pending:  { bg: 'var(--high-dim)',     color: 'var(--high)' },
    approved: { bg: 'var(--low-dim)',      color: 'var(--low)' },
    declined: { bg: 'var(--critical-dim)', color: 'var(--critical)' },
  };
  const s = colors[status] ?? colors.pending;
  return (
    <span className="badge" style={{ background: s.bg, color: s.color, border: 'none' }}>
      {status}
    </span>
  );
}

export default function AccountPage() {
  const { user, refreshUser } = useAuth();
  const [reqState, setReqState] = useState(null);   // latest role request or null
  const [loading, setLoading] = useState(true);
  const [saving, setSaving]   = useState(false);
  const [error, setError]     = useState('');

  const load = () =>
    api.myRoleRequest()
      .then(d => setReqState(d.data ?? null))
      .catch(() => {})
      .finally(() => setLoading(false));

  useEffect(() => {
    // Pick up a role change (e.g. an approved request) without a manual re-login.
    refreshUser();
    load();
  }, []);

  const submit = async () => {
    setSaving(true);
    setError('');
    try {
      await api.requestUpgrade();
      await load();
    } catch (err) {
      setError(err.message || 'Failed to submit request');
    } finally {
      setSaving(false);
    }
  };

  const hasPending = reqState?.status === 'pending';

  return (
    <div>
      <div className="page-header">
        <div className="page-title">My Account</div>
        <div className="page-sub">Your role and access requests</div>
      </div>

      <div className="card" style={{ marginBottom: 20 }}>
        <div className="section-title" style={{ marginBottom: 12 }}>Account</div>
        <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 6 }}>
          {user?.email}
        </div>
        <span className="role-badge">{user?.role}</span>
      </div>

      <div className="card">
        <div className="section-title" style={{ marginBottom: 12 }}>Contributor Access</div>

        {loading ? (
          <LoadingState />
        ) : user?.role !== 'readonly' ? (
          <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
            You already have {user?.role} access — no upgrade needed.
          </div>
        ) : (
          <>
            <p style={{ fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.6, marginBottom: 16 }}>
              Contributors can trigger ingestion runs and write threat data.
              Request the role and an administrator will review it.
            </p>

            {reqState && (
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
                Latest request: <StatusBadge status={reqState.status} />
                <span>· {new Date(reqState.created_at).toLocaleString()}</span>
              </div>
            )}

            {error && (
              <div style={{ color: 'var(--critical)', fontSize: 12, marginBottom: 14 }}>{error}</div>
            )}

            <button
              className="btn btn-primary"
              onClick={submit}
              disabled={saving || hasPending}
            >
              {saving
                ? <><Spinner size={13} /> Submitting…</>
                : hasPending
                  ? 'Request pending review'
                  : <><ArrowUpCircle size={13} /> Request contributor role</>}
            </button>
          </>
        )}
      </div>
    </div>
  );
}
