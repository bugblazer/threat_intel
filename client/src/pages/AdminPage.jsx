import { useState, useEffect } from 'react';
import { api } from '../lib/api.js';
import { LoadingState, Spinner } from '../components/ui/index.jsx';
import { RefreshCw, UserCheck, UserX } from 'lucide-react';

function RoleBadge({ role }) {
  const colors = {
    admin:       { bg: 'var(--critical-dim)', color: 'var(--critical)' },
    contributor: { bg: 'var(--high-dim)',     color: 'var(--high)' },
    readonly:    { bg: 'var(--cyan-dim)',      color: 'var(--cyan)' },
  };
  const s = colors[role] ?? colors.readonly;
  return (
    <span className="badge" style={{ background: s.bg, color: s.color, border: 'none' }}>
      {role}
    </span>
  );
}

export default function AdminPage() {
  const [users, setUsers]           = useState([]);
  const [loading, setLoading]       = useState(true);
  const [ingestStatus, setIngestStatus] = useState(null);
  const [ingesting, setIngesting]   = useState(false);
  const [ingestSource, setIngestSource] = useState('');

  const loadUsers = () =>
    api.adminUsers().then(d => setUsers(d.data ?? [])).finally(() => setLoading(false));

  const loadStatus = () => api.ingestStatus().then(setIngestStatus);

  useEffect(() => {
    loadUsers();
    loadStatus();
    const t = setInterval(loadStatus, 5000);
    return () => clearInterval(t);
  }, []);

  const triggerIngest = async () => {
    setIngesting(true);
    try {
      await api.triggerIngest({ source: ingestSource || undefined });
      await loadStatus();
    } finally {
      setIngesting(false);
    }
  };

  const deactivate = async (id) => {
    if (!confirm('Deactivate this user?')) return;
    await api.deactivateUser(id);
    loadUsers();
  };

  return (
    <div>
      <div className="page-header">
        <div className="page-title">Admin Panel</div>
        <div className="page-sub">User management and ingestion controls</div>
      </div>

      <div className="grid-2 mb-6">
        {/* Ingestion panel */}
        <div className="card">
          <div className="section-title" style={{ marginBottom: 16 }}>Manual Ingestion</div>

          <div style={{ display: 'flex', gap: 8, marginBottom: 14 }}>
            <select className="filter-select" value={ingestSource} onChange={e => setIngestSource(e.target.value)}>
              <option value="">All sources</option>
              <option value="mitre">MITRE ATT&CK</option>
              <option value="nvd">NVD CVE</option>
              <option value="abusech">Abuse.ch</option>
              <option value="otx">AlienVault OTX</option>
            </select>
            <button
              className="btn btn-primary"
              onClick={triggerIngest}
              disabled={ingesting || ingestStatus?.running}
            >
              {ingesting || ingestStatus?.running
                ? <><Spinner size={13} /> Running…</>
                : <><RefreshCw size={13} /> Run ingestion</>}
            </button>
          </div>

          {ingestStatus && (
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              {ingestStatus.running && (
                <div style={{ color: 'var(--high)', marginBottom: 6 }}>⟳ Ingestion in progress…</div>
              )}
              {ingestStatus.last && (
                <div>
                  <div style={{ marginBottom: 4 }}>
                    Last run: {new Date(ingestStatus.last.completedAt).toLocaleString()}
                  </div>
                  {ingestStatus.last.triggeredBy && (
                    <div>Triggered by: {ingestStatus.last.triggeredBy}</div>
                  )}
                  {ingestStatus.last.error && (
                    <div style={{ color: 'var(--critical)', marginTop: 4 }}>
                      Error: {ingestStatus.last.error}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Quick stats placeholder */}
        <div className="card">
          <div className="section-title" style={{ marginBottom: 12 }}>Active Users</div>
          <div className="kpi-value" style={{ fontSize: 40 }}>
            {users.filter(u => u.is_active).length}
          </div>
          <div className="kpi-sub">{users.length} total accounts</div>
        </div>
      </div>

      {/* User table */}
      <div className="card" style={{ padding: 0 }}>
        <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)' }}>
          <div className="section-title">User Accounts</div>
        </div>
        {loading ? (
          <LoadingState />
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Email</th>
                <th>Role</th>
                <th>Status</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id}>
                  <td>
                    <span className="mono" style={{ fontSize: 12 }}>{u.email}</span>
                  </td>
                  <td><RoleBadge role={u.role} /></td>
                  <td>
                    {u.is_active
                      ? <span style={{ color: 'var(--low)', fontSize: 12 }}>● Active</span>
                      : <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>○ Inactive</span>}
                  </td>
                  <td>
                    <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                      {new Date(u.created_at).toLocaleDateString()}
                    </span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: 6 }}>
                      {u.is_active ? (
                        <button
                          className="btn btn-ghost"
                          style={{ padding: '3px 8px', fontSize: 11 }}
                          onClick={() => deactivate(u.id)}
                        >
                          <UserX size={11} /> Deactivate
                        </button>
                      ) : (
                        <button
                          className="btn btn-ghost"
                          style={{ padding: '3px 8px', fontSize: 11 }}
                          onClick={async () => {
                            await api.updateUser(u.id, { is_active: true });
                            loadUsers();
                          }}
                        >
                          <UserCheck size={11} /> Activate
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
