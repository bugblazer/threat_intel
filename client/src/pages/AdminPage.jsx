import { useState, useEffect } from 'react';
import { api } from '../lib/api.js';
import { LoadingState, Spinner } from '../components/ui/index.jsx';
import { UserCheck, UserX, UserPlus, X, Check, ArrowUpCircle, ScrollText } from 'lucide-react';

// Human-readable label for an audit action code.
const AUDIT_LABELS = {
  'user.signed_up':             'User signed up',
  'user.role_changed':          'Role changed',
  'user.activated':             'User activated',
  'user.deactivated':           'User deactivated',
  'role_request.submitted':     'Upgrade requested',
  'role_request.approved':      'Role request approved',
  'role_request.declined':      'Role request declined',
  'technique.coverage_changed': 'Coverage changed',
  'ingestion.triggered':        'Ingestion triggered',
};

function auditSummary(entry) {
  const d = entry.detail || {};
  switch (entry.action) {
    case 'user.role_changed':          return `${entry.target_id}: ${d.from} → ${d.to}`;
    case 'user.signed_up':
    case 'user.activated':
    case 'user.deactivated':           return entry.target_id;
    case 'role_request.submitted':     return `→ ${d.requested_role}`;
    case 'role_request.approved':
    case 'role_request.declined':      return `${d.user} (${d.requested_role})`;
    case 'technique.coverage_changed': return `${entry.target_id}: ${d.from} → ${d.to}`;
    case 'ingestion.triggered':        return `source: ${d.source}${d.full_sync ? ' · full sync' : ''}`;
    default:                           return entry.target_id ?? '';
  }
}

const ROLES = ['readonly', 'contributor', 'admin'];

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

function RequestStatusBadge({ status }) {
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

// ── Create User Modal ─────────────────────────────────────────────────────────
function CreateUserModal({ onClose, onCreated }) {
  const [email, setEmail]       = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole]         = useState('readonly');
  const [error, setError]       = useState('');
  const [saving, setSaving]     = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!email || !password) { setError('Email and password are required'); return; }
    if (password.length < 8)  { setError('Password must be at least 8 characters'); return; }
    setSaving(true);
    setError('');
    try {
      await api.register({ email: email.toLowerCase(), password, role });
      onCreated();
      onClose();
    } catch (err) {
      setError(err.message || 'Failed to create user');
    } finally {
      setSaving(false);
    }
  };

  // Close on backdrop click
  const handleBackdrop = (e) => { if (e.target === e.currentTarget) onClose(); };

  return (
    <div
      onClick={handleBackdrop}
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        zIndex: 200,
      }}
    >
      <div style={{
        background: 'var(--bg-surface)', border: '1px solid var(--border)',
        borderRadius: 10, padding: 28, width: 400, position: 'relative',
      }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 22 }}>
          <div style={{ fontWeight: 600, fontSize: 15, color: 'var(--text-primary)' }}>
            Create New Account
          </div>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 2 }}
          >
            <X size={16} />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="form-field">
            <label className="form-label">Email</label>
            <input
              className="form-input"
              type="email"
              placeholder="analyst@example.com"
              value={email}
              onChange={e => setEmail(e.target.value)}
              autoFocus
              required
            />
          </div>

          <div className="form-field">
            <label className="form-label">Password</label>
            <input
              className="form-input"
              type="password"
              placeholder="Min. 8 characters"
              value={password}
              onChange={e => setPassword(e.target.value)}
              required
            />
          </div>

          <div className="form-field">
            <label className="form-label">Role</label>
            <select
              className="form-input"
              value={role}
              onChange={e => setRole(e.target.value)}
              style={{ cursor: 'pointer' }}
            >
              {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
            </select>
            {/* Role descriptions */}
            <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.6 }}>
              {role === 'readonly'    && 'Can view all threat data. Cannot modify anything.'}
              {role === 'contributor' && 'Can view data and trigger ingestion runs. Cannot manage users.'}
              {role === 'admin'       && 'Full access including user management and ingestion controls.'}
            </div>
          </div>

          {error && (
            <div style={{ color: 'var(--critical)', fontSize: 12, marginBottom: 14 }}>
              {error}
            </div>
          )}

          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 4 }}>
            <button type="button" className="btn btn-ghost" onClick={onClose} disabled={saving}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={saving}>
              {saving ? <><Spinner size={13} /> Creating…</> : <><UserPlus size={13} /> Create account</>}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function AdminPage() {
  const [users, setUsers]               = useState([]);
  const [loading, setLoading]           = useState(true);
  const [showCreate, setShowCreate]     = useState(false);
  // Track which user row is having its role changed: { id, role }
  const [editingRole, setEditingRole]   = useState(null);
  const [roleRequests, setRoleRequests] = useState([]);
  const [requestHistory, setRequestHistory] = useState([]);
  const [requestView, setRequestView]   = useState('pending'); // 'pending' | 'history'
  const [decidingId, setDecidingId]     = useState(null);
  const [auditLog, setAuditLog]         = useState([]);

  const loadAudit = () =>
    api.auditLog(50).then(d => setAuditLog(d.data ?? [])).catch(() => {});

  const loadUsers = () =>
    api.adminUsers().then(d => setUsers(d.data ?? [])).finally(() => setLoading(false));

  const loadRequests = () =>
    api.roleRequests('pending').then(d => setRoleRequests(d.data ?? [])).catch(() => {});

  // History = every request that has been resolved (approved or declined).
  const loadHistory = () =>
    api.roleRequests('all')
      .then(d => setRequestHistory((d.data ?? []).filter(r => r.status !== 'pending')))
      .catch(() => {});

  useEffect(() => {
    loadUsers();
    loadRequests();
    loadAudit();
  }, []);

  useEffect(() => {
    if (requestView === 'history') loadHistory();
  }, [requestView]);

  const decideRequest = async (id, action) => {
    setDecidingId(id);
    try {
      await api.decideRoleRequest(id, action);
      await Promise.all([loadRequests(), loadHistory(), loadUsers(), loadAudit()]);
    } finally {
      setDecidingId(null);
    }
  };

  const deactivate = async (id) => {
    if (!confirm('Deactivate this user?')) return;
    await api.deactivateUser(id);
    loadUsers();
    loadAudit();
  };

  const activate = async (id) => {
    await api.updateUser(id, { is_active: true });
    loadUsers();
    loadAudit();
  };

  const saveRole = async (id, newRole) => {
    await api.updateUser(id, { role: newRole });
    setEditingRole(null);
    loadUsers();
    loadAudit();
  };

  return (
    <div>
      {showCreate && (
        <CreateUserModal
          onClose={() => setShowCreate(false)}
          onCreated={loadUsers}
        />
      )}

      <div className="page-header">
        <div className="page-title">Admin Panel</div>
        <div className="page-sub">User management, role requests, and activity</div>
      </div>

      {/* Stats card */}
      <div className="card mb-6">
        <div className="section-title" style={{ marginBottom: 12 }}>Active Users</div>
        <div className="kpi-value" style={{ fontSize: 40 }}>
          {users.filter(u => u.is_active).length}
        </div>
        <div className="kpi-sub">{users.length} total accounts</div>
      </div>

      {/* Role requests */}
      <div className="card" style={{ padding: 0, marginBottom: 24 }}>
        <div style={{
          padding: '14px 20px',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          gap: 8,
        }}>
          <ArrowUpCircle size={15} style={{ color: 'var(--high)' }} />
          <div className="section-title">Contributor Role Requests</div>
          {roleRequests.length > 0 && (
            <span className="badge" style={{ background: 'var(--high-dim)', color: 'var(--high)', border: 'none' }}>
              {roleRequests.length} pending
            </span>
          )}
          {/* Pending / History toggle */}
          <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
            <button
              className={`btn ${requestView === 'pending' ? 'btn-primary' : 'btn-ghost'}`}
              style={{ padding: '3px 10px', fontSize: 11 }}
              onClick={() => setRequestView('pending')}
            >
              Pending
            </button>
            <button
              className={`btn ${requestView === 'history' ? 'btn-primary' : 'btn-ghost'}`}
              style={{ padding: '3px 10px', fontSize: 11 }}
              onClick={() => setRequestView('history')}
            >
              History
            </button>
          </div>
        </div>

        {requestView === 'pending' ? (
          roleRequests.length === 0 ? (
            <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
              No pending requests.
            </div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Email</th>
                  <th>Current role</th>
                  <th>Requested</th>
                  <th>Requested at</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {roleRequests.map(r => (
                  <tr key={r.id}>
                    <td><span className="mono" style={{ fontSize: 12 }}>{r.email}</span></td>
                    <td><RoleBadge role={r.current_role} /></td>
                    <td><RoleBadge role={r.requested_role} /></td>
                    <td>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        {new Date(r.created_at).toLocaleString()}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 6 }}>
                        <button
                          className="btn btn-primary"
                          style={{ padding: '3px 8px', fontSize: 11 }}
                          disabled={decidingId === r.id}
                          onClick={() => decideRequest(r.id, 'approve')}
                        >
                          <Check size={11} /> Approve
                        </button>
                        <button
                          className="btn btn-ghost"
                          style={{ padding: '3px 8px', fontSize: 11 }}
                          disabled={decidingId === r.id}
                          onClick={() => decideRequest(r.id, 'decline')}
                        >
                          <X size={11} /> Decline
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )
        ) : (
          requestHistory.length === 0 ? (
            <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
              No resolved requests yet.
            </div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Email</th>
                  <th>Requested</th>
                  <th>Outcome</th>
                  <th>Decided by</th>
                  <th>Decided at</th>
                </tr>
              </thead>
              <tbody>
                {requestHistory.map(r => (
                  <tr key={r.id}>
                    <td><span className="mono" style={{ fontSize: 12 }}>{r.email}</span></td>
                    <td><RoleBadge role={r.requested_role} /></td>
                    <td><RequestStatusBadge status={r.status} /></td>
                    <td>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        {r.decided_by || '—'}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        {r.decided_at ? new Date(r.decided_at).toLocaleString() : '—'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )
        )}
      </div>

      {/* User table */}
      <div className="card" style={{ padding: 0 }}>
        <div style={{
          padding: '14px 20px',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}>
          <div className="section-title">User Accounts</div>
          <button className="btn btn-primary" style={{ fontSize: 12 }} onClick={() => setShowCreate(true)}>
            <UserPlus size={13} /> New account
          </button>
        </div>

        {loading ? (
          <LoadingState />
        ) : users.length === 0 ? (
          <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
            No users yet.
          </div>
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
              {users.map(u => {
                const isEditingThisRole = editingRole?.id === u.id;
                return (
                  <tr key={u.id}>
                    <td>
                      <span className="mono" style={{ fontSize: 12 }}>{u.email}</span>
                    </td>

                    {/* Role cell — click badge to open inline role editor */}
                    <td>
                      {isEditingThisRole ? (
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <select
                            className="filter-select"
                            style={{ fontSize: 11, padding: '3px 6px' }}
                            value={editingRole.role}
                            onChange={e => setEditingRole({ id: u.id, role: e.target.value })}
                            autoFocus
                          >
                            {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                          </select>
                          <button
                            className="btn btn-primary"
                            style={{ padding: '3px 8px', fontSize: 11 }}
                            onClick={() => saveRole(u.id, editingRole.role)}
                          >
                            Save
                          </button>
                          <button
                            className="btn btn-ghost"
                            style={{ padding: '3px 8px', fontSize: 11 }}
                            onClick={() => setEditingRole(null)}
                          >
                            <X size={10} />
                          </button>
                        </div>
                      ) : (
                        <span
                          title="Click to change role"
                          style={{ cursor: 'pointer' }}
                          onClick={() => setEditingRole({ id: u.id, role: u.role })}
                        >
                          <RoleBadge role={u.role} />
                        </span>
                      )}
                    </td>

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
                      {u.role === 'admin' ? (
                        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                          Admins can't be deactivated
                        </span>
                      ) : u.is_active ? (
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
                          onClick={() => activate(u.id)}
                        >
                          <UserCheck size={11} /> Activate
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Activity log */}
      <div className="card" style={{ padding: 0, marginTop: 24 }}>
        <div style={{
          padding: '14px 20px',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          gap: 8,
        }}>
          <ScrollText size={15} style={{ color: 'var(--text-muted)' }} />
          <div className="section-title">Activity Log</div>
        </div>

        {auditLog.length === 0 ? (
          <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
            No recorded activity yet.
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>When</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {auditLog.map(e => (
                <tr key={e.id}>
                  <td>
                    <span style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                      {new Date(e.created_at).toLocaleString()}
                    </span>
                  </td>
                  <td><span className="mono" style={{ fontSize: 12 }}>{e.actor_email ?? 'system'}</span></td>
                  <td>
                    <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                      {AUDIT_LABELS[e.action] ?? e.action}
                    </span>
                  </td>
                  <td>
                    <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{auditSummary(e)}</span>
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
