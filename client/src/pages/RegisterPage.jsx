import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Terminal } from 'lucide-react';
import { useAuth } from '../hooks/useAuth.jsx';
import { Spinner } from '../components/ui/index.jsx';

export default function RegisterPage() {
  const { signup }              = useAuth();
  const navigate                = useNavigate();
  const [email, setEmail]       = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm]   = useState('');
  const [error, setError]       = useState('');
  const [loading, setLoading]   = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (password.length < 8) { setError('Password must be at least 8 characters'); return; }
    if (password !== confirm) { setError('Passwords do not match'); return; }
    setLoading(true);
    try {
      await signup(email.toLowerCase(), password);
      navigate('/');
    } catch (err) {
      setError(err.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-logo">
          <Terminal size={12} style={{ display: 'inline', marginRight: 6 }} />
          ThreatIntel
        </div>
        <div className="login-title">Create a read-only account</div>

        <form onSubmit={handleSubmit}>
          <div className="form-field">
            <label className="form-label">Email</label>
            <input
              className="form-input"
              type="email"
              autoComplete="email"
              placeholder="analyst@example.com"
              value={email}
              onChange={e => setEmail(e.target.value)}
              required
            />
          </div>
          <div className="form-field">
            <label className="form-label">Password</label>
            <input
              className="form-input"
              type="password"
              autoComplete="new-password"
              placeholder="Min. 8 characters"
              value={password}
              onChange={e => setPassword(e.target.value)}
              required
            />
          </div>
          <div className="form-field">
            <label className="form-label">Confirm password</label>
            <input
              className="form-input"
              type="password"
              autoComplete="new-password"
              placeholder="Re-enter password"
              value={confirm}
              onChange={e => setConfirm(e.target.value)}
              required
            />
          </div>

          {error && <div className="form-error">{error}</div>}

          <button
            className="btn btn-primary"
            type="submit"
            disabled={loading}
            style={{ width: '100%', marginTop: 20, justifyContent: 'center' }}
          >
            {loading ? <Spinner size={14} /> : 'Create account'}
          </button>
        </form>

        <p style={{ marginTop: 16, fontSize: 12, color: 'var(--text-muted)', textAlign: 'center', lineHeight: 1.6 }}>
          New accounts have read-only access. You can request the contributor
          role from your profile once signed in.
        </p>
        <p style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)', textAlign: 'center' }}>
          Already have an account? <Link to="/login" style={{ color: 'var(--cyan)' }}>Sign in</Link>
        </p>
      </div>
    </div>
  );
}
