import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard, ShieldAlert, Crosshair, Wifi,
  Users, Settings, LogOut, Terminal,
} from 'lucide-react';
import { useAuth } from '../../hooks/useAuth.jsx';

const NAV = [
  { label: 'Overview',      to: '/',               icon: LayoutDashboard },
  { label: 'CVE Explorer',  to: '/cves',            icon: ShieldAlert },
  { label: 'ATT&CK Matrix', to: '/techniques',      icon: Crosshair },
  { label: 'IOC Search',    to: '/iocs',            icon: Wifi },
  { label: 'Threat Actors', to: '/threat-actors',  icon: Users },
];

const ADMIN_NAV = [
  { label: 'Admin',         to: '/admin',           icon: Settings },
];

export default function Sidebar() {
  const { user, logout } = useAuth();

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-mark">
          <Terminal size={11} style={{ display: 'inline', marginRight: 5 }} />
          ThreatIntel
        </div>
        <div className="logo-sub">Intelligence Platform</div>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-section-label">Intelligence</div>
        {NAV.map(({ label, to, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
          >
            <Icon size={15} />
            {label}
          </NavLink>
        ))}

        {user?.role === 'admin' && (
          <>
            <div className="nav-section-label" style={{ marginTop: 8 }}>Admin</div>
            {ADMIN_NAV.map(({ label, to, icon: Icon }) => (
              <NavLink
                key={to}
                to={to}
                className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
              >
                <Icon size={15} />
                {label}
              </NavLink>
            ))}
          </>
        )}
      </nav>

      <div className="sidebar-footer">
        <div style={{ marginBottom: 10 }}>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 4 }}>
            {user?.email}
          </div>
          <span className="role-badge">{user?.role}</span>
        </div>
        <button className="nav-item" onClick={logout} style={{ color: 'var(--text-muted)' }}>
          <LogOut size={13} />
          Sign out
        </button>
      </div>
    </aside>
  );
}
