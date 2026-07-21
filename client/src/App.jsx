import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './hooks/useAuth.jsx';
import Sidebar from './components/layout/Sidebar.jsx';
import LoginPage       from './pages/LoginPage.jsx';
import RegisterPage    from './pages/RegisterPage.jsx';
import DashboardPage   from './pages/DashboardPage.jsx';
import CvesPage        from './pages/CvesPage.jsx';
import TechniquesPage  from './pages/TechniquesPage.jsx';
import IocsPage        from './pages/IocsPage.jsx';
import ThreatActorsPage from './pages/ThreatActorsPage.jsx';
import AdminPage       from './pages/AdminPage.jsx';
import AccountPage     from './pages/AccountPage.jsx';
import CveDetailPage from './pages/CveDetailPage';
import TechniqueDetailPage from './pages/TechniqueDetailPage';
import ThreatActorDetailPage from './pages/ThreatActorDetailPage';
import { Spinner }     from './components/ui/index.jsx';

function ProtectedRoute({ children, adminOnly = false }) {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh' }}>
        <Spinner size={28} />
      </div>
    );
  }

  if (!user) return <Navigate to="/login" replace />;
  if (adminOnly && user.role !== 'admin') return <Navigate to="/" replace />;
  return children;
}

function AppShell() {
  return (
    <div className="app-shell">
      <Sidebar />
      <main className="main-content">
        <Routes>
          <Route path="/"              element={<DashboardPage />} />
          <Route path="/cves"          element={<CvesPage />} />
          <Route path="/cves/:cveId" element={<CveDetailPage />} />
          <Route path="/techniques"    element={<TechniquesPage />} />
          <Route path="/techniques/:techniqueId" element={<TechniqueDetailPage />} />
          <Route path="/threat-actors/:id" element={<ThreatActorDetailPage />} />
          <Route path="/iocs"          element={<IocsPage />} />
          <Route path="/threat-actors" element={<ThreatActorsPage />} />
          <Route path="/admin"         element={<AdminPage />} />
          <Route path="/account"       element={<AccountPage />} />
          <Route path="*"              element={<Navigate to="/" replace />} />

        </Routes>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route
            path="/*"
            element={
              <ProtectedRoute>
                <AppShell />
              </ProtectedRoute>
            }
          />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
