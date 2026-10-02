// lib/api.js — Thin API client
//
// Sessions: the access token is a 15-minute JWT kept ONLY in memory (never in
// localStorage, where any injected script could read it). The long-lived session
// is an httpOnly refresh cookie the browser sends to /api/v1/auth only. When a
// request gets 401, we refresh once and retry; if that fails, back to /login.

const BASE = '/api/v1';

let accessToken = null;
export const setAccessToken = (token) => { accessToken = token ?? null; };

// Clear the token older versions of the app stored in localStorage.
try { localStorage.removeItem('token'); } catch { /* storage unavailable */ }

// Concurrent 401s share one refresh call instead of each rotating the cookie
// (a second rotation with the same cookie would look like token theft).
let refreshing = null;
export function refreshSession() {
  refreshing ??= fetch(`${BASE}/auth/refresh`, { method: 'POST', credentials: 'same-origin' })
    .then(async (res) => {
      if (!res.ok) { setAccessToken(null); return null; }
      const data = await res.json();
      setAccessToken(data.token);
      return data;
    })
    .catch(() => null)
    .finally(() => { refreshing = null; });
  return refreshing;
}

async function request(path, options = {}, retried = false) {
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
      ...options.headers,
    },
  });

  // Expired access token: refresh once and retry. Auth endpoints answer 401 for
  // bad credentials, so they're returned as errors instead.
  if (res.status === 401 && !path.startsWith('/auth/')) {
    if (!retried && await refreshSession()) return request(path, options, true);
    setAccessToken(null);
    window.location.href = '/login';
    return;
  }

  let data = null;
  try { data = await res.json(); } catch { /* empty or non-JSON body */ }
  if (!res.ok) throw new Error(data?.error || `HTTP ${res.status}`);
  return data;
}

export const api = {
  // Auth
  login:    (body)  => request('/auth/login',    { method: 'POST', body: JSON.stringify(body) }),
  register: (body)  => request('/auth/register', { method: 'POST', body: JSON.stringify(body) }),
  signup:   (body)  => request('/auth/signup',   { method: 'POST', body: JSON.stringify(body) }),
  me:       ()      => request('/auth/me'),
  logout:   ()      => request('/auth/logout', { method: 'POST' }),

  // Dashboard
  dashboard: () => request('/dashboard/summary'),

  // CVEs
  cves:          (params = {}) => request(`/cves?${new URLSearchParams(params)}`),
  cve:           (id)          => request(`/cves/${id}`),
  cvesSearch:    (q, params)   => request(`/cves/search?q=${encodeURIComponent(q)}&${new URLSearchParams(params)}`),
  cvesHighSev:   (params = {}) => request(`/cves/high-severity?${new URLSearchParams(params)}`),

  // Techniques
  techniques:      (params = {}) => request(`/techniques?${new URLSearchParams(params)}`),
  technique:       (id)          => request(`/techniques/${id}`),
  techniquesSearch:(q)           => request(`/techniques/search?q=${encodeURIComponent(q)}`),
  heatmap:         ()            => request('/techniques/heatmap'),
  tactics:         ()            => request('/techniques/tactics'),
  setCoverage:     (id, body)    => request(`/techniques/${id}/coverage`, { method: 'PATCH', body: JSON.stringify(body) }),

  // IOCs
  iocs:       (params = {}) => request(`/iocs?${new URLSearchParams(params)}`),
  ioc:        (id)          => request(`/iocs/${id}`),
  iocsSearch: (q, exact)    => request(`/iocs/search?q=${encodeURIComponent(q)}&exact=${exact}`),
  iocStats:   ()            => request('/iocs/stats'),
  iocLookup:  (values)      => request('/iocs/lookup', { method: 'POST', body: JSON.stringify({ values }) }),

  // Threat actors
  threatActors:       (params = {}) => request(`/threat-actors?${new URLSearchParams(params)}`),
  threatActor:        (id)          => request(`/threat-actors/${id}`),
  threatActorsSearch: (q)           => request(`/threat-actors/search?q=${encodeURIComponent(q)}`),

  // Admin
  adminUsers:    ()       => request('/admin/users'),
  updateUser:    (id, b)  => request(`/admin/users/${id}`, { method: 'PATCH', body: JSON.stringify(b) }),
  deactivateUser:(id)     => request(`/admin/users/${id}`, { method: 'DELETE' }),
  triggerIngest: (body)   => request('/admin/ingest', { method: 'POST', body: JSON.stringify(body) }),
  ingestStatus:  ()       => request('/admin/ingest/status'),

  // Role requests (user-facing)
  myRoleRequest:   ()          => request('/requests/me'),
  requestUpgrade:  ()          => request('/requests', { method: 'POST' }),

  // Role requests (admin)
  roleRequests:      (status = 'pending') => request(`/admin/role-requests?status=${status}`),
  decideRoleRequest: (id, action)         => request(`/admin/role-requests/${id}`, { method: 'PATCH', body: JSON.stringify({ action }) }),

  // Audit log (admin)
  auditLog:          (limit = 50)         => request(`/admin/audit-log?limit=${limit}`),
};
