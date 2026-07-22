// lib/api.js — Thin API client + AuthContext

// ── API client ────────────────────────────────────────────────────────────────
const BASE = '/api/v1';

function getToken() {
  return localStorage.getItem('token');
}

async function request(path, options = {}) {
  const token = getToken();
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
  });

  if (res.status === 401) {
    localStorage.removeItem('token');
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
