import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Filter } from 'lucide-react';
import { api } from '../lib/api.js';
import {
  SeverityBadge, CvssScore, MonoId,
  LoadingState, EmptyState, Pagination,
} from '../components/ui/index.jsx';
import { ShieldAlert } from 'lucide-react';

const SEVERITIES = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export default function CvesPage() {
  const navigate   = useNavigate();
  const [rows, setRows]         = useState([]);
  const [total, setTotal]       = useState(0);
  const [loading, setLoading]   = useState(true);
  const [page, setPage]         = useState(1);
  const [query, setQuery]       = useState('');
  const [debouncedQ, setDebouncedQ] = useState('');
  const [severity, setSeverity] = useState('');
  const [minScore, setMinScore] = useState('');

  // Debounce search input 350ms
  useEffect(() => {
    const t = setTimeout(() => { setDebouncedQ(query); setPage(1); }, 350);
    return () => clearTimeout(t);
  }, [query]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = { page, limit: 25, ...(severity && { severity }), ...(minScore && { min_score: minScore }) };
      const data = debouncedQ
        ? await api.cvesSearch(debouncedQ, { page, limit: 25 })
        : await api.cves(params);
      setRows(data.data ?? []);
      setTotal(data.total ?? 0);
    } finally {
      setLoading(false);
    }
  }, [page, debouncedQ, severity, minScore]);

  useEffect(() => { load(); }, [load]);

  return (
    <div>
      <div className="page-header">
        <div className="page-title">CVE Explorer</div>
        <div className="page-sub">Search and filter {total.toLocaleString()} vulnerabilities</div>
      </div>

      {/* Search + filters */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap' }}>
        <div className="search-bar" style={{ flex: 1, minWidth: 260 }}>
          <Search size={14} color="var(--text-muted)" />
          <input
            placeholder="Search CVE IDs, descriptions, CWE…"
            value={query}
            onChange={e => setQuery(e.target.value)}
          />
        </div>
        <select
          className="filter-select"
          value={severity}
          onChange={e => { setSeverity(e.target.value); setPage(1); }}
        >
          {SEVERITIES.map(s => <option key={s} value={s}>{s || 'All severities'}</option>)}
        </select>
        <select
          className="filter-select"
          value={minScore}
          onChange={e => { setMinScore(e.target.value); setPage(1); }}
        >
          <option value="">Any score</option>
          <option value="9">Critical ≥ 9.0</option>
          <option value="7">High ≥ 7.0</option>
          <option value="4">Medium ≥ 4.0</option>
        </select>
      </div>

      <div className="card" style={{ padding: 0 }}>
        {loading ? (
          <LoadingState />
        ) : rows.length === 0 ? (
          <EmptyState icon={ShieldAlert} message="No CVEs match your filters" sub="Try broadening the search or clearing filters" />
        ) : (
          <>
            <table className="data-table">
              <thead>
                <tr>
                  <th>CVE ID</th>
                  <th>CVSS</th>
                  <th>Severity</th>
                  <th>CWE</th>
                  <th>Published</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody>
                {rows.map(c => (
                  <tr key={c.cve_id} onClick={() => navigate(`/cves/${c.cve_id}`)}>
                    <td><MonoId>{c.cve_id}</MonoId></td>
                    <td><CvssScore score={c.cvss_score} /></td>
                    <td><SeverityBadge severity={c.severity} /></td>
                    <td>
                      <span className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        {c.cwe_id ?? '—'}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                        {c.published_at ? new Date(c.published_at).toLocaleDateString() : '—'}
                      </span>
                    </td>
                    <td style={{ maxWidth: 360 }}>
                      <span style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {c.description}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Pagination page={page} total={total} limit={25} onPage={setPage} />
          </>
        )}
      </div>
    </div>
  );
}
