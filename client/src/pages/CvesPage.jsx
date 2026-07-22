import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Filter } from 'lucide-react';
import { api } from '../lib/api.js';
import {
  SeverityBadge, CvssScore, MonoId,
  LoadingState, EmptyState, Pagination,
} from '../components/ui/index.jsx';
import { ShieldAlert, Crosshair, Wifi, EyeOff } from 'lucide-react';

const SEVERITIES = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

// Small inline indicator of a CVE's real-world threat context.
// A "blind" badge flags CVEs mapped to techniques with no detection coverage.
function ThreatSignal({ techniques, iocs, blind }) {
  const t = Number(techniques ?? 0);
  const i = Number(iocs ?? 0);
  const b = Number(blind ?? 0);
  if (!t && !i) return <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>—</span>;
  return (
    <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
      {t > 0 && (
        <span title={`${t} linked ATT&CK technique(s)`} style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: 'var(--high)', fontSize: 11 }}>
          <Crosshair size={11} /> {t}
        </span>
      )}
      {i > 0 && (
        <span title={`${i} linked IOC(s)`} style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: 'var(--cyan)', fontSize: 11 }}>
          <Wifi size={11} /> {i}
        </span>
      )}
      {b > 0 && (
        <span
          title={`${b} mapped technique(s) with no detection coverage`}
          className="badge"
          style={{ display: 'inline-flex', alignItems: 'center', gap: 3, background: 'var(--critical-dim)', color: 'var(--critical)', border: 'none', fontSize: 10 }}
        >
          <EyeOff size={10} /> {b} blind
        </span>
      )}
    </div>
  );
}

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
  const [sort, setSort]         = useState('severity'); // 'severity' | 'threat' | 'recent'
  const [threatOnly, setThreatOnly] = useState(false);

  // Debounce search input 350ms
  useEffect(() => {
    const t = setTimeout(() => { setDebouncedQ(query); setPage(1); }, 350);
    return () => clearTimeout(t);
  }, [query]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = {
        page, limit: 25,
        ...(severity && { severity }),
        ...(minScore && { min_score: minScore }),
        ...(sort && { sort }),
        ...(threatOnly && { threat_only: 'true' }),
      };
      const data = debouncedQ
        ? await api.cvesSearch(debouncedQ, { page, limit: 25 })
        : await api.cves(params);
      setRows(data.data ?? []);
      setTotal(data.total ?? 0);
    } finally {
      setLoading(false);
    }
  }, [page, debouncedQ, severity, minScore, sort, threatOnly]);

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
        <select
          className="filter-select"
          value={sort}
          onChange={e => { setSort(e.target.value); setPage(1); }}
          title="Sort order"
          disabled={!!debouncedQ}
        >
          <option value="severity">Sort: Severity</option>
          <option value="threat">Sort: Threat-informed</option>
          <option value="recent">Sort: Newest</option>
        </select>
        <label
          className="filter-select"
          style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: debouncedQ ? 'not-allowed' : 'pointer', opacity: debouncedQ ? 0.5 : 1 }}
          title="Only CVEs linked to a technique or IOC"
        >
          <input
            type="checkbox"
            checked={threatOnly}
            disabled={!!debouncedQ}
            onChange={e => { setThreatOnly(e.target.checked); setPage(1); }}
          />
          With threat intel
        </label>
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
                  <th>Threat</th>
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
                    <td><ThreatSignal techniques={c.technique_count} iocs={c.ioc_count} blind={c.blind_technique_count} /></td>
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
