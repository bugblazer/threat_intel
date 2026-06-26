import { useState, useEffect, useCallback } from 'react';
import { Search, Wifi } from 'lucide-react';
import { api } from '../lib/api.js';
import { TypeBadge, MonoId, LoadingState, EmptyState, Pagination } from '../components/ui/index.jsx';

const IOC_TYPES   = ['', 'ip', 'domain', 'url', 'md5', 'sha256', 'sha1'];
const SOURCE_FEEDS = ['', 'malwarebazaar', 'urlhaus', 'threatfox', 'otx'];

export default function IocsPage() {
  const [rows, setRows]         = useState([]);
  const [total, setTotal]       = useState(0);
  const [loading, setLoading]   = useState(true);
  const [page, setPage]         = useState(1);
  const [query, setQuery]       = useState('');
  const [debouncedQ, setDebouncedQ] = useState('');
  const [type, setType]         = useState('');
  const [feed, setFeed]         = useState('');

  useEffect(() => {
    const t = setTimeout(() => { setDebouncedQ(query); setPage(1); }, 350);
    return () => clearTimeout(t);
  }, [query]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      if (debouncedQ) {
        const data = await api.iocsSearch(debouncedQ, false);
        setRows(data.data ?? []);
        setTotal(data.data?.length ?? 0);
      } else {
        const data = await api.iocs({ page, limit: 25, ...(type && { type }), ...(feed && { source_feed: feed }) });
        setRows(data.data ?? []);
        setTotal(data.total ?? 0);
      }
    } finally {
      setLoading(false);
    }
  }, [page, debouncedQ, type, feed]);

  useEffect(() => { load(); }, [load]);

  return (
    <div>
      <div className="page-header">
        <div className="page-title">IOC Search</div>
        <div className="page-sub">Search indicators of compromise across all ingested feeds</div>
      </div>

      <div style={{ display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap' }}>
        <div className="search-bar" style={{ flex: 1, minWidth: 280 }}>
          <Search size={14} color="var(--text-muted)" />
          <input
            placeholder="Search IP, domain, hash, URL…"
            value={query}
            onChange={e => setQuery(e.target.value)}
          />
        </div>
        <select className="filter-select" value={type} onChange={e => { setType(e.target.value); setPage(1); }}>
          {IOC_TYPES.map(t => <option key={t} value={t}>{t || 'All types'}</option>)}
        </select>
        <select className="filter-select" value={feed} onChange={e => { setFeed(e.target.value); setPage(1); }}>
          {SOURCE_FEEDS.map(f => <option key={f} value={f}>{f || 'All feeds'}</option>)}
        </select>
      </div>

      <div className="card" style={{ padding: 0 }}>
        {loading ? (
          <LoadingState />
        ) : rows.length === 0 ? (
          <EmptyState icon={Wifi} message="No IOCs found" sub="Try a different search term or clear filters" />
        ) : (
          <>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Value</th>
                  <th>Type</th>
                  <th>Feed</th>
                  <th>Malware Family</th>
                  <th>Confidence</th>
                  <th>Last Seen</th>
                  <th>Linked CVE</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((ioc, i) => (
                  <tr key={i}>
                    <td>
                      <span className="mono" style={{ fontSize: 11, color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                        {ioc.value.length > 50 ? ioc.value.slice(0, 50) + '…' : ioc.value}
                      </span>
                    </td>
                    <td><TypeBadge type={ioc.type} /></td>
                    <td>
                      <span className="badge badge-gray">{ioc.source_feed}</span>
                    </td>
                    <td>
                      <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                        {ioc.malware_family ?? '—'}
                      </span>
                    </td>
                    <td>
                      <span className="mono" style={{ fontSize: 12, color: ioc.confidence >= 80 ? 'var(--low)' : 'var(--text-muted)' }}>
                        {ioc.confidence}%
                      </span>
                    </td>
                    <td>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                        {ioc.last_seen ? new Date(ioc.last_seen).toLocaleDateString() : '—'}
                      </span>
                    </td>
                    <td>
                      {ioc.linked_cve
                        ? <MonoId>{ioc.linked_cve}</MonoId>
                        : <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>—</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!debouncedQ && <Pagination page={page} total={total} limit={25} onPage={setPage} />}
          </>
        )}
      </div>
    </div>
  );
}
