import { useState, useEffect, useCallback } from 'react';
import { Search, Wifi, ChevronDown, ChevronRight, ListChecks, Copy, Check } from 'lucide-react';
import { api } from '../lib/api.js';
import { TypeBadge, MonoId, LoadingState, EmptyState, Pagination, Spinner } from '../components/ui/index.jsx';

const IOC_TYPES    = ['', 'ip', 'domain', 'url', 'md5', 'sha256', 'sha1'];
const SOURCE_FEEDS = ['', 'malwarebazaar', 'urlhaus', 'threatfox', 'otx'];

// Render an indicator "defanged" so it's safe to paste into tickets/email.
function defang(value) {
  return String(value)
    .replace(/^http(s?):\/\//i, 'hxxp$1://')
    .replace(/\./g, '[.]')
    .replace(/@/g, '[@]');
}

function CopyButton({ text, title = 'Copy' }) {
  const [copied, setCopied] = useState(false);
  const copy = async (e) => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch { /* clipboard unavailable */ }
  };
  return (
    <button
      className="btn btn-ghost"
      style={{ padding: '2px 6px', fontSize: 11 }}
      onClick={copy}
      title={title}
    >
      {copied ? <Check size={11} /> : <Copy size={11} />}
    </button>
  );
}

// ── Bulk lookup panel ─────────────────────────────────────────────────────────
function BulkLookup() {
  const [input, setInput]     = useState('');
  const [results, setResults] = useState(null);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState('');
  const [defanged, setDefanged] = useState(true);

  const run = async () => {
    // Split on newlines, commas, semicolons, or whitespace.
    const values = input.split(/[\s,;]+/).map(s => s.trim()).filter(Boolean);
    if (values.length === 0) { setError('Paste at least one indicator'); return; }
    setLoading(true);
    setError('');
    try {
      const data = await api.iocLookup(values);
      setResults(data.results ?? []);
      setSummary(data.summary ?? null);
    } catch (err) {
      setError(err.message || 'Lookup failed');
    } finally {
      setLoading(false);
    }
  };

  const show = (v) => (defanged ? defang(v) : v);

  return (
    <div>
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="section-title" style={{ marginBottom: 10 }}>
          Paste indicators to check against known IOCs
        </div>
        <textarea
          className="form-input"
          style={{ width: '100%', minHeight: 120, fontFamily: 'var(--font-mono, monospace)', fontSize: 12, resize: 'vertical' }}
          placeholder={'One per line, or comma/space separated.\nDefanged indicators are fine: 1[.]2[.]3[.]4, hxxp://evil, evil(dot)com'}
          value={input}
          onChange={e => setInput(e.target.value)}
        />
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 12 }}>
          <button className="btn btn-primary" onClick={run} disabled={loading}>
            {loading ? <><Spinner size={13} /> Checking…</> : <><ListChecks size={13} /> Look up</>}
          </button>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text-muted)', cursor: 'pointer' }}>
            <input type="checkbox" checked={defanged} onChange={e => setDefanged(e.target.checked)} />
            Show defanged
          </label>
          {error && <span style={{ color: 'var(--critical)', fontSize: 12 }}>{error}</span>}
        </div>
      </div>

      {summary && (
        <div style={{ display: 'flex', gap: 16, marginBottom: 12, fontSize: 12 }}>
          <span style={{ color: 'var(--text-muted)' }}>{summary.total} checked</span>
          <span style={{ color: 'var(--critical)' }}>● {summary.found} known</span>
          <span style={{ color: 'var(--low)' }}>○ {summary.notFound} clean</span>
        </div>
      )}

      {results && (
        results.length === 0 ? (
          <EmptyState icon={Wifi} message="Nothing to show" />
        ) : (
          <div className="card" style={{ padding: 0 }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Indicator</th>
                  <th>Status</th>
                  <th>Type</th>
                  <th>Feed</th>
                  <th>Malware Family</th>
                  <th>Last Seen</th>
                  <th style={{ width: 40 }} />
                </tr>
              </thead>
              <tbody>
                {results.map((r, i) => {
                  const hit = r.matches[0];
                  return (
                    <tr key={i} style={hit ? { background: 'var(--critical-dim)' } : undefined}>
                      <td>
                        <span className="mono" style={{ fontSize: 11, color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                          {show(r.input)}
                        </span>
                      </td>
                      <td>
                        {hit
                          ? <span className="badge" style={{ background: 'var(--critical-dim)', color: 'var(--critical)', border: 'none' }}>Known</span>
                          : <span style={{ color: 'var(--low)', fontSize: 12 }}>Clean</span>}
                      </td>
                      <td>{hit ? <TypeBadge type={hit.type} /> : <span style={{ color: 'var(--text-muted)' }}>—</span>}</td>
                      <td>{hit ? <span className="badge badge-gray">{hit.source_feed}</span> : <span style={{ color: 'var(--text-muted)' }}>—</span>}</td>
                      <td><span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{hit?.malware_family ?? '—'}</span></td>
                      <td>
                        <span style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                          {hit?.last_seen ? new Date(hit.last_seen).toLocaleDateString() : '—'}
                        </span>
                      </td>
                      <td><CopyButton text={show(r.input)} title="Copy indicator" /></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )
      )}
    </div>
  );
}

function ExpandedRow({ ioc }) {
  return (
    <tr>
      <td colSpan={7} style={{ background: 'var(--bg-input)', padding: '12px 16px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '10px 24px', fontSize: 12 }}>
          <div>
            <div style={{ color: 'var(--text-muted)', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 3 }}>Full Value</div>
            <span className="mono" style={{ color: 'var(--text-primary)', wordBreak: 'break-all' }}>{ioc.value}</span>
          </div>
          <div>
            <div style={{ color: 'var(--text-muted)', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 3 }}>First Seen</div>
            <span style={{ color: 'var(--text-secondary)' }}>{ioc.first_seen ? new Date(ioc.first_seen).toLocaleString() : '—'}</span>
          </div>
          <div>
            <div style={{ color: 'var(--text-muted)', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 3 }}>Threat Type</div>
            <span style={{ color: 'var(--text-secondary)' }}>{ioc.threat_type ?? '—'}</span>
          </div>
          {ioc.linked_cve && (
            <div>
              <div style={{ color: 'var(--text-muted)', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 3 }}>Linked CVE</div>
              <MonoId>{ioc.linked_cve}</MonoId>
            </div>
          )}
          {ioc.linked_technique && (
            <div>
              <div style={{ color: 'var(--text-muted)', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 3 }}>Linked Technique</div>
              <MonoId>{ioc.linked_technique}</MonoId>
              {ioc.linked_technique_name && (
                <span style={{ marginLeft: 8, color: 'var(--text-secondary)' }}>{ioc.linked_technique_name}</span>
              )}
            </div>
          )}
          {Array.isArray(ioc.tags) && ioc.tags.length > 0 && (
            <div>
              <div style={{ color: 'var(--text-muted)', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 3 }}>Tags</div>
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                {ioc.tags.map(t => <span key={t} className="badge badge-gray">{t}</span>)}
              </div>
            </div>
          )}
        </div>
      </td>
    </tr>
  );
}

export default function IocsPage() {
  const [rows, setRows]             = useState([]);
  const [total, setTotal]           = useState(0);
  const [loading, setLoading]       = useState(true);
  const [page, setPage]             = useState(1);
  const [query, setQuery]           = useState('');
  const [debouncedQ, setDebouncedQ] = useState('');
  const [type, setType]             = useState('');
  const [feed, setFeed]             = useState('');
  const [expandedId, setExpandedId] = useState(null);
  const [mode, setMode]             = useState('search'); // 'search' | 'bulk'

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

  const toggleExpand = (id) => setExpandedId(prev => prev === id ? null : id);

  return (
    <div>
      <div className="page-header">
        <div className="page-title">IOC Search</div>
        <div className="page-sub">Search indicators of compromise across all ingested feeds. Click any row for details.</div>
      </div>

      {/* Mode tabs */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 16 }}>
        <button
          className={`btn ${mode === 'search' ? 'btn-primary' : 'btn-ghost'}`}
          style={{ fontSize: 12 }}
          onClick={() => setMode('search')}
        >
          <Search size={13} /> Search
        </button>
        <button
          className={`btn ${mode === 'bulk' ? 'btn-primary' : 'btn-ghost'}`}
          style={{ fontSize: 12 }}
          onClick={() => setMode('bulk')}
        >
          <ListChecks size={13} /> Bulk lookup
        </button>
      </div>

      {mode === 'bulk' ? <BulkLookup /> : (
      <>
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
                  <th style={{ width: 24 }} />
                  <th>Value</th>
                  <th>Type</th>
                  <th>Feed</th>
                  <th>Malware Family</th>
                  <th>Confidence</th>
                  <th>Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((ioc, i) => {
                  const rowId = ioc.id ?? i;
                  const isOpen = expandedId === rowId;
                  return (
                    <>
                      <tr
                        key={rowId}
                        onClick={() => toggleExpand(rowId)}
                        style={{ cursor: 'pointer' }}
                      >
                        <td style={{ color: 'var(--text-muted)', paddingRight: 0 }}>
                          {isOpen
                            ? <ChevronDown size={12} />
                            : <ChevronRight size={12} />}
                        </td>
                        <td>
                          <span className="mono" style={{ fontSize: 11, color: 'var(--text-primary)' }}>
                            {ioc.value.length > 45 ? ioc.value.slice(0, 45) + '…' : ioc.value}
                          </span>
                        </td>
                        <td><TypeBadge type={ioc.type} /></td>
                        <td><span className="badge badge-gray">{ioc.source_feed}</span></td>
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
                      </tr>
                      {isOpen && <ExpandedRow key={`${rowId}-exp`} ioc={ioc} />}
                    </>
                  );
                })}
              </tbody>
            </table>
            {!debouncedQ && <Pagination page={page} total={total} limit={25} onPage={setPage} />}
          </>
        )}
      </div>
      </>
      )}
    </div>
  );
}
