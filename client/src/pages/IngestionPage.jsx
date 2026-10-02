import { useState, useEffect } from 'react';
import { RefreshCw, Database } from 'lucide-react';
import { api } from '../lib/api.js';
import { useAuth } from '../hooks/useAuth.jsx';
import { Spinner, EmptyState } from '../components/ui/index.jsx';

const STATUS_COLOR = {
  running:     'var(--high)',
  succeeded:   'var(--low)',
  partial:     'var(--medium)',
  failed:      'var(--critical)',
  interrupted: 'var(--text-muted)',
};

const duration = (run) => {
  if (!run.finished_at) return '—';
  const s = Math.round((new Date(run.finished_at) - new Date(run.started_at)) / 1000);
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
};

// Per-source outcome, e.g. "nvd 412 · kev 1731 · otx failed"
const summary = (run) => {
  const parts = Object.entries(run.results ?? {}).map(([k, v]) => {
    const n = v?.count ?? v?.flagged ?? v?.total ?? v?.cveLinks;
    return n != null ? `${k} ${Number(n).toLocaleString()}` : k;
  });
  for (const k of Object.keys(run.errors ?? {})) parts.push(`${k} failed`);
  return parts.join(' · ') || '—';
};

const SOURCES = [
  { value: '',        label: 'All sources' },
  { value: 'mitre',   label: 'MITRE ATT&CK' },
  { value: 'nvd',     label: 'NVD CVE' },
  { value: 'kev',     label: 'CISA KEV' },
  { value: 'abusech', label: 'Abuse.ch' },
  { value: 'otx',     label: 'AlienVault OTX' },
];

export default function IngestionPage() {
  const { user } = useAuth();
  const canRun   = user?.role === 'contributor' || user?.role === 'admin';

  const [ingestStatus, setIngestStatus] = useState(null);
  const [ingesting, setIngesting]       = useState(false);
  const [ingestSource, setIngestSource] = useState('');
  const [error, setError]               = useState('');

  const loadStatus = () => api.ingestStatus().then(setIngestStatus).catch(() => {});

  useEffect(() => {
    if (!canRun) return;
    loadStatus();
    const t = setInterval(loadStatus, 5000);
    return () => clearInterval(t);
  }, [canRun]);

  const triggerIngest = async () => {
    setIngesting(true);
    setError('');
    try {
      await api.triggerIngest({ source: ingestSource || undefined });
      await loadStatus();
    } catch (err) {
      setError(err.message);
    } finally {
      setIngesting(false);
    }
  };

  return (
    <div>
      <div className="page-header">
        <div className="page-title">Data Ingestion</div>
        <div className="page-sub">Trigger a manual pull from the threat intelligence feeds</div>
      </div>

      {!canRun ? (
        <EmptyState icon={Database} message="Not authorized" sub="Ingestion requires the contributor or admin role." />
      ) : (
        <div className="card" style={{ maxWidth: 560 }}>
          <div className="section-title" style={{ marginBottom: 16 }}>Manual Ingestion</div>
          <div style={{ display: 'flex', gap: 8, marginBottom: 14 }}>
            <select className="filter-select" value={ingestSource} onChange={e => setIngestSource(e.target.value)}>
              {SOURCES.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
            </select>
            <button
              className="btn btn-primary"
              onClick={triggerIngest}
              disabled={ingesting || ingestStatus?.running}
            >
              {ingesting || ingestStatus?.running
                ? <><Spinner size={13} /> Running…</>
                : <><RefreshCw size={13} /> Run ingestion</>}
            </button>
          </div>
          {error && <div style={{ color: 'var(--critical)', fontSize: 12, marginBottom: 8 }}>{error}</div>}
          {ingestStatus?.running && (
            <div style={{ color: 'var(--high)', fontSize: 12 }}>
              ⟳ {ingestStatus.running.trigger === 'schedule' ? 'Scheduled' : 'Manual'} run in progress
              {ingestStatus.running.triggered_by && ` (started by ${ingestStatus.running.triggered_by})`}…
            </div>
          )}
        </div>
      )}

      {canRun && ingestStatus?.recent?.length > 0 && (
        <div className="card" style={{ padding: 0, marginTop: 16 }}>
          <div className="section-title" style={{ padding: '14px 16px 0' }}>Recent runs</div>
          <table className="data-table">
            <thead>
              <tr><th>Started</th><th>Trigger</th><th>Source</th><th>Status</th><th>Took</th><th>Result</th></tr>
            </thead>
            <tbody>
              {ingestStatus.recent.map(run => (
                <tr key={run.id} style={{ cursor: 'default' }}>
                  <td style={{ whiteSpace: 'nowrap', fontSize: 12 }}>{new Date(run.started_at).toLocaleString()}</td>
                  <td style={{ fontSize: 12 }}>{run.trigger === 'manual' ? run.triggered_by ?? 'manual' : run.trigger}</td>
                  <td className="mono" style={{ fontSize: 11 }}>{run.source ?? 'all'}</td>
                  <td style={{ fontSize: 12, fontWeight: 600, color: STATUS_COLOR[run.status] }}>{run.status}</td>
                  <td style={{ fontSize: 12 }}>{duration(run)}</td>
                  <td style={{ fontSize: 11, color: 'var(--text-muted)' }} title={JSON.stringify(run.errors)}>{summary(run)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
