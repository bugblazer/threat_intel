import { useState, useEffect } from 'react';
import { RefreshCw, Database } from 'lucide-react';
import { api } from '../lib/api.js';
import { useAuth } from '../hooks/useAuth.jsx';
import { Spinner, EmptyState } from '../components/ui/index.jsx';

const SOURCES = [
  { value: '',        label: 'All sources' },
  { value: 'mitre',   label: 'MITRE ATT&CK' },
  { value: 'nvd',     label: 'NVD CVE' },
  { value: 'abusech', label: 'Abuse.ch' },
  { value: 'otx',     label: 'AlienVault OTX' },
];

export default function IngestionPage() {
  const { user } = useAuth();
  const canRun   = user?.role === 'contributor' || user?.role === 'admin';

  const [ingestStatus, setIngestStatus] = useState(null);
  const [ingesting, setIngesting]       = useState(false);
  const [ingestSource, setIngestSource] = useState('');

  const loadStatus = () => api.ingestStatus().then(setIngestStatus).catch(() => {});

  useEffect(() => {
    if (!canRun) return;
    loadStatus();
    const t = setInterval(loadStatus, 5000);
    return () => clearInterval(t);
  }, [canRun]);

  const triggerIngest = async () => {
    setIngesting(true);
    try {
      await api.triggerIngest({ source: ingestSource || undefined });
      await loadStatus();
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
          {ingestStatus && (
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              {ingestStatus.running && (
                <div style={{ color: 'var(--high)', marginBottom: 6 }}>⟳ Ingestion in progress…</div>
              )}
              {ingestStatus.last && (
                <div>
                  <div style={{ marginBottom: 4 }}>
                    Last run: {new Date(ingestStatus.last.completedAt).toLocaleString()}
                  </div>
                  {ingestStatus.last.triggeredBy && (
                    <div>Triggered by: {ingestStatus.last.triggeredBy}</div>
                  )}
                  {ingestStatus.last.error && (
                    <div style={{ color: 'var(--critical)', marginTop: 4 }}>
                      Error: {ingestStatus.last.error}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
