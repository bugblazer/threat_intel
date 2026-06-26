import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, ExternalLink } from 'lucide-react';
import { api } from '../lib/api.js';
import { SeverityBadge, CvssScore, MonoId, LoadingState } from '../components/ui/index.jsx';

export default function CveDetailPage() {
  const { cveId }  = useParams();
  const navigate   = useNavigate();
  const [cve, setCve]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]   = useState('');

  useEffect(() => {
    api.cve(cveId)
      .then(setCve)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, [cveId]);

  if (loading) return <LoadingState />;
  if (error)   return <div style={{ color: 'var(--critical)', padding: 32 }}>{error}</div>;
  if (!cve)    return null;

  const products = Array.isArray(cve.affected_products)
    ? cve.affected_products
    : JSON.parse(cve.affected_products || '[]');

  const refs = Array.isArray(cve.references)
    ? cve.references
    : JSON.parse(cve.references || '[]');

  return (
    <div>
      <button className="btn btn-ghost" style={{ marginBottom: 20 }} onClick={() => navigate(-1)}>
        <ArrowLeft size={13} /> Back
      </button>

      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
          <div className="page-title mono" style={{ color: 'var(--cyan)', fontSize: 22 }}>{cve.cve_id}</div>
          <SeverityBadge severity={cve.severity} />
          <CvssScore score={cve.cvss_score} />
        </div>
        {cve.cwe_id && (
          <div className="page-sub" style={{ marginTop: 6 }}>
            Weakness: <span className="mono" style={{ color: 'var(--text-secondary)' }}>{cve.cwe_id}</span>
            {cve.published_at && (
              <span style={{ marginLeft: 16 }}>
                Published: {new Date(cve.published_at).toLocaleDateString()}
              </span>
            )}
          </div>
        )}
      </div>

      {/* Description */}
      <div className="card mb-4">
        <div className="section-title" style={{ marginBottom: 10 }}>Description</div>
        <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.7 }}>{cve.description}</p>
      </div>

      <div className="grid-2 mb-4">
        {/* Linked ATT&CK techniques */}
        <div className="card">
          <div className="section-title" style={{ marginBottom: 12 }}>Exploiting Techniques</div>
          {cve.techniques?.length ? (
            <table className="data-table">
              <thead>
                <tr><th>ID</th><th>Name</th><th>Tactic</th><th>Confidence</th></tr>
              </thead>
              <tbody>
                {cve.techniques.map(t => (
                  <tr key={t.technique_id} onClick={() => navigate(`/techniques/${t.technique_id}`)} style={{ cursor: 'pointer' }}>
                    <td><MonoId>{t.technique_id}</MonoId></td>
                    <td style={{ fontSize: 12 }}>{t.name}</td>
                    <td><span className="badge badge-gray">{t.tactic}</span></td>
                    <td><span className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>{t.confidence_score ?? '—'}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>No techniques linked yet</div>
          )}
        </div>

        {/* Affected products */}
        <div className="card">
          <div className="section-title" style={{ marginBottom: 12 }}>Affected Products</div>
          {products.length ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 280, overflowY: 'auto' }}>
              {products.slice(0, 30).map((p, i) => (
                <div key={i} style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'flex', gap: 8 }}>
                  <span className="mono" style={{ color: 'var(--text-muted)', minWidth: 80 }}>{p.vendor}</span>
                  <span>{p.product}</span>
                  {p.version && p.version !== '*' && (
                    <span className="mono" style={{ color: 'var(--text-muted)', fontSize: 11 }}>{p.version}</span>
                  )}
                </div>
              ))}
              {products.length > 30 && (
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>+{products.length - 30} more</div>
              )}
            </div>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>No product data</div>
          )}
        </div>
      </div>

      {/* References */}
      {refs.length > 0 && (
        <div className="card">
          <div className="section-title" style={{ marginBottom: 12 }}>References</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {refs.slice(0, 10).map((r, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
                <ExternalLink size={11} color="var(--text-muted)" style={{ flexShrink: 0 }} />
                <a href={r.url} target="_blank" rel="noreferrer"
                  style={{ color: 'var(--cyan)', textDecoration: 'none', wordBreak: 'break-all' }}>
                  {r.url}
                </a>
                {r.tags?.map(tag => (
                  <span key={tag} className="badge badge-gray" style={{ fontSize: 9 }}>{tag}</span>
                ))}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
