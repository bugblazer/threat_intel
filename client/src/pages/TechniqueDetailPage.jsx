import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { api } from '../lib/api.js';
import { CvssScore, SeverityBadge, MonoId, TypeBadge, LoadingState } from '../components/ui/index.jsx';

export default function TechniqueDetailPage() {
  const { techniqueId } = useParams();
  const navigate        = useNavigate();
  const [tech, setTech]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState('');

  useEffect(() => {
    api.technique(techniqueId)
      .then(setTech)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, [techniqueId]);

  if (loading) return <LoadingState />;
  if (error)   return <div style={{ color: 'var(--critical)', padding: 32 }}>{error}</div>;
  if (!tech)   return null;

  const platforms = Array.isArray(tech.platforms)
    ? tech.platforms
    : JSON.parse(tech.platforms || '[]');

  return (
    <div>
      <button className="btn btn-ghost" style={{ marginBottom: 20 }} onClick={() => navigate(-1)}>
        <ArrowLeft size={13} /> Back
      </button>

      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <div className="page-title mono" style={{ color: 'var(--cyan)' }}>{tech.technique_id}</div>
          <div className="page-title">{tech.name}</div>
          {tech.is_subtechnique && <span className="badge badge-gray">Sub-technique</span>}
        </div>
        <div className="page-sub" style={{ marginTop: 6, display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          {tech.tactic && <span className="badge badge-cyan">{tech.tactic}</span>}
          {platforms.map(p => (
            <span key={p} className="badge badge-gray">{p}</span>
          ))}
        </div>
      </div>

      {/* Description */}
      <div className="card mb-4">
        <div className="section-title" style={{ marginBottom: 10 }}>Description</div>
        <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.7, whiteSpace: 'pre-wrap' }}>
          {tech.description ?? 'No description available.'}
        </p>
      </div>

      <div className="grid-2 mb-4">
        {/* Linked CVEs */}
        <div className="card">
          <div className="section-title" style={{ marginBottom: 12 }}>
            Related CVEs ({tech.cves?.length ?? 0})
          </div>
          {tech.cves?.length ? (
            <table className="data-table">
              <thead>
                <tr><th>CVE ID</th><th>Score</th><th>Severity</th></tr>
              </thead>
              <tbody>
                {tech.cves.map(c => (
                  <tr key={c.cve_id} onClick={() => navigate(`/cves/${c.cve_id}`)} style={{ cursor: 'pointer' }}>
                    <td><MonoId>{c.cve_id}</MonoId></td>
                    <td><CvssScore score={c.cvss_score} /></td>
                    <td><SeverityBadge severity={c.severity} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>No CVEs linked yet</div>
          )}
        </div>

        {/* Linked IOCs */}
        <div className="card">
          <div className="section-title" style={{ marginBottom: 12 }}>
            Recent IOCs ({tech.iocs?.length ?? 0})
          </div>
          {tech.iocs?.length ? (
            <table className="data-table">
              <thead>
                <tr><th>Value</th><th>Type</th><th>Feed</th></tr>
              </thead>
              <tbody>
                {tech.iocs.map((ioc, i) => (
                  <tr key={i}>
                    <td>
                      <span className="mono" style={{ fontSize: 11 }}>
                        {ioc.value.length > 32 ? ioc.value.slice(0, 32) + '…' : ioc.value}
                      </span>
                    </td>
                    <td><TypeBadge type={ioc.type} /></td>
                    <td><span className="badge badge-gray">{ioc.source_feed}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>No IOCs linked yet</div>
          )}
        </div>
      </div>

      {/* Sub-techniques */}
      {tech.subTechniques?.length > 0 && (
        <div className="card">
          <div className="section-title" style={{ marginBottom: 12 }}>
            Sub-techniques ({tech.subTechniques.length})
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {tech.subTechniques.map(s => (
              <button
                key={s.technique_id}
                className="btn btn-ghost"
                style={{ fontSize: 12 }}
                onClick={() => navigate(`/techniques/${s.technique_id}`)}
              >
                <MonoId>{s.technique_id}</MonoId>
                <span style={{ marginLeft: 8, color: 'var(--text-secondary)' }}>{s.name}</span>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
