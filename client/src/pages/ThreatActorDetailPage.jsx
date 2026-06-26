import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Globe, Target } from 'lucide-react';
import { api } from '../lib/api.js';
import { MonoId, TypeBadge, LoadingState } from '../components/ui/index.jsx';

export default function ThreatActorDetailPage() {
  const { id }     = useParams();
  const navigate   = useNavigate();
  const [actor, setActor]     = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState('');

  useEffect(() => {
    api.threatActor(id)
      .then(setActor)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) return <LoadingState />;
  if (error)   return <div style={{ color: 'var(--critical)', padding: 32 }}>{error}</div>;
  if (!actor)  return null;

  return (
    <div>
      <button className="btn btn-ghost" style={{ marginBottom: 20 }} onClick={() => navigate(-1)}>
        <ArrowLeft size={13} /> Back
      </button>

      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <div className="page-title">{actor.name}</div>
          {actor.country && (
            <span className="badge badge-gray">
              <Globe size={9} style={{ marginRight: 4 }} />{actor.country}
            </span>
          )}
          {actor.motivation && (
            <span className="badge badge-gray">
              <Target size={9} style={{ marginRight: 4 }} />{actor.motivation}
            </span>
          )}
        </div>
        {actor.aliases?.length > 0 && (
          <div className="page-sub" style={{ marginTop: 8, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>Also known as:</span>
            {actor.aliases.map(a => (
              <span key={a} className="badge badge-gray">{a}</span>
            ))}
          </div>
        )}
      </div>

      {/* Description */}
      {actor.description && (
        <div className="card mb-4">
          <div className="section-title" style={{ marginBottom: 10 }}>Profile</div>
          <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.7 }}>{actor.description}</p>
        </div>
      )}

      <div className="grid-2 mb-4">
        {/* ATT&CK techniques */}
        <div className="card">
          <div className="section-title" style={{ marginBottom: 12 }}>
            Known Techniques ({actor.techniques?.length ?? 0})
          </div>
          {actor.techniques?.length ? (
            <table className="data-table">
              <thead>
                <tr><th>ID</th><th>Name</th><th>Tactic</th></tr>
              </thead>
              <tbody>
                {actor.techniques.map(t => (
                  <tr key={t.technique_id} onClick={() => navigate(`/techniques/${t.technique_id}`)} style={{ cursor: 'pointer' }}>
                    <td><MonoId>{t.technique_id}</MonoId></td>
                    <td style={{ fontSize: 12 }}>{t.name}</td>
                    <td><span className="badge badge-gray">{t.tactic}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>No techniques mapped yet</div>
          )}
        </div>

        {/* Recent IOCs */}
        <div className="card">
          <div className="section-title" style={{ marginBottom: 12 }}>
            Recent IOCs ({actor.recentIocs?.length ?? 0})
          </div>
          {actor.recentIocs?.length ? (
            <table className="data-table">
              <thead>
                <tr><th>Value</th><th>Type</th><th>Technique</th></tr>
              </thead>
              <tbody>
                {actor.recentIocs.map((ioc, i) => (
                  <tr key={i}>
                    <td>
                      <span className="mono" style={{ fontSize: 11 }}>
                        {ioc.value.length > 28 ? ioc.value.slice(0, 28) + '…' : ioc.value}
                      </span>
                    </td>
                    <td><TypeBadge type={ioc.type} /></td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{ioc.technique_name}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>No IOCs linked via this actor's techniques</div>
          )}
        </div>
      </div>
    </div>
  );
}
