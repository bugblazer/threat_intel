import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Users, Globe, Target } from 'lucide-react';
import { api } from '../lib/api.js';
import { MonoId, LoadingState, EmptyState } from '../components/ui/index.jsx';

function ActorCard({ actor, onClick }) {
  const techCount = actor.technique_ids?.length ?? 0;
  return (
    <div
      className="card"
      style={{ cursor: 'pointer', transition: 'border-color 0.15s' }}
      onClick={onClick}
      onMouseEnter={e => e.currentTarget.style.borderColor = 'var(--cyan)'}
      onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--border)'}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
        <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: 14 }}>{actor.name}</div>
        {actor.country && (
          <span className="badge badge-gray">
            <Globe size={9} style={{ marginRight: 4 }} />{actor.country}
          </span>
        )}
      </div>
      {actor.motivation && (
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8 }}>
          <Target size={10} style={{ display: 'inline', marginRight: 4 }} />
          {actor.motivation}
        </div>
      )}
      {actor.description && (
        <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 10, lineHeight: 1.6 }}>
          {actor.description.length > 120 ? actor.description.slice(0, 120) + '…' : actor.description}
        </p>
      )}
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        {actor.aliases?.slice(0, 3).map(a => (
          <span key={a} className="badge badge-gray">{a}</span>
        ))}
        {techCount > 0 && (
          <span className="badge badge-cyan">
            {techCount} technique{techCount !== 1 ? 's' : ''}
          </span>
        )}
      </div>
    </div>
  );
}

export default function ThreatActorsPage() {
  const navigate = useNavigate();
  const [actors, setActors]     = useState([]);
  const [loading, setLoading]   = useState(true);
  const [query, setQuery]       = useState('');
  const [debouncedQ, setDebouncedQ] = useState('');

  useEffect(() => {
    const t = setTimeout(() => setDebouncedQ(query), 350);
    return () => clearTimeout(t);
  }, [query]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = debouncedQ
        ? await api.threatActorsSearch(debouncedQ)
        : await api.threatActors({ limit: 50 });
      setActors(data.data ?? []);
    } finally {
      setLoading(false);
    }
  }, [debouncedQ]);

  useEffect(() => { load(); }, [load]);

  return (
    <div>
      <div className="page-header">
        <div className="page-title">Threat Actors</div>
        <div className="page-sub">Adversary profiles with mapped ATT&CK techniques</div>
      </div>

      <div className="search-bar mb-4" style={{ maxWidth: 420 }}>
        <Search size={14} color="var(--text-muted)" />
        <input
          placeholder="Search actor names, aliases, country…"
          value={query}
          onChange={e => setQuery(e.target.value)}
        />
      </div>

      {loading ? (
        <LoadingState />
      ) : actors.length === 0 ? (
        <EmptyState icon={Users} message="No threat actors found" sub="Run the OTX ingestion script to populate actors" />
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 16 }}>
          {actors.map(a => (
            <ActorCard key={a.id} actor={a} onClick={() => navigate(`/threat-actors/${a.id}`)} />
          ))}
        </div>
      )}
    </div>
  );
}
