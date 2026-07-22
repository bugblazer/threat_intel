import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, ShieldCheck, Save } from 'lucide-react';
import { api } from '../lib/api.js';
import { useAuth } from '../hooks/useAuth.jsx';
import { CvssScore, SeverityBadge, MonoId, TypeBadge, LoadingState, Spinner } from '../components/ui/index.jsx';

const COVERAGE_STATES = ['none', 'partial', 'detected'];
const COVERAGE_STYLE = {
  none:     { label: 'None',     bg: 'var(--text-muted)',  color: 'var(--bg-base, #0b1120)' },
  partial:  { label: 'Partial',  bg: 'var(--medium, #f59e0b)', color: '#1a1500' },
  detected: { label: 'Detected', bg: 'var(--low, #10b981)', color: '#00190c' },
};

function CoverageBadge({ status }) {
  const s = COVERAGE_STYLE[status] ?? COVERAGE_STYLE.none;
  return (
    <span className="badge" style={{ background: s.bg, color: s.color, border: 'none' }}>
      {s.label}
    </span>
  );
}

// ── Detection coverage panel ──────────────────────────────────────────────────
function CoveragePanel({ tech, onSaved }) {
  const { user } = useAuth();
  const canEdit  = user?.role === 'contributor' || user?.role === 'admin';

  const [status, setStatus] = useState(tech.detection_status || 'none');
  const [notes, setNotes]   = useState(tech.detection_notes || '');
  const [saving, setSaving] = useState(false);
  const [savedAt, setSavedAt] = useState(0);
  const [error, setError]   = useState('');

  const dirty = status !== (tech.detection_status || 'none') || notes !== (tech.detection_notes || '');

  const save = async () => {
    setSaving(true);
    setError('');
    try {
      const updated = await api.setCoverage(tech.technique_id, { detection_status: status, detection_notes: notes });
      onSaved(updated);
      setSavedAt(Date.now());
    } catch (err) {
      setError(err.message || 'Failed to save');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="card mb-4">
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
        <ShieldCheck size={14} style={{ color: 'var(--low)' }} />
        <div className="section-title" style={{ margin: 0 }}>Detection Coverage</div>
        {!canEdit && <CoverageBadge status={tech.detection_status || 'none'} />}
      </div>

      {canEdit ? (
        <>
          <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
            {COVERAGE_STATES.map(s => (
              <button
                key={s}
                className={`btn ${status === s ? 'btn-primary' : 'btn-ghost'}`}
                style={{ fontSize: 12 }}
                onClick={() => setStatus(s)}
              >
                {COVERAGE_STYLE[s].label}
              </button>
            ))}
          </div>
          <label className="form-label">Notes</label>
          <textarea
            className="form-input"
            style={{ width: '100%', minHeight: 80, fontSize: 12, resize: 'vertical' }}
            placeholder="Why is this partial/blind? e.g. no EDR on Linux hosts, rule pending review…"
            value={notes}
            onChange={e => setNotes(e.target.value)}
          />
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 12 }}>
            <button className="btn btn-primary" onClick={save} disabled={saving || !dirty}>
              {saving ? <><Spinner size={13} /> Saving…</> : <><Save size={13} /> Save coverage</>}
            </button>
            {error && <span style={{ color: 'var(--critical)', fontSize: 12 }}>{error}</span>}
            {!error && savedAt > 0 && !dirty && <span style={{ color: 'var(--low)', fontSize: 12 }}>Saved</span>}
          </div>
        </>
      ) : (
        <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6, whiteSpace: 'pre-wrap', margin: 0 }}>
          {tech.detection_notes || 'No coverage notes.'}
        </p>
      )}

      {tech.detection_updated_by && (
        <div style={{ marginTop: 12, fontSize: 11, color: 'var(--text-muted)' }}>
          Last set by {tech.detection_updated_by}
          {tech.detection_updated_at ? ` on ${new Date(tech.detection_updated_at).toLocaleString()}` : ''}
        </div>
      )}
    </div>
  );
}

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

      {/* Detection coverage */}
      <CoveragePanel
        tech={tech}
        onSaved={(updated) => setTech(prev => ({ ...prev, ...updated }))}
      />

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
