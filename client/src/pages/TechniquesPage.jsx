import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../lib/api.js';
import { useAuth } from '../hooks/useAuth.jsx';
import { LoadingState, EmptyState, Spinner } from '../components/ui/index.jsx';
import { Crosshair, X, Save, ExternalLink } from 'lucide-react';

const COVERAGE_ORDER = ['none', 'partial', 'detected'];
const COVERAGE_META = {
  none:     { label: 'None',     bg: 'rgba(120,130,150,0.14)', text: 'rgba(200,210,225,0.7)' },
  partial:  { label: 'Partial',  bg: 'rgba(240,180,60,0.80)',  text: 'rgba(30,25,0,0.9)' },
  detected: { label: 'Detected', bg: 'rgba(45,190,110,0.85)',  text: 'rgba(0,25,12,0.9)' },
};

function coverageColor(status) { return (COVERAGE_META[status] ?? COVERAGE_META.none).bg; }
function coverageText(status)  { return (COVERAGE_META[status] ?? COVERAGE_META.none).text; }

// ── Coverage editor modal ─────────────────────────────────────────────────────
// Opened from the matrix in coverage mode. Lets a contributor/admin set the
// status AND the notes in one place — this is where notes are edited.
function CoverageEditModal({ technique, onClose, onSaved, onOpenDetail }) {
  const [status, setStatus] = useState(technique.detection_status || 'none');
  const [notes, setNotes]   = useState(technique.detection_notes || '');
  const [saving, setSaving] = useState(false);
  const [error, setError]   = useState('');

  const save = async () => {
    setSaving(true);
    setError('');
    try {
      const updated = await api.setCoverage(technique.technique_id, {
        detection_status: status,
        detection_notes:  notes,
      });
      onSaved(updated);
      onClose();
    } catch (err) {
      setError(err.message || 'Failed to save');
    } finally {
      setSaving(false);
    }
  };

  const handleBackdrop = (e) => { if (e.target === e.currentTarget) onClose(); };

  return (
    <div
      onClick={handleBackdrop}
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 200,
      }}
    >
      <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 10, padding: 24, width: 440, maxWidth: '90vw' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 4 }}>
          <div>
            <div className="mono" style={{ color: 'var(--cyan)', fontSize: 12 }}>{technique.technique_id}</div>
            <div style={{ fontWeight: 600, fontSize: 15, color: 'var(--text-primary)', marginTop: 2 }}>{technique.name}</div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 2 }}>
            <X size={16} />
          </button>
        </div>

        <div style={{ marginTop: 18 }}>
          <label className="form-label">Detection status</label>
          <div style={{ display: 'flex', gap: 8, marginTop: 6, marginBottom: 16, flexWrap: 'wrap' }}>
            {COVERAGE_ORDER.map(s => (
              <button
                key={s}
                className={`btn ${status === s ? 'btn-primary' : 'btn-ghost'}`}
                style={{ fontSize: 12 }}
                onClick={() => setStatus(s)}
              >
                {COVERAGE_META[s].label}
              </button>
            ))}
          </div>

          <label className="form-label">Notes</label>
          <textarea
            className="form-input"
            style={{ width: '100%', minHeight: 90, fontSize: 12, resize: 'vertical', marginTop: 6 }}
            placeholder="Why is this partial/blind? e.g. no EDR on Linux hosts, detection rule pending…"
            value={notes}
            onChange={e => setNotes(e.target.value)}
            autoFocus
          />

          {technique.detection_updated_by && (
            <div style={{ marginTop: 10, fontSize: 11, color: 'var(--text-muted)' }}>
              Last set by {technique.detection_updated_by}
              {technique.detection_updated_at ? ` on ${new Date(technique.detection_updated_at).toLocaleString()}` : ''}
            </div>
          )}

          {error && <div style={{ color: 'var(--critical)', fontSize: 12, marginTop: 10 }}>{error}</div>}

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 18 }}>
            <button className="btn btn-ghost" style={{ fontSize: 12 }} onClick={() => onOpenDetail(technique.technique_id)}>
              <ExternalLink size={12} /> Open detail
            </button>
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn btn-ghost" onClick={onClose} disabled={saving}>Cancel</button>
              <button className="btn btn-primary" onClick={save} disabled={saving}>
                {saving ? <><Spinner size={13} /> Saving…</> : <><Save size={13} /> Save</>}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

const TACTIC_ORDER = [
  'reconnaissance', 'resource-development', 'initial-access',
  'execution', 'persistence', 'privilege-escalation',
  'defense-evasion', 'credential-access', 'discovery',
  'lateral-movement', 'collection', 'command-and-control',
  'exfiltration', 'impact',
];

const TACTIC_LABELS = {
  'reconnaissance':       'Recon',
  'resource-development': 'Resource Dev',
  'initial-access':       'Initial Access',
  'execution':            'Execution',
  'persistence':          'Persistence',
  'privilege-escalation': 'Priv Esc',
  'defense-evasion':      'Defense Evasion',
  'credential-access':    'Cred Access',
  'discovery':            'Discovery',
  'lateral-movement':     'Lateral Mvmt',
  'collection':           'Collection',
  'command-and-control':  'C2',
  'exfiltration':         'Exfiltration',
  'impact':               'Impact',
};

function cellColor(freq, max) {
  if (!freq || !max) return 'rgba(26,34,53,0.8)';
  const ratio = freq / max;
  const alpha = 0.1 + ratio * 0.85;
  if (ratio > 0.75) return `rgba(0, 212, 255, ${alpha})`;
  if (ratio > 0.5)  return `rgba(0, 160, 210, ${alpha})`;
  if (ratio > 0.25) return `rgba(0, 100, 160, ${alpha})`;
  return `rgba(20, 60, 100, ${alpha})`;
}

function cellTextColor(freq, max) {
  if (!max || !freq) return 'var(--text-muted)';
  return freq / max > 0.5 ? 'rgba(0,20,30,0.9)' : 'rgba(200,230,240,0.8)';
}

export default function TechniquesPage() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [heatmap, setHeatmap] = useState(null);
  const [tooltip, setTooltip] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState('');
  const [mode, setMode]       = useState('frequency'); // 'frequency' | 'coverage'
  const [editing, setEditing] = useState(null);        // technique being edited in coverage modal

  const canEdit = user?.role === 'contributor' || user?.role === 'admin';

  useEffect(() => {
    api.heatmap()
      .then(setHeatmap)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  // Merge a partial patch into a technique everywhere in the heatmap state.
  const applyPatch = (techniqueId, patch) => {
    setHeatmap(prev => {
      if (!prev) return prev;
      const upd = arr => (arr ?? []).map(t => t.technique_id === techniqueId ? { ...t, ...patch } : t);
      const byTactic = Object.fromEntries(Object.entries(prev.byTactic).map(([k, v]) => [k, upd(v)]));
      return { ...prev, data: upd(prev.data), byTactic };
    });
  };

  const handleCellClick = (technique) => {
    // In coverage mode, editors get the status+notes editor right here;
    // everyone else (and frequency mode) navigates to the technique detail page.
    if (mode === 'coverage' && canEdit) setEditing(technique);
    else navigate(`/techniques/${technique.technique_id}`);
  };

  if (loading) return <LoadingState />;
  if (error)   return <EmptyState icon={Crosshair} message="Failed to load matrix" sub={error} />;
  if (!heatmap?.data?.length) return <EmptyState icon={Crosshair} message="No technique data yet" sub="Run the MITRE ingestion script first" />;

  // PG COUNT returns bigints; Knex serialises them as strings to avoid JS
  // precision loss. Coerce all numeric fields to Number before any arithmetic.
  const byTactic = Object.fromEntries(
    Object.entries(heatmap.byTactic).map(([tactic, techniques]) => [
      tactic,
      techniques.map(t => ({
        ...t,
        ioc_count:       Number(t.ioc_count),
        cve_count:       Number(t.cve_count),
        total_frequency: Number(t.total_frequency),
      })),
    ])
  );

  const allTechniques = Object.values(byTactic).flat();
  const maxFreq = allTechniques.reduce((m, t) => Math.max(m, t.total_frequency), 0) || 1;

  const tactics = TACTIC_ORDER.filter(t => byTactic[t]?.length);

  return (
    <div>
      {editing && (
        <CoverageEditModal
          technique={editing}
          onClose={() => setEditing(null)}
          onSaved={(updated) => applyPatch(updated.technique_id, updated)}
          onOpenDetail={(id) => navigate(`/techniques/${id}`)}
        />
      )}

      <div className="page-header">
        <div className="page-title">ATT&CK Technique Matrix</div>
        <div className="page-sub">
          {mode === 'frequency'
            ? 'Cell intensity = combined IOC + CVE frequency. Click any technique for detail.'
            : canEdit
              ? 'Cell colour = your detection coverage. Click a cell to set its status and add notes.'
              : 'Cell colour = detection coverage. Ask a contributor to update coverage.'}
        </div>
      </div>

      {/* Mode toggle */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 14 }}>
        <button
          className={`btn ${mode === 'frequency' ? 'btn-primary' : 'btn-ghost'}`}
          style={{ fontSize: 12 }}
          onClick={() => setMode('frequency')}
        >
          Frequency
        </button>
        <button
          className={`btn ${mode === 'coverage' ? 'btn-primary' : 'btn-ghost'}`}
          style={{ fontSize: 12 }}
          onClick={() => setMode('coverage')}
        >
          Detection coverage
        </button>
      </div>

      <div className="card" style={{ padding: '20px 16px', overflowX: 'auto' }}>
        {/* Tactic header row */}
        <div style={{ display: 'flex', gap: 4, marginBottom: 8, minWidth: tactics.length * 96 }}>
          {tactics.map(tactic => (
            <div key={tactic} style={{ width: 92, flexShrink: 0 }}>
              <div className="heatmap-tactic-label">{TACTIC_LABELS[tactic] ?? tactic}</div>
            </div>
          ))}
        </div>

        {/* Cells */}
        {(() => {
          const maxRows = Math.max(...tactics.map(t => (byTactic[t] ?? []).length));
          return Array.from({ length: maxRows }, (_, row) => (
            <div key={row} style={{ display: 'flex', gap: 4, marginBottom: 4, minWidth: tactics.length * 96 }}>
              {tactics.map(tactic => {
                const technique = (byTactic[tactic] ?? [])[row];
                if (!technique) return <div key={tactic} style={{ width: 92, flexShrink: 0 }} />;

                const freq    = technique.total_frequency;
                const isCov   = mode === 'coverage';
                const status  = technique.detection_status || 'none';
                const bg      = isCov ? coverageColor(status) : cellColor(freq, maxFreq);
                const textCol = isCov ? coverageText(status)  : cellTextColor(freq, maxFreq);
                const border  = isCov
                  ? (status === 'none' ? 'rgba(30,45,69,0.6)' : 'rgba(255,255,255,0.25)')
                  : (freq > 0 ? 'rgba(0,212,255,0.2)' : 'rgba(30,45,69,0.6)');

                return (
                  <div
                    key={tactic}
                    className="heatmap-cell"
                    style={{
                      width: 92, flexShrink: 0, height: 44, background: bg,
                      border: `1px solid ${border}`,
                      padding: '5px 6px', display: 'flex', flexDirection: 'column',
                      justifyContent: 'space-between',
                      cursor: isCov && canEdit ? 'cell' : 'pointer',
                    }}
                    onClick={() => handleCellClick(technique)}
                    onMouseEnter={e => {
                      const rect   = e.currentTarget.getBoundingClientRect();
                      const tipW   = 220;
                      const tipH   = 120;
                      const x = (window.innerWidth - rect.right) >= tipW + 12 ? rect.right + 8 : rect.left - tipW - 8;
                      const y = (window.innerHeight - rect.top)  >= tipH       ? rect.top       : rect.bottom - tipH;
                      setTooltip({ technique, x, y });
                    }}
                    onMouseLeave={() => setTooltip(null)}
                  >
                    <div className="heatmap-cell-label" style={{ color: textCol, fontSize: 8, fontWeight: 600 }}>
                      {technique.technique_id}
                    </div>
                    <div className="heatmap-cell-label" style={{ color: textCol, fontSize: 7 }}>
                      {technique.name.length > 16 ? technique.name.slice(0, 16) + '…' : technique.name}
                    </div>
                  </div>
                );
              })}
            </div>
          ));
        })()}

        {/* Legend */}
        {mode === 'frequency' ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 16 }}>
            <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>Frequency:</span>
            {[0, 0.25, 0.5, 0.75, 1].map(v => (
              <div key={v} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <div style={{ width: 16, height: 10, borderRadius: 2, background: cellColor(v * maxFreq, maxFreq) }} />
                {v === 0 && <span style={{ fontSize: 9, color: 'var(--text-muted)' }}>0</span>}
                {v === 1 && <span style={{ fontSize: 9, color: 'var(--text-muted)' }}>{maxFreq}</span>}
              </div>
            ))}
          </div>
        ) : (
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 16 }}>
            <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>Coverage:</span>
            {COVERAGE_ORDER.map(s => (
              <div key={s} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <div style={{ width: 16, height: 10, borderRadius: 2, background: coverageColor(s), border: '1px solid rgba(255,255,255,0.15)' }} />
                <span style={{ fontSize: 9, color: 'var(--text-muted)' }}>{COVERAGE_META[s].label}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {tooltip && (
        <div className="tooltip" style={{ left: tooltip.x, top: tooltip.y }}>
          <div className="tooltip-title">{tooltip.technique.name}</div>
          <div className="tooltip-row">
            <span>ID</span>
            <span className="tooltip-val">{tooltip.technique.technique_id}</span>
          </div>
          <div className="tooltip-row">
            <span>Tactic</span>
            <span className="tooltip-val">{tooltip.technique.tactic}</span>
          </div>
          <div className="tooltip-row">
            <span>IOCs</span>
            <span className="tooltip-val">{tooltip.technique.ioc_count}</span>
          </div>
          <div className="tooltip-row">
            <span>CVEs</span>
            <span className="tooltip-val">{tooltip.technique.cve_count}</span>
          </div>
          <div className="tooltip-row">
            <span>Frequency</span>
            <span className="tooltip-val">{tooltip.technique.total_frequency}</span>
          </div>
          <div className="tooltip-row">
            <span>Coverage</span>
            <span className="tooltip-val">
              {(COVERAGE_META[tooltip.technique.detection_status] ?? COVERAGE_META.none).label}
            </span>
          </div>
          {tooltip.technique.detection_updated_by && (
            <div className="tooltip-row">
              <span>Set by</span>
              <span className="tooltip-val">
                {tooltip.technique.detection_updated_by}
                {tooltip.technique.detection_updated_at
                  ? ` · ${new Date(tooltip.technique.detection_updated_at).toLocaleDateString()}`
                  : ''}
              </span>
            </div>
          )}
          {tooltip.technique.detection_notes && (
            <div className="tooltip-row">
              <span>Notes</span>
              <span className="tooltip-val" style={{ maxWidth: 140, textAlign: 'right' }}>
                {tooltip.technique.detection_notes.length > 60
                  ? tooltip.technique.detection_notes.slice(0, 60) + '…'
                  : tooltip.technique.detection_notes}
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
