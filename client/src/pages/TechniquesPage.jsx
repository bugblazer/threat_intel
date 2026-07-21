import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../lib/api.js';
import { useAuth } from '../hooks/useAuth.jsx';
import { LoadingState, EmptyState } from '../components/ui/index.jsx';
import { Crosshair } from 'lucide-react';

const COVERAGE_ORDER = ['none', 'partial', 'detected'];
const COVERAGE_META = {
  none:     { label: 'None',     bg: 'rgba(120,130,150,0.14)', text: 'rgba(200,210,225,0.7)' },
  partial:  { label: 'Partial',  bg: 'rgba(240,180,60,0.80)',  text: 'rgba(30,25,0,0.9)' },
  detected: { label: 'Detected', bg: 'rgba(45,190,110,0.85)',  text: 'rgba(0,25,12,0.9)' },
};

function coverageColor(status) { return (COVERAGE_META[status] ?? COVERAGE_META.none).bg; }
function coverageText(status)  { return (COVERAGE_META[status] ?? COVERAGE_META.none).text; }

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

  const canEdit = user?.role === 'contributor' || user?.role === 'admin';

  useEffect(() => {
    api.heatmap()
      .then(setHeatmap)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  // Update a technique's detection_status everywhere in the heatmap state.
  const applyStatus = (techniqueId, status) => {
    setHeatmap(prev => {
      if (!prev) return prev;
      const upd = arr => (arr ?? []).map(t => t.technique_id === techniqueId ? { ...t, detection_status: status } : t);
      const byTactic = Object.fromEntries(Object.entries(prev.byTactic).map(([k, v]) => [k, upd(v)]));
      return { ...prev, data: upd(prev.data), byTactic };
    });
  };

  const cycleCoverage = async (technique) => {
    const cur  = technique.detection_status || 'none';
    const next = COVERAGE_ORDER[(COVERAGE_ORDER.indexOf(cur) + 1) % COVERAGE_ORDER.length];
    applyStatus(technique.technique_id, next); // optimistic
    try {
      await api.setCoverage(technique.technique_id, { detection_status: next });
    } catch {
      applyStatus(technique.technique_id, cur); // revert on failure
    }
  };

  const handleCellClick = (technique) => {
    if (mode === 'coverage' && canEdit) cycleCoverage(technique);
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
      <div className="page-header">
        <div className="page-title">ATT&CK Technique Matrix</div>
        <div className="page-sub">
          {mode === 'frequency'
            ? 'Cell intensity = combined IOC + CVE frequency. Click any technique for detail.'
            : canEdit
              ? 'Cell colour = your detection coverage. Click a cell to cycle None → Partial → Detected.'
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
        </div>
      )}
    </div>
  );
}
