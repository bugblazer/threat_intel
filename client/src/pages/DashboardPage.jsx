import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { PieChart, Pie, Cell, Tooltip as ReTooltip, ResponsiveContainer, Sector } from 'recharts';
import { ShieldAlert, Wifi, Crosshair, Flame } from 'lucide-react';
import { api } from '../lib/api.js';
import { SeverityBadge, CvssScore, MonoId, LoadingState } from '../components/ui/index.jsx';

const SEV_COLORS = {
  CRITICAL: '#FF3B3B',
  HIGH:     '#F59E0B',
  MEDIUM:   '#3B82F6',
  LOW:      '#10B981',
};

function KpiCard({ label, value, sub, accent = 'var(--cyan)' }) {
  return (
    <div className="kpi-card" style={{ '--accent': accent }}>
      <div className="kpi-label">{label}</div>
      <div className="kpi-value">{value?.toLocaleString() ?? '—'}</div>
      {sub && <div className="kpi-sub">{sub}</div>}
    </div>
  );
}

// Active (hovered) slice — pops outward with a glow
function ActiveSlice(props) {
  const { cx, cy, innerRadius, outerRadius, startAngle, endAngle, fill } = props;
  return (
    <g>
      <Sector
        cx={cx}
        cy={cy}
        innerRadius={innerRadius}
        outerRadius={outerRadius + 6}
        startAngle={startAngle}
        endAngle={endAngle}
        fill={fill}
        style={{ filter: `drop-shadow(0 0 6px ${fill})`, transition: 'all 0.2s ease' }}
      />
    </g>
  );
}

export default function DashboardPage() {
  const [data, setData]     = useState(null);
  const [error, setError]   = useState('');
  const [loading, setLoading] = useState(true);
  const [activeIndex, setActiveIndex] = useState(-1);
  const navigate            = useNavigate();

  useEffect(() => {
    api.dashboard()
      .then(setData)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <LoadingState />;
  if (error)   return <div style={{ color: 'var(--critical)', padding: 32 }}>Failed to load dashboard: {error}</div>;
  if (!data)   return null;

  const { kpis, charts, feeds } = data;

  const pieData = (charts.severityDistribution ?? []).map(r => ({
    name:  r.severity,
    value: Number(r.count),
    color: SEV_COLORS[r.severity] ?? '#64748B',
  }));

  const iocTypes   = (charts.iocsByType ?? []).map(r => ({ type: r.type, count: Number(r.count) }));
  const maxIocType = iocTypes.reduce((m, r) => Math.max(m, r.count), 0) || 1;

  return (
    <div>
      <div className="page-header">
        <div className="page-title">Intelligence Overview</div>
        <div className="page-sub">
          Live threat data across all ingested feeds
        </div>
      </div>

      {/* KPI row */}
      <div className="kpi-grid">
        <KpiCard
          label="Total CVEs"
          value={kpis.totalCves}
          sub="All ingested vulnerabilities"
          accent="var(--cyan)"
        />
        <KpiCard
          label="Critical CVEs"
          value={kpis.criticalCves}
          sub="CVSS ≥ 9.0"
          accent="var(--critical)"
        />
        <KpiCard
          label="Active IOCs"
          value={kpis.totalIocs}
          sub="Indicators of compromise"
          accent="var(--high)"
        />
        <KpiCard
          label="ATT&CK Techniques"
          value={kpis.totalTechniques}
          sub="MITRE coverage"
          accent="var(--medium)"
        />
        <KpiCard
          label="Detection Coverage"
          value={`${kpis.coveragePct ?? 0}%`}
          sub={`${kpis.detectedTechniques ?? 0} detected · ${kpis.partialTechniques ?? 0} partial · ${kpis.blindTechniques ?? 0} blind`}
          accent="var(--low)"
        />
      </div>

      {/* Detection coverage breakdown */}
      {kpis.totalTechniques > 0 && (
        <div className="card mb-6">
          <div className="section-header">
            <div className="section-title">
              <Crosshair size={12} style={{ display: 'inline', marginRight: 6, color: 'var(--low)' }} />
              Detection Coverage
            </div>
            <button className="btn btn-ghost" style={{ fontSize: 11, padding: '3px 8px' }} onClick={() => navigate('/techniques')}>
              Open matrix →
            </button>
          </div>
          {(() => {
            const total = kpis.totalTechniques || 1;
            const seg = [
              { key: 'detected', label: 'Detected', count: kpis.detectedTechniques ?? 0, color: 'rgba(45,190,110,0.85)' },
              { key: 'partial',  label: 'Partial',  count: kpis.partialTechniques ?? 0,  color: 'rgba(240,180,60,0.85)' },
              { key: 'none',     label: 'Blind',    count: kpis.blindTechniques ?? 0,    color: 'rgba(120,130,150,0.35)' },
            ];
            return (
              <>
                <div style={{ display: 'flex', height: 10, borderRadius: 5, overflow: 'hidden', background: 'var(--border)' }}>
                  {seg.map(s => s.count > 0 && (
                    <div key={s.key} title={`${s.label}: ${s.count}`} style={{ width: `${(s.count / total) * 100}%`, background: s.color, transition: 'width 0.5s' }} />
                  ))}
                </div>
                <div style={{ display: 'flex', gap: 16, marginTop: 12, flexWrap: 'wrap' }}>
                  {seg.map(s => (
                    <div key={s.key} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
                      <div style={{ width: 9, height: 9, borderRadius: 2, background: s.color }} />
                      <span style={{ color: 'var(--text-secondary)' }}>{s.label}</span>
                      <span className="mono" style={{ color: 'var(--text-primary)', fontSize: 11 }}>
                        {s.count} ({Math.round((s.count / total) * 100)}%)
                      </span>
                    </div>
                  ))}
                </div>
              </>
            );
          })()}
        </div>
      )}

      {/* Charts + Top techniques */}
      <div className="grid-2 mb-6">
        {/* Severity donut */}
        <div className="card">
          <div className="section-header">
            <div className="section-title">CVE Severity Distribution</div>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={pieData}
                cx="50%"
                cy="50%"
                innerRadius={55}
                outerRadius={85}
                paddingAngle={3}
                dataKey="value"
                isAnimationActive
                animationBegin={200}
                animationDuration={1400}
                animationEasing="ease-out"
                activeIndex={activeIndex}
                activeShape={ActiveSlice}
                onMouseEnter={(_, i) => setActiveIndex(i)}
                onMouseLeave={() => setActiveIndex(-1)}
              >
                {pieData.map((entry, i) => (
                  <Cell
                    key={i}
                    fill={entry.color}
                    style={{ cursor: 'pointer', transition: 'opacity 0.2s ease' }}
                    opacity={activeIndex === -1 || activeIndex === i ? 1 : 0.4}
                  />
                ))}
              </Pie>
              <ReTooltip
                contentStyle={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 6, fontSize: 12 }}
                itemStyle={{ color: 'var(--text-primary)' }}
              />
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap', marginTop: 8 }}>
            {pieData.map((d, i) => (
              <div
                key={d.name}
                onMouseEnter={() => setActiveIndex(i)}
                onMouseLeave={() => setActiveIndex(-1)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, cursor: 'pointer',
                  opacity: activeIndex === -1 || activeIndex === i ? 1 : 0.4,
                  transition: 'opacity 0.2s ease',
                }}
              >
                <div style={{ width: 8, height: 8, borderRadius: 2, background: d.color }} />
                <span style={{ color: 'var(--text-secondary)' }}>{d.name}</span>
                <span className="mono" style={{ color: 'var(--text-primary)', fontSize: 11 }}>{d.value.toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Top techniques */}
        <div className="card">
          <div className="section-header">
            <div className="section-title">
              <Flame size={12} style={{ display: 'inline', marginRight: 6, color: 'var(--high)' }} />
              Hottest Techniques
            </div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {(feeds.topTechniques ?? []).slice(0, 7).map(t => {
              const maxFreq = Number(feeds.topTechniques[0]?.total_frequency) || 1;
              const pct = Math.round((Number(t.total_frequency) / maxFreq) * 100);
              return (
                <div key={t.technique_id} style={{ cursor: 'pointer' }} onClick={() => navigate(`/techniques/${t.technique_id}`)}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                    <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{t.name}</span>
                    <MonoId>{t.technique_id}</MonoId>
                  </div>
                  <div style={{ height: 3, background: 'var(--border)', borderRadius: 2 }}>
                    <div style={{ height: '100%', width: `${pct}%`, background: 'var(--cyan)', borderRadius: 2, transition: 'width 0.5s' }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* IOCs by type — data was already returned by the API but never shown */}
      {iocTypes.length > 0 && (
        <div className="card mb-6">
          <div className="section-header">
            <div className="section-title">
              <Wifi size={12} style={{ display: 'inline', marginRight: 6, color: 'var(--cyan)' }} />
              IOCs by Type
            </div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {iocTypes.map(r => (
              <div key={r.type} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span className="mono" style={{ width: 70, fontSize: 11, color: 'var(--text-secondary)' }}>{r.type}</span>
                <div style={{ flex: 1, height: 6, background: 'var(--border)', borderRadius: 3 }}>
                  <div style={{ height: '100%', width: `${Math.round((r.count / maxIocType) * 100)}%`, background: 'var(--cyan)', borderRadius: 3, transition: 'width 0.5s' }} />
                </div>
                <span className="mono" style={{ width: 64, textAlign: 'right', fontSize: 11, color: 'var(--text-primary)' }}>{r.count.toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recent feeds */}
      <div className="grid-2">
        {/* Recent CVEs */}
        <div className="card">
          <div className="section-header">
            <div className="section-title">
              <ShieldAlert size={12} style={{ display: 'inline', marginRight: 6, color: 'var(--critical)' }} />
              Recent CVEs
            </div>
            <button className="btn btn-ghost" style={{ fontSize: 11, padding: '3px 8px' }} onClick={() => navigate('/cves')}>
              View all →
            </button>
          </div>
          <table className="data-table">
            <thead>
              <tr>
                <th>CVE ID</th>
                <th>Score</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {(feeds.recentCves ?? []).map(c => (
                <tr key={c.cve_id} onClick={() => navigate(`/cves/${c.cve_id}`)}>
                  <td><MonoId>{c.cve_id}</MonoId></td>
                  <td><CvssScore score={c.cvss_score} /></td>
                  <td><SeverityBadge severity={c.severity} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Recent IOCs */}
        <div className="card">
          <div className="section-header">
            <div className="section-title">
              <Wifi size={12} style={{ display: 'inline', marginRight: 6, color: 'var(--cyan)' }} />
              Recent IOCs
            </div>
            <button className="btn btn-ghost" style={{ fontSize: 11, padding: '3px 8px' }} onClick={() => navigate('/iocs')}>
              View all →
            </button>
          </div>
          <table className="data-table">
            <thead>
              <tr>
                <th>Value</th>
                <th>Type</th>
                <th>Feed</th>
              </tr>
            </thead>
            <tbody>
              {(feeds.recentIocs ?? []).map((ioc, i) => (
                <tr key={i}>
                  <td>
                    <span className="mono" style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                      {ioc.value.length > 30 ? ioc.value.slice(0, 30) + '…' : ioc.value}
                    </span>
                  </td>
                  <td><span className="badge badge-cyan">{ioc.type}</span></td>
                  <td><span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{ioc.source_feed}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}