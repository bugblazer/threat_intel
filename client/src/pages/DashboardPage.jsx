import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { PieChart, Pie, Cell, Tooltip as ReTooltip, ResponsiveContainer } from 'recharts';
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

export default function DashboardPage() {
  const [data, setData]     = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate            = useNavigate();

  useEffect(() => {
    api.dashboard()
      .then(setData)
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <LoadingState />;
  if (!data)   return null;

  const { kpis, charts, feeds } = data;

  const pieData = (charts.severityDistribution ?? []).map(r => ({
    name:  r.severity,
    value: Number(r.count),
    color: SEV_COLORS[r.severity] ?? '#64748B',
  }));

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
      </div>

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
              >
                {pieData.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              <ReTooltip
                contentStyle={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 6, fontSize: 12 }}
                itemStyle={{ color: 'var(--text-primary)' }}
              />
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap', marginTop: 8 }}>
            {pieData.map(d => (
              <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
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
              const maxFreq = feeds.topTechniques[0]?.total_frequency || 1;
              const pct = Math.round((t.total_frequency / maxFreq) * 100);
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
