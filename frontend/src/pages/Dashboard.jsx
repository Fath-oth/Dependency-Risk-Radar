// pages/Dashboard.jsx
import { useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  RadialBarChart, RadialBar, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, Tooltip, Cell,
  PieChart, Pie, Legend,
} from 'recharts';
import { useStore } from '../stores/useStore';
import { RiskBadge, ScoreBar, StatCard, Spinner, EmptyState } from '../components/shared';
import { AlertTriangle, ShieldCheck, GitBranch, Package, ChevronRight } from 'lucide-react';

const RISK_COLORS = {
  BLOCKING: '#7f1d1d',
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MODERATE: '#eab308',
  LOW:      '#22c55e',
};

export default function Dashboard() {
  const { reportId } = useParams();
  const { activeReport, activeReportLoading, fetchReport } = useStore();

  useEffect(() => {
    if (reportId) fetchReport(reportId);
  }, [reportId]);

  if (activeReportLoading) {
    return <div className="flex items-center justify-center h-full"><Spinner size={10} /></div>;
  }
  if (!activeReport) {
    return <EmptyState icon="📊" title="No report loaded" description="Run an analysis or select a report from the sidebar." />;
  }

  const { summary, global_risk_score, project_name, analyzed_at } = activeReport;

  // Distribution data for pie chart
  const distribution = [
    { name: 'Critical', value: summary.critical_components, color: RISK_COLORS.CRITICAL },
    { name: 'High',     value: summary.high_components,     color: RISK_COLORS.HIGH },
    { name: 'Moderate', value: summary.moderate_components, color: RISK_COLORS.MODERATE },
    { name: 'Low',      value: summary.low_components,      color: RISK_COLORS.LOW },
  ].filter(d => d.value > 0);

  // Top 10 riskiest components
  const top10 = [...(activeReport.components || [])]
    .sort((a, b) => b.scores.global - a.scores.global)
    .slice(0, 10);

  const globalColor =
    global_risk_score >= 75 ? '#ef4444' :
    global_risk_score >= 50 ? '#f97316' :
    global_risk_score >= 20 ? '#eab308' : '#22c55e';

  return (
    <div className="p-6 space-y-6 overflow-y-auto h-full">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">{project_name}</h1>
          <p className="text-sm text-gray-400 mt-1">
            Analysed {new Date(analyzed_at).toLocaleString()} · {summary.total_components} components
          </p>
        </div>
        <Link
          to={`/report/${reportId}/plan`}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white text-sm px-4 py-2 rounded-lg transition"
        >
          View Update Plan <ChevronRight size={14} />
        </Link>
      </div>

      {/* Global score gauge + stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {/* Gauge */}
        <div className="col-span-2 md:col-span-1 bg-gray-800 border border-gray-700 rounded-xl p-4 flex flex-col items-center justify-center">
          <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">Global Risk</p>
          <div className="relative w-24 h-24">
            <ResponsiveContainer width="100%" height="100%">
              <RadialBarChart
                cx="50%" cy="50%"
                innerRadius="70%" outerRadius="100%"
                startAngle={90} endAngle={-270}
                data={[{ value: global_risk_score, fill: globalColor }]}
              >
                <RadialBar dataKey="value" cornerRadius={4} background={{ fill: '#374151' }} />
              </RadialBarChart>
            </ResponsiveContainer>
            <span className="absolute inset-0 flex items-center justify-center text-2xl font-bold" style={{ color: globalColor }}>
              {global_risk_score}
            </span>
          </div>
        </div>

        <StatCard label="Total CVEs" value={summary.total_cves} color="text-red-400" sub={`${summary.vulnerable_components} components affected`} />
        <StatCard label="Outdated" value={summary.outdated_components} color="text-orange-400" sub="behind latest version" />
        <StatCard label="Copyleft" value={summary.copyleft_components} color="text-yellow-400" sub="licence risk" />
        <StatCard label="Trackers" value={summary.tracker_components} color="text-purple-400" sub="privacy risk" />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Risk distribution pie */}
        <div className="bg-gray-800 border border-gray-700 rounded-xl p-4">
          <h2 className="text-sm font-semibold text-gray-300 mb-3">Risk Distribution</h2>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={distribution} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}>
                {distribution.map((entry) => (
                  <Cell key={entry.name} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip formatter={(v, n) => [v, n]} contentStyle={{ background: '#1f2937', border: 'none' }} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Top 10 bar chart */}
        <div className="bg-gray-800 border border-gray-700 rounded-xl p-4">
          <h2 className="text-sm font-semibold text-gray-300 mb-3">Top 10 Riskiest Components</h2>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={top10} layout="vertical" margin={{ left: 0, right: 20 }}>
              <XAxis type="number" domain={[0, 100]} tick={{ fill: '#9ca3af', fontSize: 11 }} />
              <YAxis type="category" dataKey="artifact" width={90} tick={{ fill: '#d1d5db', fontSize: 10 }} />
              <Tooltip
                formatter={(v) => [`${v}/100`, 'Risk score']}
                contentStyle={{ background: '#1f2937', border: 'none', fontSize: 12 }}
              />
              <Bar dataKey="scores.global" radius={[0, 3, 3, 0]}>
                {top10.map((c) => (
                  <Cell
                    key={c.purl}
                    fill={
                      c.scores.global >= 75 ? RISK_COLORS.CRITICAL :
                      c.scores.global >= 50 ? RISK_COLORS.HIGH :
                      c.scores.global >= 20 ? RISK_COLORS.MODERATE :
                      RISK_COLORS.LOW
                    }
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Top critical components list */}
      <div className="bg-gray-800 border border-gray-700 rounded-xl p-4">
        <h2 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
          <AlertTriangle size={14} className="text-red-400" /> Critical Components
        </h2>
        <div className="space-y-2">
          {top10.filter(c => c.scores.global >= 50).map(comp => (
            <Link
              key={comp.purl}
              to={`/report/${reportId}/explorer`}
              className="flex items-center gap-3 p-2 rounded-lg hover:bg-gray-700 transition cursor-pointer"
            >
              <Package size={14} className="text-gray-400 flex-shrink-0" />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-white truncate">{comp.name}</p>
                <p className="text-xs text-gray-400">v{comp.version} · {comp.is_direct ? 'direct' : `transitive (depth ${comp.depth})`}</p>
              </div>
              <div className="flex items-center gap-3 flex-shrink-0">
                <ScoreBar score={comp.scores.global} className="w-24" />
                <RiskBadge level={comp.scores.risk_level} />
              </div>
            </Link>
          ))}
          {top10.filter(c => c.scores.global >= 50).length === 0 && (
            <div className="flex items-center gap-2 text-green-400 text-sm py-2">
              <ShieldCheck size={16} /> No critical components detected
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
