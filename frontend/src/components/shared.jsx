// components/RiskBadge.jsx
export function RiskBadge({ level, score }) {
  const config = {
    BLOCKING: { bg: 'bg-red-900', text: 'text-red-100', label: 'BLOCKING' },
    CRITICAL: { bg: 'bg-red-600', text: 'text-white',   label: 'CRITICAL' },
    HIGH:     { bg: 'bg-orange-500', text: 'text-white', label: 'HIGH'     },
    MODERATE: { bg: 'bg-yellow-400', text: 'text-gray-900', label: 'MODERATE' },
    LOW:      { bg: 'bg-green-500', text: 'text-white',  label: 'LOW'      },
  };
  const c = config[level] || config.LOW;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-bold ${c.bg} ${c.text}`}>
      {c.label}
      {score !== undefined && <span className="opacity-80">·{score}</span>}
    </span>
  );
}

// components/ScoreBar.jsx
export function ScoreBar({ score, max = 100, className = '' }) {
  const pct = Math.min((score / max) * 100, 100);
  const color =
    pct >= 75 ? 'bg-red-500' :
    pct >= 50 ? 'bg-orange-400' :
    pct >= 20 ? 'bg-yellow-400' :
    'bg-green-400';
  return (
    <div className={`flex items-center gap-2 ${className}`}>
      <div className="flex-1 h-1.5 bg-gray-700 rounded-full overflow-hidden">
        <div className={`h-full ${color} rounded-full transition-all`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-gray-300 w-8 text-right">{score}</span>
    </div>
  );
}

// components/StatCard.jsx
export function StatCard({ label, value, sub, color = 'text-white' }) {
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-xl p-4">
      <p className="text-xs text-gray-400 uppercase tracking-wide mb-1">{label}</p>
      <p className={`text-3xl font-bold ${color}`}>{value}</p>
      {sub && <p className="text-xs text-gray-500 mt-1">{sub}</p>}
    </div>
  );
}

// components/Spinner.jsx
export function Spinner({ size = 6 }) {
  return (
    <div className={`w-${size} h-${size} border-2 border-blue-500 border-t-transparent rounded-full animate-spin`} />
  );
}

// components/EmptyState.jsx
export function EmptyState({ icon, title, description }) {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-center">
      <div className="text-5xl mb-4">{icon}</div>
      <p className="text-lg font-semibold text-gray-300">{title}</p>
      <p className="text-sm text-gray-500 mt-2 max-w-sm">{description}</p>
    </div>
  );
}
