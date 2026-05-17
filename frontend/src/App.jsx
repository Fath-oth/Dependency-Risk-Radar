// App.jsx - Main app with sidebar navigation and routing
import { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, Link, useParams, useNavigate, useLocation } from 'react-router-dom';
import { useStore } from './stores/useStore';
import Dashboard from './pages/Dashboard';
import Explorer from './pages/Explorer';
import UpdatePlan from './pages/UpdatePlan';
import GraphView from './pages/GraphView';
import {
  LayoutDashboard, Search, GitBranch, Zap, Upload,
  FolderOpen, ChevronRight, ShieldAlert, Loader2, CheckCircle, XCircle,
  Menu, X
} from 'lucide-react';

const NAV = [
  { path: 'dashboard', label: 'Overview',    icon: LayoutDashboard },
  { path: 'explorer',  label: 'Components',  icon: Search },
  { path: 'graph',     label: 'Dep Graph',   icon: GitBranch },
  { path: 'plan',      label: 'Update Plan', icon: Zap },
];

function Sidebar({ reportId }) {
  const { reports, reportsLoading, fetchReports, activeJob, jobProgress, jobMessage, sidebarOpen, toggleSidebar } = useStore();
  const location = useLocation();

  useEffect(() => { fetchReports(); }, []);

  return (
    <aside className={`${sidebarOpen ? 'w-56' : 'w-14'} bg-gray-900 border-r border-gray-700 flex flex-col transition-all duration-200 flex-shrink-0`}>
      {/* Logo */}
      <div className="flex items-center gap-2 p-4 border-b border-gray-700">
        <ShieldAlert size={20} className="text-blue-400 flex-shrink-0" />
        {sidebarOpen && <span className="font-bold text-white text-sm">Risk Radar</span>}
        <button onClick={toggleSidebar} className="ml-auto text-gray-400 hover:text-white">
          {sidebarOpen ? <X size={14} /> : <Menu size={14} />}
        </button>
      </div>

      {/* Job progress */}
      {activeJob && (
        <div className="m-3 bg-blue-950/50 border border-blue-800 rounded-lg p-2">
          <div className="flex items-center gap-2">
            <Loader2 size={12} className="text-blue-400 animate-spin flex-shrink-0" />
            {sidebarOpen && <span className="text-xs text-blue-300 truncate">{jobMessage}</span>}
          </div>
          {sidebarOpen && (
            <div className="mt-1.5 h-1 bg-gray-700 rounded-full overflow-hidden">
              <div className="h-full bg-blue-500 transition-all" style={{ width: `${jobProgress}%` }} />
            </div>
          )}
        </div>
      )}

      {/* Nav items for active report */}
      {reportId && (
        <nav className="px-2 pt-3 space-y-0.5">
          {sidebarOpen && <p className="text-xs text-gray-500 px-2 pb-1 uppercase tracking-wide">Analysis</p>}
          {NAV.map(({ path, label, icon: Icon }) => {
            const to = `/report/${reportId}/${path}`;
            const active = location.pathname === to;
            return (
              <Link
                key={path}
                to={to}
                className={`flex items-center gap-2 px-2 py-2 rounded-lg text-sm transition ${
                  active ? 'bg-blue-600 text-white' : 'text-gray-300 hover:bg-gray-800 hover:text-white'
                }`}
              >
                <Icon size={15} className="flex-shrink-0" />
                {sidebarOpen && label}
              </Link>
            );
          })}
        </nav>
      )}

      {/* Reports list */}
      <div className="flex-1 overflow-y-auto px-2 pt-4">
        {sidebarOpen && <p className="text-xs text-gray-500 px-2 pb-1 uppercase tracking-wide">Recent Reports</p>}
        {reportsLoading && <div className="flex justify-center py-4"><Loader2 size={14} className="animate-spin text-gray-500" /></div>}
        {reports.map(r => {
          const isActive = r.report_id === reportId;
          const score = r.global_risk_score;
          const color = score >= 75 ? 'text-red-400' : score >= 50 ? 'text-orange-400' : score >= 20 ? 'text-yellow-400' : 'text-green-400';
          return (
            <Link
              key={r.report_id}
              to={`/report/${r.report_id}/dashboard`}
              className={`block rounded-lg p-2 mb-0.5 hover:bg-gray-800 transition ${isActive ? 'bg-gray-800' : ''}`}
              title={r.project_name}
            >
              {sidebarOpen ? (
                <>
                  <p className="text-xs font-medium text-white truncate">{r.project_name}</p>
                  <div className="flex justify-between items-center mt-0.5">
                    <p className="text-xs text-gray-500">{r.total_components} deps</p>
                    <span className={`text-xs font-bold ${color}`}>{score}</span>
                  </div>
                </>
              ) : (
                <div className={`w-3 h-3 rounded-full mx-auto ${score >= 75 ? 'bg-red-500' : score >= 50 ? 'bg-orange-400' : score >= 20 ? 'bg-yellow-400' : 'bg-green-500'}`} />
              )}
            </Link>
          );
        })}
      </div>
    </aside>
  );
}

function ReportLayout() {
  const { reportId } = useParams();
  return (
    <div className="flex h-full">
      <Sidebar reportId={reportId} />
      <main className="flex-1 overflow-hidden">
        <Routes>
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="explorer"  element={<Explorer />} />
          <Route path="graph"     element={<GraphView />} />
          <Route path="plan"      element={<UpdatePlan />} />
        </Routes>
      </main>
    </div>
  );
}

function Home() {
  const navigate = useNavigate();
  const { startApkAnalysis, startGradleAnalysis, activeJob, jobProgress, jobMessage } = useStore();
  const [tab, setTab] = useState('apk');
  const [gradlePath, setGradlePath] = useState('');
  const [dragOver, setDragOver] = useState(false);

  const handleApk = async (file) => {
    if (!file || !file.name.endsWith('.apk')) return;
    const jobId = await startApkAnalysis(file);
  };

  const handleGradle = async () => {
    if (!gradlePath.trim()) return;
    await startGradleAnalysis(gradlePath.trim());
  };

  return (
    <div className="flex h-full">
      <Sidebar reportId={null} />
      <main className="flex-1 flex items-center justify-center p-8">
        <div className="w-full max-w-lg space-y-6">
          <div className="text-center">
            <div className="flex justify-center mb-3">
              <div className="p-3 bg-blue-900/40 rounded-2xl">
                <ShieldAlert size={32} className="text-blue-400" />
              </div>
            </div>
            <h1 className="text-3xl font-bold text-white">Dependency Risk Radar</h1>
            <p className="text-gray-400 mt-2">SBOM · CVE Analysis · Licence Risk · AI Update Plan</p>
          </div>

          <div className="bg-gray-800 border border-gray-700 rounded-2xl p-6 space-y-4">
            {/* Tabs */}
            <div className="flex bg-gray-900 rounded-lg p-1 gap-1">
              {[{ key: 'apk', label: '📦 APK File' }, { key: 'gradle', label: '⚙️ Gradle Project' }].map(t => (
                <button
                  key={t.key}
                  onClick={() => setTab(t.key)}
                  className={`flex-1 py-1.5 rounded-md text-sm font-medium transition ${tab === t.key ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white'}`}
                >
                  {t.label}
                </button>
              ))}
            </div>

            {tab === 'apk' ? (
              <div
                className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition ${dragOver ? 'border-blue-400 bg-blue-950/20' : 'border-gray-600 hover:border-gray-500'}`}
                onDragOver={e => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={e => { e.preventDefault(); setDragOver(false); handleApk(e.dataTransfer.files[0]); }}
                onClick={() => document.getElementById('apk-input').click()}
              >
                <Upload size={32} className="mx-auto text-gray-400 mb-3" />
                <p className="text-gray-300 font-medium">Drop your APK here</p>
                <p className="text-gray-500 text-sm mt-1">or click to browse</p>
                <input id="apk-input" type="file" accept=".apk" className="hidden" onChange={e => handleApk(e.target.files[0])} />
              </div>
            ) : (
              <div className="space-y-3">
                <div className="relative">
                  <FolderOpen size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
                  <input
                    className="w-full bg-gray-900 border border-gray-600 rounded-lg pl-9 pr-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                    placeholder="/path/to/android/project"
                    value={gradlePath}
                    onChange={e => setGradlePath(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && handleGradle()}
                  />
                </div>
                <button
                  onClick={handleGradle}
                  disabled={!gradlePath.trim() || !!activeJob}
                  className="w-full bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:text-gray-500 text-white font-medium py-2 rounded-lg transition flex items-center justify-center gap-2"
                >
                  {activeJob ? <><Loader2 size={14} className="animate-spin" /> Analysing…</> : <>Analyse Project <ChevronRight size={14} /></>}
                </button>
              </div>
            )}

            {/* Progress */}
            {activeJob && (
              <div className="space-y-2">
                <div className="flex justify-between text-xs text-gray-400">
                  <span>{jobMessage}</span>
                  <span>{jobProgress}%</span>
                </div>
                <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
                  <div className="h-full bg-blue-500 transition-all" style={{ width: `${jobProgress}%` }} />
                </div>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <div className="h-screen bg-gray-950 text-white flex flex-col overflow-hidden">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/report/:reportId/*" element={<ReportLayout />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}
