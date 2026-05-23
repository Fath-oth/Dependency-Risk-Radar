// pages/Explorer.jsx
import { useEffect, useState, useMemo } from 'react';
import { useParams } from 'react-router-dom';
import { useStore } from '../stores/useStore';
import { RiskBadge, ScoreBar, Spinner, EmptyState } from '../components/shared';
import { Search, Filter, ChevronDown, ChevronUp, X, ExternalLink } from 'lucide-react';

const COLUMNS = [
  { key: 'name',           label: 'Component',    sortable: true  },
  { key: 'version',        label: 'Version',      sortable: false },
  { key: 'scope',          label: 'Scope',        sortable: false },
  { key: 'global',         label: 'Risk Score',   sortable: true  },
  { key: 'cve',            label: 'CVEs',         sortable: true  },
  { key: 'licence',        label: 'Licence',      sortable: false },
  { key: 'trackers',       label: 'Trackers',     sortable: false },
  { key: 'risk_level',     label: 'Level',        sortable: false },
];

export default function Explorer() {
  const { reportId } = useParams();
  const { activeReport, activeReportLoading, fetchReport, setSelectedComponent } = useStore();
  const [search, setSearch] = useState('');
  const [sortKey, setSortKey] = useState('global');
  const [sortAsc, setSortAsc] = useState(false);
  const [filterDirect, setFilterDirect] = useState('all');  // all | direct | transitive
  const [filterLevel, setFilterLevel] = useState('all');
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    if (reportId && !activeReport) fetchReport(reportId);
  }, [reportId]);

  const components = useMemo(() => {
    if (!activeReport) return [];
    let list = activeReport.components || [];

    if (search) {
      const q = search.toLowerCase();
      list = list.filter(c => c.name.toLowerCase().includes(q) || c.purl.toLowerCase().includes(q));
    }
    if (filterDirect !== 'all') {
      list = list.filter(c => filterDirect === 'direct' ? c.is_direct : !c.is_direct);
    }
    if (filterLevel !== 'all') {
      list = list.filter(c => c.scores.risk_level === filterLevel);
    }

    list = [...list].sort((a, b) => {
      let va, vb;
      if (sortKey === 'global')  { va = a.scores.global; vb = b.scores.global; }
      else if (sortKey === 'cve') { va = a.vulnerabilities.length; vb = b.vulnerabilities.length; }
      else if (sortKey === 'name') { va = a.name; vb = b.name; }
      else return 0;
      if (va < vb) return sortAsc ? -1 : 1;
      if (va > vb) return sortAsc ? 1 : -1;
      return 0;
    });
    return list;
  }, [activeReport, search, sortKey, sortAsc, filterDirect, filterLevel]);

  const handleSort = (key) => {
    if (sortKey === key) setSortAsc(!sortAsc);
    else { setSortKey(key); setSortAsc(false); }
  };

  if (activeReportLoading) return <div className="flex items-center justify-center h-full"><Spinner size={10} /></div>;
  if (!activeReport) return <EmptyState icon="🔍" title="No report loaded" description="Run an analysis first." />;

  return (
    <div className="flex h-full overflow-hidden">
      {/* Main table */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Toolbar */}
        <div className="p-4 border-b border-gray-700 flex flex-wrap gap-3 items-center">
          <div className="relative flex-1 min-w-48">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
            <input
              className="w-full bg-gray-800 border border-gray-600 rounded-lg pl-9 pr-3 py-1.5 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
              placeholder="Search components…"
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>
          <select
            className="bg-gray-800 border border-gray-600 rounded-lg px-3 py-1.5 text-sm text-gray-300"
            value={filterDirect}
            onChange={e => setFilterDirect(e.target.value)}
          >
            <option value="all">All types</option>
            <option value="direct">Direct only</option>
            <option value="transitive">Transitive only</option>
          </select>
          <select
            className="bg-gray-800 border border-gray-600 rounded-lg px-3 py-1.5 text-sm text-gray-300"
            value={filterLevel}
            onChange={e => setFilterLevel(e.target.value)}
          >
            <option value="all">All levels</option>
            <option value="BLOCKING">Blocking</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MODERATE">Moderate</option>
            <option value="LOW">Low</option>
          </select>
          <span className="text-xs text-gray-400">{components.length} components</span>
        </div>

        {/* Table */}
        <div className="flex-1 overflow-auto">
          <table className="w-full text-sm border-collapse">
            <thead className="sticky top-0 bg-gray-900 z-10">
              <tr>
                {COLUMNS.map(col => (
                  <th
                    key={col.key}
                    className={`px-3 py-2 text-left text-xs font-semibold text-gray-400 border-b border-gray-700 whitespace-nowrap ${col.sortable ? 'cursor-pointer hover:text-white' : ''}`}
                    onClick={() => col.sortable && handleSort(col.key)}
                  >
                    <span className="flex items-center gap-1">
                      {col.label}
                      {col.sortable && sortKey === col.key && (
                        sortAsc ? <ChevronUp size={12} /> : <ChevronDown size={12} />
                      )}
                    </span>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {components.map(comp => (
                <tr
                  key={comp.purl}
                  className={`border-b border-gray-800 hover:bg-gray-800 cursor-pointer transition ${selected?.purl === comp.purl ? 'bg-gray-800' : ''}`}
                  onClick={() => setSelected(comp)}
                >
                  <td className="px-3 py-2">
                    <div>
                      <span className="font-medium text-white">{comp.artifact}</span>
                      {!comp.is_direct && (
                        <span className="ml-2 text-xs text-gray-500">transitive</span>
                      )}
                    </div>
                    <div className="text-xs text-gray-500 truncate max-w-48">{comp.group}</div>
                  </td>
                  <td className="px-3 py-2 text-gray-300 font-mono text-xs">{comp.version}</td>
                  <td className="px-3 py-2 text-gray-400 text-xs">{comp.scope}</td>
                  <td className="px-3 py-2 w-32">
                    <ScoreBar score={comp.scores.global} />
                  </td>
                  <td className="px-3 py-2 text-center">
                    {comp.vulnerabilities.length > 0 ? (
                      <span className="text-red-400 font-semibold">{comp.vulnerabilities.length}</span>
                    ) : (
                      <span className="text-gray-600">—</span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    {comp.license ? (
                      <span className={`text-xs ${comp.license.is_copyleft ? 'text-yellow-400' : 'text-gray-300'}`}>
                        {comp.license.spdx_id}
                      </span>
                    ) : (
                      <span className="text-gray-600 text-xs">Unknown</span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-center">
                    {comp.trackers.length > 0 ? (
                      <span className="text-purple-400 text-xs">{comp.trackers.length}</span>
                    ) : (
                      <span className="text-gray-600">—</span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <RiskBadge level={comp.scores.risk_level} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detail panel */}
      {selected && (
        <ComponentDetail comp={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}

function ComponentDetail({ comp, onClose }) {
  const maxCvss = comp.vulnerabilities.reduce((m, v) => Math.max(m, v.cvss_v3 || 0), 0);

  return (
    <div className="w-80 border-l border-gray-700 bg-gray-900 flex flex-col overflow-hidden">
      <div className="flex items-center justify-between p-4 border-b border-gray-700">
        <h2 className="font-semibold text-white text-sm truncate">{comp.artifact}</h2>
        <button onClick={onClose} className="text-gray-400 hover:text-white"><X size={16} /></button>
      </div>
      <div className="flex-1 overflow-y-auto p-4 space-y-4 text-sm">
        <div>
          <p className="text-xs text-gray-400 mb-1">PURL</p>
          <p className="font-mono text-xs text-blue-300 break-all">{comp.purl}</p>
        </div>
        <div className="grid grid-cols-2 gap-2">
          <div className="bg-gray-800 rounded p-2">
            <p className="text-xs text-gray-400">Current</p>
            <p className="text-white font-mono">{comp.version}</p>
          </div>
          <div className="bg-gray-800 rounded p-2">
            <p className="text-xs text-gray-400">Latest</p>
            <p className={`font-mono ${comp.latest_version && comp.latest_version !== comp.version ? 'text-orange-400' : 'text-green-400'}`}>
              {comp.latest_version || '?'}
            </p>
          </div>
        </div>

        <div>
          <p className="text-xs text-gray-400 mb-1">Risk Scores</p>
          <div className="space-y-1.5">
            {[
              { label: 'CVE', value: comp.scores.cve },
              { label: 'Obsolescence', value: comp.scores.obsolescence },
              { label: 'Licence', value: comp.scores.licence },
              { label: 'Trackers', value: comp.scores.tracker },
            ].map(s => (
              <div key={s.label} className="flex items-center gap-2">
                <span className="text-xs text-gray-400 w-20">{s.label}</span>
                <ScoreBar score={s.value} className="flex-1" />
              </div>
            ))}
          </div>
        </div>

        {comp.vulnerabilities.length > 0 && (
          <div>
            <p className="text-xs text-gray-400 mb-2">Vulnerabilities ({comp.vulnerabilities.length})</p>
            <div className="space-y-2">
              {comp.vulnerabilities.map(v => (
                <div key={v.id} className="bg-gray-800 rounded p-2">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs text-red-300">{v.id}</span>
                    {v.cvss_v3 && <span className="text-xs font-bold text-red-400">{v.cvss_v3}</span>}
                  </div>
                  <p className="text-xs text-gray-400 mt-1 line-clamp-2">{v.summary}</p>
                  <p className={`text-xs mt-1 ${v.has_fix ? 'text-green-400' : 'text-red-400'}`}>
                    {v.has_fix ? '✓ Fix available' : '✗ No fix available'}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}

        {comp.trackers.length > 0 && (
          <div>
            <p className="text-xs text-gray-400 mb-2">Trackers</p>
            {comp.trackers.map(t => (
              <div key={t.name} className="bg-gray-800 rounded p-2 mb-1">
                <p className="text-xs font-medium text-purple-300">{t.name}</p>
                <p className="text-xs text-gray-400">{t.categories.join(', ')}</p>
              </div>
            ))}
          </div>
        )}

        {comp.direct_ancestor && (
          <div>
            <p className="text-xs text-gray-400 mb-1">Pulled in by</p>
            <p className="font-mono text-xs text-blue-300 break-all">{comp.direct_ancestor}</p>
          </div>
        )}
      </div>
    </div>
  );
}
