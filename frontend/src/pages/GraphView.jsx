// pages/GraphView.jsx
import { useEffect, useRef, useState } from 'react';
import { useParams } from 'react-router-dom';
import * as d3 from 'd3';
import { useStore } from '../stores/useStore';
import { Spinner, EmptyState } from '../components/shared';

const RISK_COLOR = (score) =>
  score >= 75 ? '#ef4444' :
  score >= 50 ? '#f97316' :
  score >= 20 ? '#eab308' :
  '#22c55e';

export default function GraphView() {
  const { reportId } = useParams();
  const { activeReport, graphData, fetchReport, fetchGraph } = useStore();
  const svgRef = useRef(null);
  const [tooltip, setTooltip] = useState(null);
  const [stats, setStats] = useState(null);

  useEffect(() => {
    if (reportId) {
      if (!activeReport) fetchReport(reportId);
      fetchGraph(reportId);   // always re-fetch — clears stale data in store
    }
  }, [reportId]);

  useEffect(() => {
    if (!graphData || !svgRef.current) return;
    renderGraph(graphData);
  }, [graphData]);

  function renderGraph(data) {
    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const container = svgRef.current.parentElement;
    const W = container.clientWidth;
    const H = container.clientHeight;

    svg.attr('width', W).attr('height', H);

    const g = svg.append('g');

    // Zoom & pan
    svg.call(
      d3.zoom()
        .scaleExtent([0.1, 4])
        .on('zoom', (event) => g.attr('transform', event.transform))
    );

    const nodes = data.nodes.map(d => ({ ...d }));
    const edges = data.edges.map(d => ({ ...d }));
    const nodeMap = Object.fromEntries(nodes.map(n => [n.id, n]));

    const edgesResolved = edges.map(e => ({
      source: nodeMap[e.source] || e.source,
      target: nodeMap[e.target] || e.target,
    }));

    setStats({ nodes: nodes.length, edges: edges.length });

    const sim = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(edgesResolved).id(d => d.id).distance(80).strength(0.4))
      .force('charge', d3.forceManyBody().strength(-120))
      .force('center', d3.forceCenter(W / 2, H / 2))
      .force('collision', d3.forceCollide(16));

    // Arrows
    svg.append('defs').append('marker')
      .attr('id', 'arrow')
      .attr('viewBox', '0 -4 8 8')
      .attr('refX', 18)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-4L8,0L0,4')
      .attr('fill', '#4b5563');

    const link = g.append('g')
      .selectAll('line')
      .data(edgesResolved)
      .join('line')
      .attr('stroke', '#374151')
      .attr('stroke-width', 1)
      .attr('marker-end', 'url(#arrow)');

    const nodeG = g.append('g')
      .selectAll('g')
      .data(nodes)
      .join('g')
      .attr('cursor', 'pointer')
      .call(
        d3.drag()
          .on('start', (event, d) => {
            if (!event.active) sim.alphaTarget(0.3).restart();
            d.fx = d.x; d.fy = d.y;
          })
          .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y; })
          .on('end', (event, d) => {
            if (!event.active) sim.alphaTarget(0);
            d.fx = null; d.fy = null;
          })
      )
      .on('mouseenter', (event, d) => {
        setTooltip({ x: event.clientX, y: event.clientY, node: d });
      })
      .on('mouseleave', () => setTooltip(null));

    // Node circles
    nodeG.append('circle')
      .attr('r', d => d.is_direct ? 10 : 6)
      .attr('fill', d => RISK_COLOR(d.global_score || 0))
      .attr('stroke', d => d.is_direct ? '#fff' : 'none')
      .attr('stroke-width', 1.5)
      .attr('fill-opacity', 0.85);

    // Labels for direct deps only
    nodeG.filter(d => d.is_direct)
      .append('text')
      .attr('dy', '0.35em')
      .attr('x', 13)
      .attr('font-size', '9px')
      .attr('fill', '#d1d5db')
      .text(d => d.name?.split(':')[1] || d.id.split('@')[0].split('/').pop());

    sim.on('tick', () => {
      link
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y);
      nodeG.attr('transform', d => `translate(${d.x},${d.y})`);
    });
  }

  if (!graphData) return <div className="flex items-center justify-center h-full"><Spinner size={10} /></div>;

  const hasEdges = graphData.edges && graphData.edges.length > 0;

  return (
    <div className="relative w-full h-full bg-gray-950">
      {/* No-edges warning */}
      {graphData.nodes.length > 0 && !hasEdges && (
        <div className="absolute top-4 left-1/2 -translate-x-1/2 z-20 bg-amber-900/90 border border-amber-600 rounded-xl px-4 py-2 text-amber-200 text-xs text-center max-w-sm">
          ⚠️ Dependencies detected but no graph edges — transitive relationships could not be resolved for this project.
        </div>
      )}
      {/* Legend */}
      <div className="absolute top-4 left-4 z-10 bg-gray-900/90 border border-gray-700 rounded-xl p-3 text-xs space-y-1.5">
        <p className="text-gray-400 font-semibold mb-2">Risk Score</p>
        {[
          { label: '≥ 75 Critical', color: '#ef4444' },
          { label: '50–74 High',    color: '#f97316' },
          { label: '20–49 Moderate',color: '#eab308' },
          { label: '< 20 Low',      color: '#22c55e' },
        ].map(l => (
          <div key={l.label} className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full" style={{ background: l.color }} />
            <span className="text-gray-300">{l.label}</span>
          </div>
        ))}
        <div className="border-t border-gray-700 pt-1.5 mt-1.5 space-y-1">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-gray-400 border border-white" />
            <span className="text-gray-300">Direct dependency</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-gray-400" />
            <span className="text-gray-300">Transitive</span>
          </div>
        </div>
      </div>

      {/* Stats */}
      {stats && (
        <div className="absolute top-4 right-4 z-10 bg-gray-900/90 border border-gray-700 rounded-xl p-3 text-xs text-gray-400">
          <span className="text-white font-medium">{stats.nodes}</span> nodes ·{' '}
          <span className="text-white font-medium">{stats.edges}</span> edges
        </div>
      )}

      <svg ref={svgRef} className="w-full h-full" />

      {/* Tooltip */}
      {tooltip && (
        <div
          className="fixed z-50 bg-gray-900 border border-gray-600 rounded-lg p-3 text-xs pointer-events-none shadow-xl"
          style={{ left: tooltip.x + 12, top: tooltip.y - 8 }}
        >
          <p className="font-semibold text-white mb-1">{tooltip.node.name}</p>
          <p className="text-gray-400">v{tooltip.node.version}</p>
          <p className="text-gray-400">Risk: <span className="font-bold" style={{ color: RISK_COLOR(tooltip.node.global_score) }}>{tooltip.node.global_score}/100</span></p>
          <p className="text-gray-400">{tooltip.node.cve_count} CVEs · {tooltip.node.is_direct ? 'Direct' : `Transitive (depth ${tooltip.node.depth})`}</p>
          {tooltip.node.license_spdx && <p className="text-gray-400">Licence: {tooltip.node.license_spdx}</p>}
        </div>
      )}
    </div>
  );
}
