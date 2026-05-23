"""
graph/dependency_graph.py
Builds and analyses the directed dependency graph using networkx.
Propagates transitive risk scores and identifies critical risk paths.
"""
from __future__ import annotations

import math
import logging
from typing import Optional

import networkx as nx

from app.core.models import Component

logger = logging.getLogger(__name__)


class DependencyGraph:
    def __init__(self):
        self.G: nx.DiGraph = nx.DiGraph()

    # ─────────────────────────────────────────
    # Build
    # ─────────────────────────────────────────

    def build(self, components: list[Component]) -> None:
        """Populate graph from a list of enriched, scored components."""
        self.G.clear()

        # Add all nodes first
        for comp in components:
            self.G.add_node(
                comp.purl,
                name=comp.name,
                version=comp.version,
                is_direct=comp.is_direct,
                depth=comp.depth,
                global_score=comp.scores.global_score,
                cve_score=comp.scores.cve_score,
                risk_level=comp.scores.risk_level.value,
                cve_count=comp.cve_count,
                license_spdx=comp.license.spdx_id if comp.license else "UNKNOWN",
                tracker_count=len(comp.trackers),
            )

        # Add edges: parent → child (parent depends on child)
        for comp in components:
            for child_purl in comp.dependencies:
                if self.G.has_node(child_purl):
                    self.G.add_edge(comp.purl, child_purl)

        logger.info(
            "Graph built: %d nodes, %d edges",
            self.G.number_of_nodes(),
            self.G.number_of_edges(),
        )

    # ─────────────────────────────────────────
    # Transitive risk propagation
    # ─────────────────────────────────────────

    def propagate_transitive_risk(self, components: list[Component]) -> list[Component]:
        """
        For each component, compute the weighted transitive risk from its descendants.
        Risk decays exponentially with depth (factor 0.8 per level).
        Updates comp.transitive_risk_score in-place.
        """
        comp_map = {c.purl: c for c in components}

        for comp in components:
            max_weighted = 0.0
            try:
                for desc_purl in nx.descendants(self.G, comp.purl):
                    try:
                        depth = nx.shortest_path_length(self.G, comp.purl, desc_purl)
                    except nx.NetworkXNoPath:
                        continue
                    desc_score = self.G.nodes[desc_purl].get("global_score", 0.0)
                    # Exponential decay: risk at depth d = score * 0.8^(d-1)
                    weighted = desc_score * (0.8 ** max(depth - 1, 0))
                    max_weighted = max(max_weighted, weighted)
            except nx.exception.NetworkXError:
                pass

            comp.transitive_risk_score = round(max_weighted, 1)

        return components

    # ─────────────────────────────────────────
    # High-impact nodes (many dependents)
    # ─────────────────────────────────────────

    def get_high_impact_nodes(self, top_n: int = 10) -> list[dict]:
        """
        Return the top-N components that are depended upon by the most others.
        Updating these would have the highest blast radius.
        """
        in_degree = dict(self.G.in_degree())
        sorted_nodes = sorted(in_degree.items(), key=lambda x: x[1], reverse=True)
        result = []
        for purl, count in sorted_nodes[:top_n]:
            if count == 0:
                continue
            attrs = dict(self.G.nodes[purl])
            result.append({
                "purl": purl,
                "dependents_count": count,
                **attrs,
            })
        return result

    # ─────────────────────────────────────────
    # Critical risk paths
    # ─────────────────────────────────────────

    def find_risk_paths(self, vuln_purl: str) -> list[list[str]]:
        """
        Find all shortest paths from direct dependencies to a vulnerable node.
        Returns paths sorted by length (shortest first — easiest to remediate).
        """
        direct_nodes = [
            n for n, d in self.G.nodes(data=True) if d.get("is_direct")
        ]
        paths: list[list[str]] = []
        for direct in direct_nodes:
            try:
                path = nx.shortest_path(self.G, source=direct, target=vuln_purl)
                paths.append(path)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
        return sorted(paths, key=len)

    # ─────────────────────────────────────────
    # Cycles (should not exist in a valid dep graph)
    # ─────────────────────────────────────────

    def detect_cycles(self) -> list[list[str]]:
        try:
            cycles = list(nx.simple_cycles(self.G))
            if cycles:
                logger.warning("Detected %d dependency cycle(s)!", len(cycles))
            return cycles
        except Exception:
            return []

    # ─────────────────────────────────────────
    # Export for frontend
    # ─────────────────────────────────────────

    def to_json(self) -> dict:
        """
        Serialize the graph to a JSON-compatible dict suitable for D3.js force layout.
        """
        nodes = []
        for purl, attrs in self.G.nodes(data=True):
            nodes.append({
                "id": purl,
                **attrs,
            })

        edges = []
        for src, dst in self.G.edges():
            edges.append({"source": src, "target": dst})

        return {"nodes": nodes, "edges": edges}

    # ─────────────────────────────────────────
    # Subgraph around a single node
    # ─────────────────────────────────────────

    def ego_graph(self, purl: str, radius: int = 2) -> dict:
        """Return the neighbourhood subgraph of radius hops around a node."""
        try:
            sub = nx.ego_graph(self.G, purl, radius=radius)
            nodes = [{"id": n, **dict(sub.nodes[n])} for n in sub.nodes()]
            edges = [{"source": s, "target": t} for s, t in sub.edges()]
            return {"nodes": nodes, "edges": edges}
        except nx.NodeNotFound:
            return {"nodes": [], "edges": []}

    # ─────────────────────────────────────────
    # Statistics
    # ─────────────────────────────────────────

    def stats(self) -> dict:
        return {
            "nodes": self.G.number_of_nodes(),
            "edges": self.G.number_of_edges(),
            "is_dag": nx.is_directed_acyclic_graph(self.G),
            "cycles": len(self.detect_cycles()),
            "connected_components": nx.number_weakly_connected_components(self.G),
            "max_depth": max(
                (d.get("depth", 0) for _, d in self.G.nodes(data=True)), default=0
            ),
        }
