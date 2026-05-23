"""
tests/test_graph.py
Unit tests for the dependency graph module.
"""
import pytest
from app.core.models import Component, DependencyScope, RiskScores
from app.graph.dependency_graph import DependencyGraph


def _comp(artifact: str, score: float = 0.0, is_direct: bool = True, depth: int = 0, deps: list = None) -> Component:
    c = Component(
        purl=f"pkg:maven/com.example/{artifact}@1.0.0",
        name=f"com.example:{artifact}",
        group="com.example",
        artifact=artifact,
        version="1.0.0",
        scope=DependencyScope.IMPLEMENTATION,
        is_direct=is_direct,
        depth=depth,
    )
    c.scores = RiskScores(cve_score=score, obsolescence_score=0, licence_score=0, tracker_score=0)
    if deps:
        c.dependencies = [f"pkg:maven/com.example/{d}@1.0.0" for d in deps]
    return c


def _build_graph(*components) -> DependencyGraph:
    g = DependencyGraph()
    g.build(list(components))
    return g


class TestGraphBuild:
    def test_builds_nodes(self):
        g = _build_graph(_comp("retrofit"), _comp("okhttp", is_direct=False, depth=1))
        assert g.G.number_of_nodes() == 2

    def test_builds_edges(self):
        retrofit = _comp("retrofit", deps=["okhttp"])
        okhttp   = _comp("okhttp", is_direct=False, depth=1)
        g = _build_graph(retrofit, okhttp)
        assert g.G.number_of_edges() == 1

    def test_empty_graph(self):
        g = _build_graph()
        assert g.G.number_of_nodes() == 0
        assert g.G.number_of_edges() == 0

    def test_node_attributes_stored(self):
        c = _comp("lib", score=75.0, is_direct=True)
        g = _build_graph(c)
        attrs = g.G.nodes[c.purl]
        assert attrs["global_score"] == 75.0
        assert attrs["is_direct"]    is True


class TestTransitiveRisk:
    def test_no_descendants_zero_transitive(self):
        c = _comp("standalone", score=50.0)
        g = _build_graph(c)
        result = g.propagate_transitive_risk([c])
        assert result[0].transitive_risk_score == 0.0

    def test_transitive_risk_propagates_up(self):
        parent = _comp("parent", score=5.0,  deps=["child"])
        child  = _comp("child",  score=80.0, is_direct=False, depth=1)
        g = _build_graph(parent, child)
        result = g.propagate_transitive_risk([parent, child])
        parent_result = next(c for c in result if c.artifact == "parent")
        assert parent_result.transitive_risk_score > 0.0

    def test_transitive_risk_decays_with_depth(self):
        a = _comp("A", score=5.0,  deps=["B"])
        b = _comp("B", score=5.0,  is_direct=False, depth=1, deps=["C"])
        c = _comp("C", score=80.0, is_direct=False, depth=2)
        g = _build_graph(a, b, c)
        result = g.propagate_transitive_risk([a, b, c])
        a_score = next(x for x in result if x.artifact == "A").transitive_risk_score
        b_score = next(x for x in result if x.artifact == "B").transitive_risk_score
        # B is closer to C, so its transitive score should be higher (less decay)
        assert b_score >= a_score


class TestHighImpact:
    def test_most_depended_on_first(self):
        shared = _comp("shared-lib", is_direct=False, depth=1)
        a = _comp("A", deps=["shared-lib"])
        b = _comp("B", deps=["shared-lib"])
        c = _comp("C")
        g = _build_graph(shared, a, b, c)
        high_impact = g.get_high_impact_nodes(top_n=5)
        if high_impact:
            assert high_impact[0]["purl"] == shared.purl

    def test_isolated_nodes_excluded(self):
        a = _comp("A")
        b = _comp("B")
        g = _build_graph(a, b)
        result = g.get_high_impact_nodes()
        assert len(result) == 0   # no edges → no dependents


class TestRiskPaths:
    def test_finds_path_to_vulnerable_node(self):
        direct  = _comp("direct",       is_direct=True,  deps=["middle"])
        middle  = _comp("middle",       is_direct=False, depth=1, deps=["vuln"])
        vuln    = _comp("vuln-lib",     is_direct=False, depth=2, score=90.0)
        g = _build_graph(direct, middle, vuln)
        paths = g.find_risk_paths(vuln.purl)
        assert len(paths) >= 1
        assert paths[0][0]  == direct.purl
        assert paths[0][-1] == vuln.purl

    def test_no_path_returns_empty(self):
        a = _comp("A")
        b = _comp("B")
        g = _build_graph(a, b)
        paths = g.find_risk_paths(b.purl)
        assert paths == []


class TestGraphStats:
    def test_stats_returns_expected_keys(self):
        g = _build_graph(_comp("A", deps=["B"]), _comp("B", is_direct=False, depth=1))
        stats = g.stats()
        for key in ("nodes", "edges", "is_dag", "cycles", "max_depth"):
            assert key in stats

    def test_dag_detection(self):
        g = _build_graph(_comp("A", deps=["B"]), _comp("B", is_direct=False, depth=1))
        assert g.stats()["is_dag"] is True

    def test_to_json_structure(self):
        g = _build_graph(_comp("A", deps=["B"]), _comp("B", is_direct=False, depth=1))
        data = g.to_json()
        assert "nodes" in data
        assert "edges" in data
        assert isinstance(data["nodes"], list)
        assert isinstance(data["edges"], list)

    def test_ego_graph_returns_neighbours(self):
        a = _comp("A", deps=["B"])
        b = _comp("B", is_direct=False, depth=1, deps=["C"])
        c = _comp("C", is_direct=False, depth=2)
        g = _build_graph(a, b, c)
        ego = g.ego_graph(a.purl, radius=1)
        node_ids = {n["id"] for n in ego["nodes"]}
        assert a.purl in node_ids
        assert b.purl in node_ids

    def test_ego_graph_unknown_purl(self):
        g = _build_graph(_comp("A"))
        result = g.ego_graph("pkg:maven/unknown/lib@0.0.0", radius=1)
        assert result == {"nodes": [], "edges": []}
