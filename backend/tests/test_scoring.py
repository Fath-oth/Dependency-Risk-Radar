"""
tests/test_scoring.py
Unit tests for the multicriteria scoring engine.
"""
import pytest
from datetime import datetime, timezone, timedelta

from app.core.models import Component, CVE, License, Tracker, DependencyScope, RiskLevel
from app.scoring.engine import (
    _score_cve,
    _score_obsolescence,
    _score_licence,
    _score_trackers,
    score_all,
    compute_project_summary,
)


# ─────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────

def _make_component(**kwargs) -> Component:
    defaults = dict(
        purl="pkg:maven/com.example/lib@1.0.0",
        name="com.example:lib",
        group="com.example",
        artifact="lib",
        version="1.0.0",
        scope=DependencyScope.IMPLEMENTATION,
        is_direct=True,
        depth=0,
    )
    defaults.update(kwargs)
    return Component(**defaults)


def _make_cve(cvss: float, has_fix: bool = True, exploit: bool = False) -> CVE:
    return CVE(
        id="CVE-2024-1234",
        summary="Test vulnerability",
        cvss_v3=cvss,
        has_fix=has_fix,
        exploit_available=exploit,
    )


def _make_license(spdx_id: str) -> License:
    from app.ingestion.enricher import _build_license
    return _build_license(spdx_id)


def _ts_days_ago(days: int) -> float:
    return (datetime.now(timezone.utc) - timedelta(days=days)).timestamp()


# ─────────────────────────────────────────────
# CVE scoring
# ─────────────────────────────────────────────

class TestCVEScoring:
    def test_no_vulnerabilities_returns_zero(self):
        comp = _make_component()
        assert _score_cve(comp) == 0.0

    def test_critical_cvss_normalises_to_high_score(self):
        comp = _make_component(vulnerabilities=[_make_cve(cvss=9.8)])
        score = _score_cve(comp)
        assert score >= 90.0, f"Expected ≥90, got {score}"

    def test_medium_cvss_produces_medium_score(self):
        comp = _make_component(vulnerabilities=[_make_cve(cvss=5.0)])
        score = _score_cve(comp)
        assert 40.0 <= score <= 70.0, f"Expected 40-70, got {score}"

    def test_no_fix_adds_penalty(self):
        comp_fix    = _make_component(vulnerabilities=[_make_cve(cvss=7.0, has_fix=True)])
        comp_nofix  = _make_component(vulnerabilities=[_make_cve(cvss=7.0, has_fix=False)])
        assert _score_cve(comp_nofix) > _score_cve(comp_fix)

    def test_multiple_cves_add_count_penalty(self):
        single = _make_component(vulnerabilities=[_make_cve(cvss=7.0)])
        multi  = _make_component(vulnerabilities=[_make_cve(cvss=7.0)] * 5)
        assert _score_cve(multi) > _score_cve(single)

    def test_exploit_available_adds_penalty(self):
        comp_no_exploit  = _make_component(vulnerabilities=[_make_cve(cvss=8.0, exploit=False)])
        comp_exploit     = _make_component(vulnerabilities=[_make_cve(cvss=8.0, exploit=True)])
        assert _score_cve(comp_exploit) > _score_cve(comp_no_exploit)

    def test_score_never_exceeds_100(self):
        many_critical = [_make_cve(cvss=10.0, has_fix=False, exploit=True)] * 20
        comp = _make_component(vulnerabilities=many_critical)
        assert _score_cve(comp) <= 100.0

    def test_low_cvss_gives_low_score(self):
        comp = _make_component(vulnerabilities=[_make_cve(cvss=2.0)])
        score = _score_cve(comp)
        assert score < 40.0, f"Expected <40, got {score}"


# ─────────────────────────────────────────────
# Obsolescence scoring
# ─────────────────────────────────────────────

class TestObsolescenceScoring:
    def test_current_version_and_recent_release_scores_low(self):
        comp = _make_component(
            version="2.0.0",
            latest_version="2.0.0",
            last_release_ts=_ts_days_ago(30),
        )
        assert _score_obsolescence(comp) < 15.0

    def test_major_version_behind_scores_high(self):
        comp = _make_component(
            version="1.0.0",
            latest_version="3.0.0",
            last_release_ts=_ts_days_ago(60),
        )
        score = _score_obsolescence(comp)
        assert score >= 50.0, f"Expected ≥50 for major lag, got {score}"

    def test_minor_version_behind_scores_moderate(self):
        comp = _make_component(
            version="2.1.0",
            latest_version="2.5.0",
            last_release_ts=_ts_days_ago(90),
        )
        score = _score_obsolescence(comp)
        assert 20.0 <= score < 50.0, f"Expected 20-50 for minor lag, got {score}"

    def test_patch_behind_scores_low(self):
        comp = _make_component(
            version="2.0.0",
            latest_version="2.0.3",
            last_release_ts=_ts_days_ago(30),
        )
        score = _score_obsolescence(comp)
        assert score < 25.0, f"Expected <25 for patch lag, got {score}"

    def test_very_old_release_adds_significant_penalty(self):
        comp = _make_component(
            version="1.0.0",
            latest_version="1.0.0",
            last_release_ts=_ts_days_ago(900),  # 2.5 years
        )
        score = _score_obsolescence(comp)
        assert score >= 40.0, f"Expected ≥40 for old release, got {score}"

    def test_score_never_exceeds_100(self):
        comp = _make_component(
            version="0.1.0",
            latest_version="10.0.0",
            last_release_ts=_ts_days_ago(2000),
        )
        assert _score_obsolescence(comp) <= 100.0

    def test_no_version_info_returns_zero(self):
        comp = _make_component()
        assert _score_obsolescence(comp) == 0.0


# ─────────────────────────────────────────────
# Licence scoring
# ─────────────────────────────────────────────

class TestLicenceScoring:
    def test_mit_scores_zero(self):
        comp = _make_component(license=_make_license("MIT"))
        assert _score_licence(comp) == 0.0

    def test_apache_scores_zero(self):
        comp = _make_component(license=_make_license("Apache-2.0"))
        assert _score_licence(comp) == 0.0

    def test_gpl_scores_high(self):
        comp = _make_component(license=_make_license("GPL-3.0"))
        assert _score_licence(comp) >= 70.0

    def test_agpl_scores_very_high(self):
        comp = _make_component(license=_make_license("AGPL-3.0"))
        assert _score_licence(comp) >= 85.0

    def test_lgpl_scores_moderate(self):
        comp = _make_component(license=_make_license("LGPL-2.1"))
        score = _score_licence(comp)
        assert 25.0 <= score <= 50.0

    def test_unknown_license_scores_moderate_high(self):
        comp = _make_component()  # no license
        score = _score_licence(comp)
        assert 50.0 <= score <= 75.0


# ─────────────────────────────────────────────
# Tracker scoring
# ─────────────────────────────────────────────

class TestTrackerScoring:
    def test_no_trackers_scores_zero(self):
        comp = _make_component()
        assert _score_trackers(comp) == 0.0

    def test_high_risk_tracker_scores_significant(self):
        tracker = Tracker(
            name="FingerPrinter SDK",
            categories=["Fingerprinting"],
            website="",
            code_signature="com.fingerprinter",
            risk_weight=1.0,
        )
        comp = _make_component(trackers=[tracker])
        assert _score_trackers(comp) >= 15.0

    def test_multiple_trackers_accumulate(self):
        trackers = [
            Tracker("Tracker1", ["Analytics"],     "", "com.t1", risk_weight=0.6),
            Tracker("Tracker2", ["Advertising"],   "", "com.t2", risk_weight=0.8),
            Tracker("Tracker3", ["Fingerprinting"],"", "com.t3", risk_weight=1.0),
        ]
        comp = _make_component(trackers=trackers)
        single = _make_component(trackers=[trackers[0]])
        assert _score_trackers(comp) > _score_trackers(single)

    def test_tracker_score_capped_at_100(self):
        trackers = [
            Tracker(f"T{i}", ["Fingerprinting"], "", f"com.t{i}", risk_weight=1.0)
            for i in range(20)
        ]
        comp = _make_component(trackers=trackers)
        assert _score_trackers(comp) <= 100.0


# ─────────────────────────────────────────────
# Global score and risk level
# ─────────────────────────────────────────────

class TestGlobalScore:
    def test_clean_component_scores_low(self):
        comp = _make_component(license=_make_license("MIT"))
        comps = score_all([comp])
        assert comps[0].scores.global_score < 20.0

    def test_critically_vulnerable_component(self):
        comp = _make_component(
            version="1.0.0",
            latest_version="3.0.0",
            last_release_ts=_ts_days_ago(800),
            license=_make_license("GPL-3.0"),
            vulnerabilities=[_make_cve(cvss=9.8, has_fix=False)],
        )
        comps = score_all([comp])
        assert comps[0].scores.global_score >= 70.0
        assert comps[0].scores.risk_level in (RiskLevel.CRITICAL, RiskLevel.BLOCKING)

    def test_risk_level_matches_score(self):
        for score, expected_level in [
            (10.0, RiskLevel.LOW),
            (30.0, RiskLevel.MODERATE),
            (60.0, RiskLevel.HIGH),
            (80.0, RiskLevel.CRITICAL),
            (95.0, RiskLevel.BLOCKING),
        ]:
            assert RiskLevel.from_score(score) == expected_level

    def test_weights_sum_to_one(self):
        """Validate that scoring weights sum to 1.0."""
        from app.core.config import get_settings
        s = get_settings()
        total = s.WEIGHT_CVE + s.WEIGHT_OBSOLESCENCE + s.WEIGHT_LICENCE + s.WEIGHT_TRACKER
        assert abs(total - 1.0) < 1e-9, f"Weights sum to {total}, expected 1.0"


# ─────────────────────────────────────────────
# Project summary
# ─────────────────────────────────────────────

class TestProjectSummary:
    def test_empty_components(self):
        summary = compute_project_summary([])
        assert summary == {}

    def test_summary_counts_correctly(self):
        comps = [
            _make_component(purl=f"pkg:maven/com.example/lib{i}@1.0",
                            name=f"com.example:lib{i}",
                            artifact=f"lib{i}",
                            vulnerabilities=[_make_cve(cvss=9.0)] if i < 2 else [])
            for i in range(5)
        ]
        comps = score_all(comps)
        summary = compute_project_summary(comps)

        assert summary["total_components"] == 5
        assert summary["vulnerable_components"] == 2
        assert "avg_global_score" in summary
        assert "max_global_score" in summary
