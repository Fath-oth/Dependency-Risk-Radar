"""
scoring/engine.py
Multicriteria risk scoring engine.
Calculates CVE, obsolescence, licence, and tracker scores for each component,
then computes the weighted global score.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from packaging.version import Version, InvalidVersion

from app.core.config import get_settings
from app.core.models import Component, RiskScores

logger = logging.getLogger(__name__)
settings = get_settings()


def score_all(components: list[Component]) -> list[Component]:
    """Entry point: compute scores for every component in-place."""
    for comp in components:
        comp.scores = _score_component(comp)
    return components


def _score_component(comp: Component) -> RiskScores:
    return RiskScores(
        cve_score=_score_cve(comp),
        obsolescence_score=_score_obsolescence(comp),
        licence_score=_score_licence(comp),
        tracker_score=_score_trackers(comp),
    )


# ─────────────────────────────────────────────
# CVE Scoring (0–100)
# ─────────────────────────────────────────────

def _score_cve(comp: Component) -> float:
    vulns = comp.vulnerabilities
    if not vulns:
        return 0.0

    # Base: highest CVSS v3 score, normalised to 100
    max_cvss = max((v.cvss_v3 for v in vulns if v.cvss_v3 is not None), default=0.0)
    base = (max_cvss / 10.0) * 100.0

    # Penalty: unpatched vulnerabilities (+5 each, max +15)
    unfixed = sum(1 for v in vulns if not v.has_fix)
    fix_penalty = min(unfixed * 5, 15)

    # Penalty: total CVE count (+2 each, max +10)
    count_penalty = min(len(vulns) * 2, 10)

    # Bonus penalty: known exploit available (+10 flat)
    exploit_penalty = 10.0 if any(v.exploit_available for v in vulns) else 0.0

    return min(base + fix_penalty + count_penalty + exploit_penalty, 100.0)


# ─────────────────────────────────────────────
# Obsolescence Scoring (0–100)
# ─────────────────────────────────────────────

def _score_obsolescence(comp: Component) -> float:
    score = 0.0

    # ── Version gap component (up to 50 pts) ──
    if comp.version in ("unknown", "", None):
        # Can't assess version gap for APK-inferred components — use age only
        pass
    elif comp.latest_version and comp.latest_version != comp.version:
        try:
            cur = Version(comp.version)
            lat = Version(comp.latest_version)
            if cur >= lat:
                pass  # Already on latest or newer
            elif cur.major < lat.major:
                score += 50   # Major version behind = highest risk
            elif cur.minor < lat.minor:
                score += 25   # Minor version behind
            elif cur.micro < lat.micro:
                score += 10   # Patch behind
        except InvalidVersion:
            score += 15   # Non-standard version string

    # ── Age of last release component (up to 50 pts) ──
    if comp.last_release_ts:
        now_ts = datetime.now(timezone.utc).timestamp()
        days_since_release = (now_ts - comp.last_release_ts) / 86_400

        if days_since_release > 1460:   # 4+ years
            score += 50
        elif days_since_release > 730:  # 2–4 years
            score += 40
        elif days_since_release > 365:  # 1–2 years
            score += 25
        elif days_since_release > 180:  # 6–12 months
            score += 10
        # < 6 months: no penalty

    return min(score, 100.0)


# ─────────────────────────────────────────────
# Licence Scoring (0–100)
# ─────────────────────────────────────────────

def _score_licence(comp: Component) -> float:
    if comp.license is None:
        return 65.0   # Unknown licence = moderate-high risk
    return comp.license.risk_score


# ─────────────────────────────────────────────
# Tracker / Permission Scoring (0–100)
# ─────────────────────────────────────────────

_DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS":        15,
    "android.permission.WRITE_CONTACTS":       15,
    "android.permission.READ_CALL_LOG":        20,
    "android.permission.READ_SMS":             20,
    "android.permission.RECEIVE_SMS":          20,
    "android.permission.ACCESS_FINE_LOCATION": 20,
    "android.permission.RECORD_AUDIO":         20,
    "android.permission.CAMERA":               15,
    "android.permission.READ_EXTERNAL_STORAGE":10,
    "android.permission.GET_ACCOUNTS":         10,
    "android.permission.PROCESS_OUTGOING_CALLS":15,
}


def _score_trackers(comp: Component) -> float:
    score = 0.0

    # Tracker contribution
    for tracker in comp.trackers:
        # Each tracker contributes 20 * weight, capped at 60 total
        score += 20.0 * tracker.risk_weight

    # Cap tracker contribution
    score = min(score, 60.0)

    return min(score, 100.0)


# ─────────────────────────────────────────────
# Project-level summary stats
# ─────────────────────────────────────────────

def compute_project_summary(components: list[Component]) -> dict:
    """Return aggregate statistics for the whole project."""
    if not components:
        return {
            "total_components": 0, "direct_components": 0, "transitive_components": 0,
            "vulnerable_components": 0, "critical_components": 0, "high_components": 0,
            "moderate_components": 0, "low_components": 0, "total_cves": 0,
            "copyleft_components": 0, "tracker_components": 0,
            "avg_global_score": 0.0, "max_global_score": 0.0, "outdated_components": 0,
        }

    scores = [c.scores.global_score for c in components]
    cve_counts = [len(c.vulnerabilities) for c in components]

    return {
        "total_components": len(components),
        "direct_components": sum(1 for c in components if c.is_direct),
        "transitive_components": sum(1 for c in components if not c.is_direct),
        "vulnerable_components": sum(1 for c in components if c.vulnerabilities),
        "critical_components": sum(1 for c in components if c.scores.global_score >= 75),
        "high_components": sum(1 for c in components if 50 <= c.scores.global_score < 75),
        "moderate_components": sum(1 for c in components if 20 <= c.scores.global_score < 50),
        "low_components": sum(1 for c in components if c.scores.global_score < 20),
        "total_cves": sum(cve_counts),
        "copyleft_components": sum(1 for c in components if c.license and c.license.is_copyleft),
        "tracker_components": sum(1 for c in components if c.trackers),
        "avg_global_score": round(sum(scores) / len(scores), 1),
        "max_global_score": round(max(scores), 1),
        "outdated_components": sum(1 for c in components if c.is_outdated),
    }
