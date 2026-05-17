"""
ingestion/enricher.py
Async enrichment service. For each Component, fetches:
  - CVE data from OSV.dev
  - Latest version from Maven Central
  - License from ClearlyDefined
  - Trackers from Exodus Privacy
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

import httpx

from app.core.config import get_settings
from app.core.models import Component, CVE, License, Tracker

logger = logging.getLogger(__name__)
settings = get_settings()


# ─────────────────────────────────────────────
# License risk table (SPDX IDs → score 0-100)
# ─────────────────────────────────────────────

LICENSE_RISK: dict[str, tuple[float, bool, bool]] = {
    # (risk_score, is_copyleft, is_permissive)
    "MIT":            (0.0,  False, True),
    "Apache-2.0":     (0.0,  False, True),
    "BSD-2-Clause":   (5.0,  False, True),
    "BSD-3-Clause":   (5.0,  False, True),
    "ISC":            (5.0,  False, True),
    "Unlicense":      (5.0,  False, True),
    "MPL-2.0":        (20.0, True,  False),
    "CDDL-1.0":       (25.0, True,  False),
    "LGPL-2.1":       (35.0, True,  False),
    "LGPL-3.0":       (35.0, True,  False),
    "EUPL-1.2":       (50.0, True,  False),
    "GPL-2.0":        (75.0, True,  False),
    "GPL-2.0-only":   (75.0, True,  False),
    "GPL-3.0":        (75.0, True,  False),
    "GPL-3.0-only":   (75.0, True,  False),
    "AGPL-3.0":       (90.0, True,  False),
    "AGPL-3.0-only":  (90.0, True,  False),
    "UNKNOWN":        (65.0, False, False),
    "NOASSERTION":    (65.0, False, False),
    "PROPRIETARY":    (60.0, False, False),
}

# Tracker categories and their risk weights
TRACKER_CATEGORY_WEIGHTS: dict[str, float] = {
    "Analytics":              0.6,
    "Advertising":            0.8,
    "Identification":         0.9,
    "Location":               1.0,
    "Profiling":              1.0,
    "Fingerprinting":         1.0,
    "Crash reporter":         0.3,
    "Customer Support":       0.4,
    "Development":            0.2,
    "Social":                 0.5,
}


# ─────────────────────────────────────────────
# Main enrichment orchestrator
# ─────────────────────────────────────────────

async def enrich_components(components: list[Component]) -> list[Component]:
    """
    Enrich all components concurrently, respecting the concurrency limit.
    """
    semaphore = asyncio.Semaphore(settings.MAX_CONCURRENT_API_CALLS)
    # Pre-fetch tracker DB once (shared across all components)
    tracker_db = await _fetch_tracker_database()

    async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT) as client:
        tasks = [
            _enrich_one(client, comp, tracker_db, semaphore)
            for comp in components
        ]
        enriched = await asyncio.gather(*tasks, return_exceptions=False)

    return list(enriched)


async def _enrich_one(
    client: httpx.AsyncClient,
    comp: Component,
    tracker_db: list[dict],
    sem: asyncio.Semaphore,
) -> Component:
    async with sem:
        try:
            vulns, latest, license_, trackers = await asyncio.gather(
                _fetch_vulnerabilities(client, comp),
                _fetch_latest_version(client, comp),
                _fetch_license(client, comp),
                _detect_trackers_sync(comp, tracker_db),
            )
            comp.vulnerabilities = vulns
            if latest:
                comp.latest_version = latest.get("latest_version")
                comp.last_release_ts = latest.get("last_release_ts")
            comp.license = license_
            comp.trackers = trackers
        except Exception as e:
            logger.warning("Enrichment failed for %s: %s", comp.purl, e)
    return comp


# ─────────────────────────────────────────────
# CVE — OSV.dev
# ─────────────────────────────────────────────

async def _fetch_vulnerabilities(client: httpx.AsyncClient, comp: Component) -> list[CVE]:
    try:
        # When version is unknown (APK inference), query by package name only
        # to get ALL known vulnerabilities for that artifact
        if comp.version in ("unknown", "", None):
            payload = {"package": {"name": f"{comp.group}:{comp.artifact}", "ecosystem": "Maven"}}
        else:
            payload = {"package": {"purl": comp.purl}}

        resp = await client.post(
            f"{settings.OSV_API_URL}/query",
            json=payload,
        )
        if resp.status_code != 200:
            return []
        vulns = resp.json().get("vulns", [])
        logger.debug("OSV %s: %d vulns found", comp.purl, len(vulns))
        return [_parse_osv_vuln(v) for v in vulns]
    except Exception as e:
        logger.debug("OSV query failed for %s: %s", comp.purl, e)
        return []


def _parse_osv_vuln(v: dict) -> CVE:
    cvss_v3: Optional[float] = None
    for sev in v.get("severity", []):
        if sev.get("type") == "CVSS_V3":
            cvss_v3 = _extract_cvss_score(sev.get("score", ""))
            break

    # Check if a fix exists (any affected range has a fixed version)
    has_fix = any(
        any(
            event.get("fixed")
            for event in r.get("events", [])
        )
        for affected in v.get("affected", [])
        for r in affected.get("ranges", [])
    )

    return CVE(
        id=v.get("id", "UNKNOWN"),
        summary=v.get("summary", "No summary available")[:300],
        cvss_v3=cvss_v3,
        has_fix=has_fix,
        aliases=v.get("aliases", []),
    )


def _extract_cvss_score(vector_string: str) -> Optional[float]:
    """Extract the base score from a CVSS vector string or score string."""
    # Sometimes the API returns just the float score as a string
    try:
        return float(vector_string)
    except ValueError:
        pass
    # Try parsing "CVSS:3.1/AV:.../..." — score embedded in string
    m = __import__("re").search(r"/(\d+\.\d+)$", vector_string)
    if m:
        return float(m.group(1))
    return None


# ─────────────────────────────────────────────
# Latest version — Maven Central
# ─────────────────────────────────────────────

async def _fetch_latest_version(client: httpx.AsyncClient, comp: Component) -> Optional[dict]:
    try:
        resp = await client.get(
            settings.MAVEN_SEARCH_URL,
            params={
                "q": f"g:{comp.group} AND a:{comp.artifact}",
                "core": "gav",
                "rows": 1,
                "wt": "json",
                "sort": "timestamp desc",
            },
        )
        if resp.status_code != 200:
            return None
        docs = resp.json().get("response", {}).get("docs", [])
        if not docs:
            return None
        return {
            "latest_version": docs[0].get("v"),
            "last_release_ts": docs[0].get("timestamp", 0) / 1000,
        }
    except Exception as e:
        logger.debug("Maven Central query failed for %s: %s", comp.purl, e)
        return None


# ─────────────────────────────────────────────
# License — ClearlyDefined
# ─────────────────────────────────────────────

async def _fetch_license(client: httpx.AsyncClient, comp: Component) -> License:
    """
    Fetch license info from ClearlyDefined.
    Coordinates: maven/mavencentral/{group}/{artifact}/{version}
    """
    coord = f"maven/mavencentral/{comp.group}/{comp.artifact}/{comp.version}"
    try:
        resp = await client.get(f"{settings.CLEARLY_DEFINED_URL}/{coord}")
        if resp.status_code == 200:
            data = resp.json()
            spdx_id = (
                data.get("licensed", {})
                    .get("declared", "UNKNOWN")
                    .upper()
                    .replace(" ", "-")
            )
            return _build_license(spdx_id)
    except Exception as e:
        logger.debug("ClearlyDefined query failed for %s: %s", comp.purl, e)

    return License.unknown()


def _build_license(spdx_id: str) -> License:
    risk, copyleft, permissive = LICENSE_RISK.get(
        spdx_id, LICENSE_RISK["UNKNOWN"]
    )
    return License(
        spdx_id=spdx_id,
        name=spdx_id,
        risk_score=risk,
        is_copyleft=copyleft,
        is_permissive=permissive,
    )


# ─────────────────────────────────────────────
# Trackers — Exodus Privacy
# ─────────────────────────────────────────────

_tracker_db_cache: Optional[list[dict]] = None


async def _fetch_tracker_database() -> list[dict]:
    global _tracker_db_cache
    if _tracker_db_cache is not None:
        return _tracker_db_cache

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(settings.EXODUS_API_URL)
            if resp.status_code == 200:
                raw = resp.json().get("trackers", {})
                _tracker_db_cache = list(raw.values())
                return _tracker_db_cache
    except Exception as e:
        logger.warning("Could not fetch Exodus tracker database: %s", e)

    _tracker_db_cache = []
    return _tracker_db_cache


async def _detect_trackers_sync(comp: Component, tracker_db: list[dict]) -> list[Tracker]:
    """
    Match the component's group/artifact against known tracker code signatures.
    """
    detected: list[Tracker] = []
    search_string = f"{comp.group}.{comp.artifact}".lower()

    for t in tracker_db:
        sig = t.get("code_signature", "").lower()
        if sig and (sig in search_string or search_string.startswith(sig)):
            categories = t.get("categories", [])
            weight = max(
                (TRACKER_CATEGORY_WEIGHTS.get(cat, 0.5) for cat in categories),
                default=0.5,
            )
            detected.append(Tracker(
                name=t.get("name", "Unknown"),
                categories=categories,
                website=t.get("website", ""),
                code_signature=t.get("code_signature", ""),
                risk_weight=weight,
            ))

    return detected
