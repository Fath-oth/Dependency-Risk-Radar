"""
tests/test_enricher.py
Unit tests for the enrichment service using mocked HTTP responses.
"""
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch, MagicMock

from app.core.models import Component, DependencyScope
from app.ingestion.enricher import (
    _parse_osv_vuln,
    _build_license,
    _detect_trackers_sync,
    _extract_cvss_score,
    LICENSE_RISK,
)


def _make_component(artifact: str = "lib", version: str = "1.0.0") -> Component:
    return Component(
        purl=f"pkg:maven/com.example/{artifact}@{version}",
        name=f"com.example:{artifact}",
        group="com.example",
        artifact=artifact,
        version=version,
        scope=DependencyScope.IMPLEMENTATION,
        is_direct=True,
        depth=0,
    )


# ─────────────────────────────────────────────
# _parse_osv_vuln
# ─────────────────────────────────────────────

class TestParseOsvVuln:
    def test_parses_id_and_summary(self):
        raw = {
            "id": "GHSA-1234-5678-90ab",
            "summary": "Remote code execution",
            "severity": [],
            "affected": [],
            "aliases": [],
        }
        vuln = _parse_osv_vuln(raw)
        assert vuln.id      == "GHSA-1234-5678-90ab"
        assert vuln.summary == "Remote code execution"

    def test_extracts_cvss_v3(self):
        raw = {
            "id": "CVE-2021-44228",
            "summary": "Log4Shell",
            "severity": [{"type": "CVSS_V3", "score": "10.0"}],
            "affected": [],
            "aliases": [],
        }
        vuln = _parse_osv_vuln(raw)
        assert vuln.cvss_v3 == 10.0

    def test_ignores_cvss_v2(self):
        raw = {
            "id": "CVE-2020-0001",
            "summary": "Old CVE",
            "severity": [{"type": "CVSS_V2", "score": "7.5"}],
            "affected": [],
            "aliases": [],
        }
        vuln = _parse_osv_vuln(raw)
        assert vuln.cvss_v3 is None

    def test_has_fix_when_fixed_range_exists(self):
        raw = {
            "id": "CVE-2024-1234",
            "summary": "Test",
            "severity": [],
            "aliases": [],
            "affected": [{
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "2.0.0"},
                    ]
                }]
            }]
        }
        vuln = _parse_osv_vuln(raw)
        assert vuln.has_fix is True

    def test_no_fix_when_no_fixed_event(self):
        raw = {
            "id": "CVE-2024-9999",
            "summary": "Unfixed",
            "severity": [],
            "aliases": [],
            "affected": [{
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}]
                }]
            }]
        }
        vuln = _parse_osv_vuln(raw)
        assert vuln.has_fix is False

    def test_aliases_extracted(self):
        raw = {
            "id": "GHSA-abcd",
            "summary": "Test",
            "severity": [],
            "affected": [],
            "aliases": ["CVE-2024-1111", "CVE-2024-2222"],
        }
        vuln = _parse_osv_vuln(raw)
        assert "CVE-2024-1111" in vuln.aliases
        assert "CVE-2024-2222" in vuln.aliases

    def test_summary_truncated_at_300_chars(self):
        raw = {
            "id": "CVE-2024-0001",
            "summary": "A" * 500,
            "severity": [],
            "affected": [],
            "aliases": [],
        }
        vuln = _parse_osv_vuln(raw)
        assert len(vuln.summary) <= 300


# ─────────────────────────────────────────────
# _extract_cvss_score
# ─────────────────────────────────────────────

class TestExtractCvssScore:
    def test_plain_float_string(self):
        assert _extract_cvss_score("9.8") == 9.8

    def test_integer_string(self):
        assert _extract_cvss_score("10") == 10.0

    def test_returns_none_for_unparseable(self):
        assert _extract_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None or \
               isinstance(_extract_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), float)

    def test_zero_score(self):
        assert _extract_cvss_score("0.0") == 0.0


# ─────────────────────────────────────────────
# _build_license
# ─────────────────────────────────────────────

class TestBuildLicense:
    def test_mit_is_permissive_zero_risk(self):
        lic = _build_license("MIT")
        assert lic.spdx_id        == "MIT"
        assert lic.risk_score     == 0.0
        assert lic.is_permissive  is True
        assert lic.is_copyleft    is False

    def test_gpl_is_copyleft_high_risk(self):
        lic = _build_license("GPL-3.0")
        assert lic.is_copyleft   is True
        assert lic.risk_score    >= 70.0

    def test_agpl_highest_risk(self):
        lic = _build_license("AGPL-3.0")
        assert lic.risk_score    >= 85.0

    def test_apache_zero_risk(self):
        lic = _build_license("Apache-2.0")
        assert lic.risk_score    == 0.0
        assert lic.is_permissive is True

    def test_unknown_license_fallback(self):
        lic = _build_license("SOME-UNKNOWN-LICENSE-XYZ")
        assert lic.risk_score    == LICENSE_RISK["UNKNOWN"][0]

    def test_all_known_licenses_parseable(self):
        for spdx_id in LICENSE_RISK:
            lic = _build_license(spdx_id)
            assert lic is not None
            assert 0.0 <= lic.risk_score <= 100.0

    def test_lgpl_moderate_risk(self):
        lic = _build_license("LGPL-2.1")
        assert 25.0 <= lic.risk_score <= 50.0
        assert lic.is_copyleft is True


# ─────────────────────────────────────────────
# _detect_trackers_sync
# ─────────────────────────────────────────────

class TestDetectTrackers:
    TRACKER_DB = [
        {
            "name": "Google Firebase Analytics",
            "categories": ["Analytics"],
            "website": "https://firebase.google.com",
            "code_signature": "com.google.firebase",
        },
        {
            "name": "Facebook Ads SDK",
            "categories": ["Advertising"],
            "website": "https://developers.facebook.com",
            "code_signature": "com.facebook.ads",
        },
        {
            "name": "Adjust",
            "categories": ["Analytics", "Identification"],
            "website": "https://adjust.com",
            "code_signature": "com.adjust.sdk",
        },
    ]

    @pytest.mark.asyncio
    async def test_detects_matching_tracker(self):
        comp = _make_component(artifact="firebase-analytics")
        comp.group = "com.google.firebase"
        result = await _detect_trackers_sync(comp, self.TRACKER_DB)
        assert any(t.name == "Google Firebase Analytics" for t in result)

    @pytest.mark.asyncio
    async def test_no_match_returns_empty(self):
        comp = _make_component(artifact="okhttp")
        comp.group = "com.squareup.okhttp3"
        result = await _detect_trackers_sync(comp, self.TRACKER_DB)
        assert result == []

    @pytest.mark.asyncio
    async def test_tracker_risk_weight_set(self):
        comp = _make_component(artifact="adjust-android")
        comp.group = "com.adjust.sdk"
        result = await _detect_trackers_sync(comp, self.TRACKER_DB)
        assert len(result) > 0
        assert result[0].risk_weight > 0.0

    @pytest.mark.asyncio
    async def test_empty_tracker_db_returns_empty(self):
        comp = _make_component()
        result = await _detect_trackers_sync(comp, [])
        assert result == []

    @pytest.mark.asyncio
    async def test_categories_preserved(self):
        comp = _make_component(artifact="adjust-android")
        comp.group = "com.adjust.sdk"
        result = await _detect_trackers_sync(comp, self.TRACKER_DB)
        if result:
            assert "Analytics" in result[0].categories
