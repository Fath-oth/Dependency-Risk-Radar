"""
tests/test_sbom.py
Unit tests for CycloneDX and SPDX SBOM generation.
"""
import json
import tempfile
import pytest
from pathlib import Path
from datetime import datetime, timezone

from app.core.models import (
    AnalysisReport, Component, CVE, License, RiskScores, DependencyScope
)
from app.sbom.generator import generate_cyclonedx, generate_spdx, _safe_spdx_id


# ─────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────

def _make_component(artifact: str, group: str = "com.example", version: str = "1.0.0",
                    is_direct: bool = True, vulns: list = None, license_id: str = "Apache-2.0") -> Component:
    c = Component(
        purl=f"pkg:maven/{group}/{artifact}@{version}",
        name=f"{group}:{artifact}",
        group=group,
        artifact=artifact,
        version=version,
        scope=DependencyScope.IMPLEMENTATION,
        is_direct=is_direct,
        depth=0 if is_direct else 1,
    )
    c.vulnerabilities = vulns or []
    c.license = License(
        spdx_id=license_id,
        name=license_id,
        risk_score=0.0,
        is_copyleft=False,
        is_permissive=True,
    )
    c.scores = RiskScores()
    return c


def _make_report(components: list) -> AnalysisReport:
    return AnalysisReport(
        report_id="test-report-001",
        project_name="TestApp",
        project_version="2.0.0",
        analyzed_at=datetime.now(timezone.utc).isoformat(),
        components=components,
    )


# ─────────────────────────────────────────────
# CycloneDX
# ─────────────────────────────────────────────

class TestCycloneDX:
    def _generate(self, components: list) -> dict:
        report = _make_report(components)
        with tempfile.TemporaryDirectory() as tmp:
            path = generate_cyclonedx(report, Path(tmp) / "bom.json")
            return json.loads(path.read_text())

    def test_correct_bom_format(self):
        bom = self._generate([_make_component("retrofit")])
        assert bom["bomFormat"]   == "CycloneDX"
        assert bom["specVersion"] == "1.5"

    def test_metadata_fields(self):
        bom = self._generate([_make_component("lib")])
        assert bom["metadata"]["component"]["name"]    == "TestApp"
        assert bom["metadata"]["component"]["version"] == "2.0.0"
        assert "tools" in bom["metadata"]

    def test_all_components_present(self):
        comps = [_make_component(f"lib{i}") for i in range(5)]
        bom = self._generate(comps)
        assert len(bom["components"]) == 5

    def test_component_fields(self):
        comp = _make_component("retrofit", group="com.squareup.retrofit2", version="2.9.0")
        bom = self._generate([comp])
        c = bom["components"][0]
        assert c["type"]    == "library"
        assert c["name"]    == "retrofit"
        assert c["version"] == "2.9.0"
        assert c["group"]   == "com.squareup.retrofit2"
        assert "purl"       in c

    def test_purl_correct_format(self):
        comp = _make_component("gson", group="com.google.code.gson", version="2.10.1")
        bom = self._generate([comp])
        assert bom["components"][0]["purl"] == "pkg:maven/com.google.code.gson/gson@2.10.1"

    def test_license_included(self):
        comp = _make_component("lib", license_id="MIT")
        bom = self._generate([comp])
        licenses = bom["components"][0].get("licenses", [])
        assert any(
            lic.get("license", {}).get("id") == "MIT"
            for lic in licenses
        )

    def test_risk_scores_in_properties(self):
        comp = _make_component("lib")
        comp.scores = RiskScores(cve_score=75.0, obsolescence_score=30.0)
        bom = self._generate([comp])
        props = {p["name"]: p["value"] for p in bom["components"][0].get("properties", [])}
        assert "drr:global_score" in props
        assert "drr:risk_level"   in props

    def test_vulnerabilities_section(self):
        vuln = CVE(id="CVE-2021-44228", summary="Log4Shell", cvss_v3=10.0, has_fix=True)
        comp = _make_component("log4j", vulns=[vuln])
        bom = self._generate([comp])
        vuln_ids = [v["id"] for v in bom.get("vulnerabilities", [])]
        assert "CVE-2021-44228" in vuln_ids

    def test_vulnerability_cvss_rating(self):
        vuln = CVE(id="CVE-2021-44228", summary="Log4Shell", cvss_v3=10.0, has_fix=True)
        comp = _make_component("log4j", vulns=[vuln])
        bom = self._generate([comp])
        v = bom["vulnerabilities"][0]
        assert v["ratings"][0]["score"] == 10.0
        assert v["ratings"][0]["severity"] == "critical"

    def test_no_duplicate_vulnerabilities(self):
        vuln = CVE(id="CVE-2021-44228", summary="Log4Shell", cvss_v3=10.0, has_fix=True)
        comp1 = _make_component("lib1", vulns=[vuln])
        comp2 = _make_component("lib2", vulns=[vuln])
        bom = self._generate([comp1, comp2])
        # Same CVE ID should appear only once
        vuln_ids = [v["id"] for v in bom.get("vulnerabilities", [])]
        assert vuln_ids.count("CVE-2021-44228") == 1

    def test_dependencies_section(self):
        parent = _make_component("retrofit", is_direct=True)
        parent.dependencies = ["pkg:maven/com.squareup.okhttp3/okhttp@4.11.0"]
        child = _make_component("okhttp", group="com.squareup.okhttp3",
                                version="4.11.0", is_direct=False)
        bom = self._generate([parent, child])
        dep_map = {d["ref"]: d["dependsOn"] for d in bom.get("dependencies", [])}
        assert parent.purl in dep_map
        assert "pkg:maven/com.squareup.okhttp3/okhttp@4.11.0" in dep_map[parent.purl]

    def test_serial_number_is_uuid(self):
        bom = self._generate([_make_component("lib")])
        assert bom["serialNumber"].startswith("urn:uuid:")

    def test_file_written_to_disk(self):
        report = _make_report([_make_component("lib")])
        with tempfile.TemporaryDirectory() as tmp:
            path = generate_cyclonedx(report, Path(tmp) / "bom.json")
            assert path.exists()
            assert path.stat().st_size > 0

    def test_empty_project(self):
        bom = self._generate([])
        assert bom["components"] == []
        assert bom["dependencies"] == []


# ─────────────────────────────────────────────
# SPDX
# ─────────────────────────────────────────────

class TestSPDX:
    def _generate(self, components: list) -> dict:
        report = _make_report(components)
        with tempfile.TemporaryDirectory() as tmp:
            path = generate_spdx(report, Path(tmp) / "bom-spdx.json")
            return json.loads(path.read_text())

    def test_correct_spdx_version(self):
        doc = self._generate([_make_component("lib")])
        assert doc["spdxVersion"] == "SPDX-2.3"

    def test_data_license(self):
        doc = self._generate([_make_component("lib")])
        assert doc["dataLicense"] == "CC0-1.0"

    def test_document_has_name(self):
        doc = self._generate([_make_component("lib")])
        assert "TestApp" in doc["name"]

    def test_all_packages_present(self):
        comps = [_make_component(f"lib{i}") for i in range(3)]
        doc = self._generate(comps)
        assert len(doc["packages"]) == 3

    def test_package_fields(self):
        comp = _make_component("retrofit", version="2.9.0")
        doc = self._generate([comp])
        pkg = doc["packages"][0]
        assert pkg["name"]        == "retrofit"
        assert pkg["versionInfo"] == "2.9.0"
        assert "SPDXID"           in pkg

    def test_purl_in_external_refs(self):
        comp = _make_component("gson", group="com.google.code.gson", version="2.10.1")
        doc = self._generate([comp])
        pkg = doc["packages"][0]
        purls = [
            r["referenceLocator"] for r in pkg.get("externalRefs", [])
            if r.get("referenceType") == "purl"
        ]
        assert "pkg:maven/com.google.code.gson/gson@2.10.1" in purls

    def test_license_declared(self):
        comp = _make_component("lib", license_id="Apache-2.0")
        doc = self._generate([comp])
        assert doc["packages"][0]["licenseDeclared"] == "Apache-2.0"

    def test_relationships_include_depends_on(self):
        comp = _make_component("lib")
        doc = self._generate([comp])
        rel_types = {r["relationshipType"] for r in doc.get("relationships", [])}
        assert "DEPENDS_ON" in rel_types

    def test_document_namespace_unique(self):
        report = _make_report([_make_component("lib")])
        docs = []
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(2):
                path = generate_spdx(report, Path(tmp) / f"bom{i}.json")
                docs.append(json.loads(path.read_text()))
        assert docs[0]["documentNamespace"] != docs[1]["documentNamespace"]


# ─────────────────────────────────────────────
# _safe_spdx_id
# ─────────────────────────────────────────────

class TestSafeSpdxId:
    def test_valid_id_generated(self):
        result = _safe_spdx_id("pkg:maven/com.squareup.retrofit2/retrofit@2.9.0")
        assert result.startswith("SPDXRef-")
        assert " " not in result
        assert "/" not in result
        assert "@" not in result

    def test_id_not_too_long(self):
        long_purl = "pkg:maven/" + "a" * 200 + "/lib@1.0.0"
        result = _safe_spdx_id(long_purl)
        # SPDX element IDs must be reasonably short
        assert len(result) <= 80
