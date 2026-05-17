"""
sbom/generator.py
Generates SBOM documents in CycloneDX 1.5 (JSON) and SPDX 2.3 (JSON) formats.
"""
from __future__ import annotations

import json
import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path

from app.core.models import Component, AnalysisReport


# ─────────────────────────────────────────────
# CycloneDX 1.5
# ─────────────────────────────────────────────

def generate_cyclonedx(report: AnalysisReport, output_path: Path) -> Path:
    """Generate a CycloneDX 1.5 JSON SBOM and write it to disk."""
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": report.analyzed_at,
            "tools": [
                {
                    "vendor": "DependencyRiskRadar",
                    "name": "dependency-risk-radar",
                    "version": "1.0.0",
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": f"pkg:maven/{report.project_name}@{report.project_version}",
                "name": report.project_name,
                "version": report.project_version,
            },
        },
        "components": [_comp_to_cyclonedx(c) for c in report.components],
        "dependencies": _build_cyclonedx_dependencies(report.components),
        "vulnerabilities": _build_cyclonedx_vulnerabilities(report.components),
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(bom, indent=2, ensure_ascii=False))
    return output_path


def _comp_to_cyclonedx(comp: Component) -> dict:
    c: dict = {
        "type": "library",
        "bom-ref": comp.purl,
        "group": comp.group,
        "name": comp.artifact,
        "version": comp.version,
        "purl": comp.purl,
        "scope": "required" if comp.scope.value in ("implementation", "api") else "optional",
    }

    if comp.license:
        c["licenses"] = [{"license": {"id": comp.license.spdx_id}}]

    # Risk metadata in properties (CycloneDX extension)
    c["properties"] = [
        {"name": "drr:global_score", "value": str(comp.scores.global_score)},
        {"name": "drr:cve_score", "value": str(comp.scores.cve_score)},
        {"name": "drr:obsolescence_score", "value": str(comp.scores.obsolescence_score)},
        {"name": "drr:risk_level", "value": comp.scores.risk_level.value},
        {"name": "drr:is_direct", "value": str(comp.is_direct).lower()},
        {"name": "drr:depth", "value": str(comp.depth)},
    ]

    if comp.latest_version:
        c["properties"].append({"name": "drr:latest_version", "value": comp.latest_version})

    if comp.trackers:
        tracker_names = ", ".join(t.name for t in comp.trackers)
        c["properties"].append({"name": "drr:trackers", "value": tracker_names})

    return c


def _build_cyclonedx_dependencies(components: list[Component]) -> list[dict]:
    deps = []
    for comp in components:
        entry = {
            "ref": comp.purl,
            "dependsOn": comp.dependencies,
        }
        deps.append(entry)
    return deps


def _build_cyclonedx_vulnerabilities(components: list[Component]) -> list[dict]:
    vulns_out = []
    seen_ids: set[str] = set()

    for comp in components:
        for v in comp.vulnerabilities:
            if v.id in seen_ids:
                continue
            seen_ids.add(v.id)

            vuln: dict = {
                "id": v.id,
                "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{v.id}"},
                "description": v.summary,
                "affects": [{"ref": comp.purl}],
            }

            if v.cvss_v3 is not None:
                vuln["ratings"] = [
                    {
                        "source": {"name": "OSV"},
                        "score": v.cvss_v3,
                        "severity": _cvss_to_severity(v.cvss_v3),
                        "method": "CVSSv3",
                    }
                ]

            if v.aliases:
                vuln["references"] = [
                    {"id": alias, "source": {"name": "NVD"}}
                    for alias in v.aliases
                    if alias.startswith("CVE-")
                ]

            if v.has_fix:
                vuln["analysis"] = {"state": "in_triage"}
            else:
                vuln["analysis"] = {"state": "exploitable"}

            vulns_out.append(vuln)

    return vulns_out


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    return "low"


# ─────────────────────────────────────────────
# SPDX 2.3 (JSON)
# ─────────────────────────────────────────────

def generate_spdx(report: AnalysisReport, output_path: Path) -> Path:
    """Generate an SPDX 2.3 JSON SBOM."""
    doc_namespace = f"https://dependency-risk-radar/{report.project_name}/{uuid.uuid4()}"

    spdx = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
        "creationInfo": {
            "created": report.analyzed_at,
            "creators": ["Tool: dependency-risk-radar-1.0.0"],
            "licenseListVersion": "3.22",
        },
        "name": f"SBOM-{report.project_name}",
        "dataLicense": "CC0-1.0",
        "documentNamespace": doc_namespace,
        "packages": [_comp_to_spdx(comp) for comp in report.components],
        "relationships": _build_spdx_relationships(report),
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(spdx, indent=2, ensure_ascii=False))
    return output_path


def _safe_spdx_id(purl: str) -> str:
    """Convert a PURL to a valid SPDX element ID."""
    safe = purl.replace("pkg:maven/", "").replace("/", "-").replace("@", "-").replace(":", "-")
    return f"SPDXRef-{safe[:64]}"


def _comp_to_spdx(comp: Component) -> dict:
    pkg: dict = {
        "SPDXID": _safe_spdx_id(comp.purl),
        "name": comp.artifact,
        "versionInfo": comp.version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": comp.purl,
            }
        ],
    }

    if comp.license:
        pkg["licenseConcluded"] = comp.license.spdx_id
        pkg["licenseDeclared"] = comp.license.spdx_id
    else:
        pkg["licenseConcluded"] = "NOASSERTION"
        pkg["licenseDeclared"] = "NOASSERTION"

    pkg["copyrightText"] = "NOASSERTION"
    return pkg


def _build_spdx_relationships(report: AnalysisReport) -> list[dict]:
    relationships = []
    root_id = "SPDXRef-DOCUMENT"

    for comp in report.components:
        if comp.is_direct:
            relationships.append({
                "spdxElementId": root_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": _safe_spdx_id(comp.purl),
            })
        for child_purl in comp.dependencies:
            # Find matching component
            relationships.append({
                "spdxElementId": _safe_spdx_id(comp.purl),
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": _safe_spdx_id(child_purl),
            })

    return relationships
