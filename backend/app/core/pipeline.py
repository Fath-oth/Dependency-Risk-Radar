"""
core/pipeline.py — GUI-only pipeline, no gradlew subprocess
"""
from __future__ import annotations
import asyncio, logging, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Callable

from app.core.models import AnalysisReport
from app.core.config import get_settings
from app.ingestion.gradle_parser import parse_project, build_components
from app.ingestion.apk_analyzer import analyze_apk, build_components_from_apk
from app.ingestion.enricher import enrich_components
from app.scoring.engine import score_all, compute_project_summary
from app.graph.dependency_graph import DependencyGraph
from app.ai.planner import generate_update_plan
from app.sbom.generator import generate_cyclonedx, generate_spdx

logger   = logging.getLogger(__name__)
settings = get_settings()
ProgressCallback = Callable[[str, int], None]


async def run_gradle_analysis(project_root: Path, output_dir: Path,
                               progress: Optional[ProgressCallback] = None) -> AnalysisReport:
    def _p(msg, pct):
        logger.info("[%3d%%] %s", pct, msg)
        if progress: progress(msg, pct)

    report_id = str(uuid.uuid4())
    out_dir   = output_dir / report_id
    out_dir.mkdir(parents=True, exist_ok=True)

    _p("Scanning project files…", 5)
    raw_deps = parse_project(project_root)

    if raw_deps:
        _p(f"Found {len(raw_deps)} dependencies — enriching…", 15)
    else:
        root_items = [f.name for f in project_root.iterdir()] if project_root.exists() else []
        logger.warning("No deps found. Root: %s", root_items)
        _p(f"No dependencies found. Contents: {root_items[:8]}", 15)

    components = build_components(raw_deps)
    _p(f"Built {len(components)} components", 20)

    _p("Fetching CVE, versions, licences, trackers…", 25)
    components = await enrich_components(components)
    _p("Enrichment complete", 60)

    _p("Computing risk scores…", 62)
    components = score_all(components)

    _p("Building dependency graph…", 65)
    g = DependencyGraph(); g.build(components)
    components = g.propagate_transitive_risk(components)
    _p("Graph complete", 70)

    report = AnalysisReport(
        report_id=report_id, project_name=project_root.name,
        project_version="unknown",
        analyzed_at=datetime.now(timezone.utc).isoformat(), components=components,
    )
    generate_cyclonedx(report, out_dir / "sbom_cyclonedx.json")
    generate_spdx(report, out_dir / "sbom_spdx.json")
    _p("SBOM generated", 80)

    _p("Generating AI update plan…", 82)
    if settings.GEMINI_API_KEY or settings.ANTHROPIC_API_KEY:
        report.update_plan = await generate_update_plan(components)
    else:
        report.update_plan = {"updates": [], "_fallback": True,
                               "executive_summary": "Set GEMINI_API_KEY in .env for AI-powered analysis."}
    _p("Analysis complete", 100)
    logger.info("Done: %d components, score=%.1f", len(components), report.global_risk_score)
    return report


async def run_apk_analysis(apk_path: Path, output_dir: Path,
                            progress: Optional[ProgressCallback] = None) -> AnalysisReport:
    def _p(msg, pct):
        logger.info("[%3d%%] %s", pct, msg)
        if progress: progress(msg, pct)

    report_id = str(uuid.uuid4())
    out_dir   = output_dir / report_id
    out_dir.mkdir(parents=True, exist_ok=True)

    _p("Analysing APK…", 10)
    apk_result   = analyze_apk(apk_path)
    meta         = apk_result.get("metadata", {})
    project_name = meta.get("package_name", apk_path.stem)
    project_ver  = meta.get("version_name", "unknown")
    n_comps      = len(apk_result.get("components", []))
    _p(f"APK: {project_name} v{project_ver} — {n_comps} components detected", 20)

    components = build_components_from_apk(apk_result)
    _p(f"Enriching {len(components)} components…", 25)

    components = await enrich_components(components)
    components = score_all(components)

    g = DependencyGraph(); g.build(components)
    components = g.propagate_transitive_risk(components)
    _p("Graph complete", 70)

    report = AnalysisReport(
        report_id=report_id, project_name=project_name, project_version=project_ver,
        analyzed_at=datetime.now(timezone.utc).isoformat(), components=components,
    )
    generate_cyclonedx(report, out_dir / "sbom_cyclonedx.json")
    generate_spdx(report, out_dir / "sbom_spdx.json")

    _p("Generating AI update plan…", 82)
    if settings.GEMINI_API_KEY or settings.ANTHROPIC_API_KEY:
        report.update_plan = await generate_update_plan(components)
    else:
        report.update_plan = {"updates": [], "_fallback": True,
                               "executive_summary": "Set GEMINI_API_KEY in .env for AI-powered analysis."}
    _p("Analysis complete", 100)
    return report
