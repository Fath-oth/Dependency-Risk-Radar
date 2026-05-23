"""
api/main.py — FastAPI application, GUI-only
"""
from __future__ import annotations
import asyncio, logging, os, tempfile, uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app.core.config import get_settings
from app.core.pipeline import run_gradle_analysis, run_apk_analysis
from app.scoring.engine import compute_project_summary
from app.graph.dependency_graph import DependencyGraph

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(name)s: %(message)s", datefmt="%H:%M:%S")
logger   = logging.getLogger(__name__)
settings = get_settings()

app = FastAPI(title="Dependency Risk Radar", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

_reports: dict[str, dict] = {}
_jobs:    dict[str, dict] = {}
OUTPUT_BASE = Path(os.getenv("OUTPUT_DIR", "/tmp/drr_reports"))


# ── Health ──────────────────────────────────────────────
@app.get("/health")
def health(): return {"status": "ok", "version": settings.APP_VERSION}


# ── Analysis endpoints ───────────────────────────────────
class GradleRequest(BaseModel):
    project_path: str

@app.post("/api/v1/analyze/gradle")
async def analyze_gradle(req: GradleRequest):
    p = Path(req.project_path)
    if not p.exists():
        raise HTTPException(404, f"Path not found: {p}")
    jid = _new_job()
    asyncio.create_task(_gradle_job(jid, p))
    return {"job_id": jid, "status": "queued"}

@app.post("/api/v1/analyze/apk")
async def analyze_apk_upload(file: UploadFile = File(...)):
    if not file.filename.endswith(".apk"):
        raise HTTPException(400, "File must be .apk")
    tmp = Path(tempfile.mkdtemp()) / file.filename
    tmp.write_bytes(await file.read())
    jid = _new_job()
    asyncio.create_task(_apk_job(jid, tmp))
    return {"job_id": jid, "status": "queued"}


# ── Job status ───────────────────────────────────────────
@app.get("/api/v1/jobs/{job_id}")
def get_job(job_id: str):
    job = _jobs.get(job_id)
    if not job: raise HTTPException(404, "Job not found")
    return job


# ── Reports ──────────────────────────────────────────────
@app.get("/api/v1/reports")
def list_reports(limit: int = 20):
    rows = sorted(_reports.values(), key=lambda r: r.get("analyzed_at",""), reverse=True)[:limit]
    return [{"report_id": r["report_id"], "project_name": r.get("project_name","?"),
             "analyzed_at": r.get("analyzed_at",""), "global_risk_score": r.get("global_risk_score",0),
             "total_components": r.get("summary",{}).get("total_components",0)} for r in rows]

@app.get("/api/v1/reports/{report_id}")
def get_report(report_id: str):
    r = _get_or_404(report_id)
    return {k: v for k, v in r.items() if not k.startswith("_")}

@app.get("/api/v1/reports/{report_id}/components")
def get_components(report_id: str, min_score: float=0, max_score: float=100,
                   is_direct: Optional[bool]=None, sort_by: str="global_score",
                   order: str="desc", limit: int=200, offset: int=0):
    r  = _get_or_404(report_id)
    cs = r["components"]
    if is_direct is not None: cs = [c for c in cs if c["is_direct"] == is_direct]
    cs = [c for c in cs if min_score <= c["scores"]["global"] <= max_score]
    reverse = order == "desc"
    if sort_by == "global_score": cs.sort(key=lambda c: c["scores"]["global"], reverse=reverse)
    elif sort_by == "name":       cs.sort(key=lambda c: c["name"], reverse=reverse)
    return {"total": len(cs), "offset": offset, "limit": limit, "items": cs[offset:offset+limit]}

@app.get("/api/v1/reports/{report_id}/update-plan")
def get_plan(report_id: str):
    return _get_or_404(report_id).get("update_plan", {})

@app.get("/api/v1/reports/{report_id}/graph")
def get_graph(report_id: str):
    return _get_or_404(report_id).get("graph", {"nodes":[], "edges":[]})

@app.get("/api/v1/reports/{report_id}/sbom")
def download_sbom(report_id: str, format: str = "cyclonedx"):
    _get_or_404(report_id)
    fname = "sbom_cyclonedx.json" if format == "cyclonedx" else "sbom_spdx.json"
    path  = OUTPUT_BASE / report_id / fname
    if not path.exists(): raise HTTPException(404, "SBOM not found")
    return FileResponse(str(path), media_type="application/json", filename=fname)


# ── Internals ────────────────────────────────────────────
def _get_or_404(report_id: str) -> dict:
    r = _reports.get(report_id)
    if not r: raise HTTPException(404, "Report not found")
    return r

def _new_job() -> str:
    jid = str(uuid.uuid4())
    _jobs[jid] = {"job_id": jid, "status": "queued", "progress": 0, "message": "Queued"}
    return jid

def _upd(jid, msg, pct):
    if jid in _jobs: _jobs[jid].update({"message": msg, "progress": pct, "status": "running"})

async def _gradle_job(jid: str, path: Path):
    try:
        report = await run_gradle_analysis(path, OUTPUT_BASE, lambda m,p: _upd(jid,m,p))
        _save(report, jid)
    except Exception as e:
        logger.exception("Gradle job %s failed", jid)
        _jobs[jid].update({"status": "failed", "error": str(e)})

async def _apk_job(jid: str, path: Path):
    try:
        report = await run_apk_analysis(path, OUTPUT_BASE, lambda m,p: _upd(jid,m,p))
        _save(report, jid)
    except Exception as e:
        logger.exception("APK job %s failed", jid)
        _jobs[jid].update({"status": "failed", "error": str(e)})

def _save(report, jid: str):
    g = DependencyGraph(); g.build(report.components)
    _reports[report.report_id] = {
        "report_id":         report.report_id,
        "project_name":      report.project_name,
        "project_version":   report.project_version,
        "analyzed_at":       report.analyzed_at,
        "global_risk_score": report.global_risk_score,
        "summary":           compute_project_summary(report.components),
        "components":        [c.to_dict() for c in report.components],
        "update_plan":       report.update_plan,
        "graph":             g.to_json(),
        "_graph_obj":        g,
    }
    _jobs[jid].update({"status": "completed", "progress": 100, "report_id": report.report_id})
