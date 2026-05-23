"""
ai/planner.py — Gemini Flash primary, Anthropic fallback
"""
from __future__ import annotations
import json, logging, re
from typing import Optional
from app.core.config import get_settings
from app.core.models import Component, RiskLevel

logger   = logging.getLogger(__name__)
settings = get_settings()

SYSTEM_PROMPT_PLANNER = """You are an expert Android security engineer and dependency management specialist.
You receive a structured risk report for an Android project listing its risky dependencies.
Your task: generate a precise, actionable, prioritised update plan.
CRITICAL: Respond ONLY with valid JSON. No markdown fences, no preamble, no explanation outside the JSON.
Required format:
{
  "updates": [
    {
      "purl": "pkg:maven/group/artifact@version",
      "name": "artifact-name",
      "current_version": "x.y.z",
      "recommended_version": "a.b.c",
      "priority": "CRITICAL|HIGH|MEDIUM|LOW",
      "main_reason": "One sentence stating the primary risk driver",
      "breaking_risk": "LOW|MODERATE|HIGH",
      "migration_effort": "< 1h | 2-4h | 1 day | > 1 day",
      "action": "UPDATE|REPLACE|REMOVE|MONITOR",
      "replacement_suggestion": null,
      "notes": null
    }
  ],
  "executive_summary": "3-5 sentences for management",
  "total_risk_reduction": "~XX%"
}
Sort by priority descending. Return ONLY the JSON."""

SYSTEM_PROMPT_NARRATOR = """You are a cybersecurity consultant writing an audit report.
For each component produce ONLY valid JSON:
{"narratives":[{"purl":"...","technical":"2-3 sentences: CVE, attack vector, impact","management":"1-2 sentences: business risk, urgency"}]}"""

def _call_llm(system_prompt: str, user_content: str) -> str:
    if settings.GEMINI_API_KEY:
        try:
            import google.generativeai as genai
            logger.info("LLM: Gemini %s", settings.GEMINI_MODEL)
            genai.configure(api_key=settings.GEMINI_API_KEY)
            model = genai.GenerativeModel(
                model_name=settings.GEMINI_MODEL,
                system_instruction=system_prompt,
            )
            resp = model.generate_content(
                user_content,
                generation_config=genai.GenerationConfig(max_output_tokens=settings.LLM_MAX_TOKENS, temperature=0.2),
            )
            return resp.text
        except Exception as e:
            logger.error("Gemini failed: %s", e)

    if settings.ANTHROPIC_API_KEY:
        try:
            import anthropic
            logger.info("LLM: Anthropic %s", settings.LLM_MODEL)
            client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
            msg = client.messages.create(
                model=settings.LLM_MODEL, max_tokens=settings.LLM_MAX_TOKENS,
                system=system_prompt, messages=[{"role":"user","content":user_content}],
            )
            return msg.content[0].text
        except Exception as e:
            logger.error("Anthropic failed: %s", e)

    raise RuntimeError("No LLM key configured. Set GEMINI_API_KEY in .env")

async def generate_update_plan(components: list[Component]) -> dict:
    risky = sorted([c for c in components if c.scores.global_score > 20],
                   key=lambda c: c.scores.global_score, reverse=True)[:settings.MAX_COMPONENTS_FOR_LLM]
    if not risky:
        return {"updates":[],"executive_summary":"No significant risks detected.","total_risk_reduction":"0%"}
    context = _build_context(risky)
    for attempt in range(3):
        try:
            raw  = _call_llm(SYSTEM_PROMPT_PLANNER, context)
            plan = _parse_json(raw)
            if plan and "updates" in plan:
                logger.info("Plan generated: %d items", len(plan["updates"]))
                return plan
        except Exception as e:
            logger.error("Attempt %d: %s", attempt+1, e)
    return _fallback(risky)

def _build_context(components: list[Component]) -> str:
    lines = ["Android dependency risk report.", f"{len(components)} risky components (score>20).\n"]
    for c in components:
        cves = ", ".join(v.id for v in c.vulnerabilities[:3])
        lines.append(f"- {c.name} | {c.version}→{c.latest_version or '?'} | score={c.scores.global_score} | CVE=[{cves or 'none'}] | licence={c.license.spdx_id if c.license else 'UNKNOWN'} | trackers={len(c.trackers)}")
    return "\n".join(lines)

def _fallback(components: list[Component]) -> dict:
    updates = []
    for c in components:
        p = "CRITICAL" if c.scores.global_score>=75 else "HIGH" if c.scores.global_score>=50 else "MEDIUM"
        top = max(c.vulnerabilities, key=lambda v: v.cvss_v3 or 0, default=None)
        reason = f"CVE {top.id} (CVSS {top.cvss_v3})" if top else f"Score {c.scores.global_score}/100"
        updates.append({"purl":c.purl,"name":c.artifact,"current_version":c.version,
                        "recommended_version":c.latest_version or "latest","priority":p,
                        "main_reason":reason,"breaking_risk":"MODERATE","migration_effort":"2-4h",
                        "action":"UPDATE","replacement_suggestion":None,"notes":None})
    nc = sum(1 for u in updates if u["priority"]=="CRITICAL")
    nh = sum(1 for u in updates if u["priority"]=="HIGH")
    return {"updates":updates,"executive_summary":f"{nc} critical, {nh} high-priority updates required. Review and apply in priority order.","total_risk_reduction":"~60%","_fallback":True}

async def generate_risk_narratives(components: list[Component]) -> dict[str, dict]:
    top = [c for c in components if c.scores.risk_level in (RiskLevel.CRITICAL,RiskLevel.BLOCKING,RiskLevel.HIGH)][:15]
    if not top: return {}
    try:
        raw = _call_llm(SYSTEM_PROMPT_NARRATOR, "\n---\n".join(
            f"Component: {c.name} v{c.version}\nPURL: {c.purl}\nScore: {c.scores.global_score}/100\nCVEs: {'; '.join(v.id for v in c.vulnerabilities[:3]) or 'none'}"
            for c in top))
        result = _parse_json(raw)
        if result and "narratives" in result:
            return {n["purl"]: n for n in result["narratives"]}
    except Exception as e:
        logger.error("Narrator failed: %s", e)
    return {}

def _parse_json(text: str) -> Optional[dict]:
    cleaned = re.sub(r"```(?:json)?\s*","",text).strip().rstrip("`").strip()
    try: return json.loads(cleaned)
    except: return None
