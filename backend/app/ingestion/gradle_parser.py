"""
ingestion/gradle_parser.py — pure file parsing, no gradlew
"""
from __future__ import annotations
import re, logging
from pathlib import Path

logger = logging.getLogger(__name__)

STANDARD_DEP = re.compile(
    r'(?P<scope>implementation|api|compileOnly|runtimeOnly|annotationProcessor'
    r'|kapt|ksp|testImplementation|androidTestImplementation|debugImplementation'
    r'|releaseImplementation)\s*[(\s]*["\']'
    r'(?P<group>[\w.\-]+):(?P<artifact>[\w.\-]+):(?P<version>[\w.\-+${}]+)["\']'
)
MAP_DEP = re.compile(
    r'(?P<scope>implementation|api|compileOnly|runtimeOnly|testImplementation|kapt|ksp)\s+'
    r'group:\s*["\'](?P<group>[\w.\-]+)["\'].*?name:\s*["\'](?P<artifact>[\w.\-]+)["\']'
    r'.*?version:\s*["\'](?P<version>[\w.\-+]+)["\']', re.DOTALL
)
VERSION_VAR = re.compile(r'(?:def|val|var|const val)\s+(?P<name>\w+)\s*=\s*["\'](?P<value>[\w.\-+]+)["\']')
_SKIP_DIRS = {"build", ".gradle", ".idea", "node_modules", "__pycache__"}

def _build_purl(group, artifact, version):
    return f"pkg:maven/{group}/{artifact}@{version}"

def _scope(raw):
    from app.core.models import DependencyScope
    return {"implementation": DependencyScope.IMPLEMENTATION, "api": DependencyScope.API,
            "compileonly": DependencyScope.COMPILE_ONLY, "runtimeonly": DependencyScope.RUNTIME_ONLY,
            "testimplementation": DependencyScope.TEST, "androidtestimplementation": DependencyScope.ANDROID_TEST,
            "kapt": DependencyScope.KAPT, "ksp": DependencyScope.KSP,
            "annotationprocessor": DependencyScope.ANNOTATION_PROCESSOR,
            }.get(raw.lower(), DependencyScope.IMPLEMENTATION)

def _is_in_skip_dir(path: Path) -> bool:
    """Skip only if a PARENT directory (not the file itself) is a generated dir."""
    for part in path.parts[:-1]:  # exclude filename
        if part in _SKIP_DIRS:
            return True
    return False

def parse_gradle_file(path: Path) -> list[dict]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        logger.warning("Cannot read %s: %s", path, e); return []
    deps, seen = [], set()
    vars_map = {m.group("name"): m.group("value") for m in VERSION_VAR.finditer(text)}
    def _subst(v):
        return re.sub(r'\$\{?(\w+)\}?', lambda m: vars_map.get(m.group(1), m.group(0)), v)
    def _add(g, a, v, sc):
        key = f"{g}:{a}"
        if key in seen or not g or not a or len(g) < 2: return
        v = _subst(v)
        if "$" in v or "{" in v: v = "unknown"
        seen.add(key)
        deps.append({"group": g, "artifact": a, "version": v, "scope": sc, "is_direct": True, "depth": 0})
    for m in STANDARD_DEP.finditer(text): _add(m.group("group"), m.group("artifact"), m.group("version"), m.group("scope"))
    for m in MAP_DEP.finditer(text): _add(m.group("group"), m.group("artifact"), m.group("version"), m.group("scope"))
    logger.debug("%s → %d deps", path.name, len(deps)); return deps

def parse_version_catalog(path: Path) -> list[dict]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        logger.warning("Cannot read %s: %s", path, e); return []
    deps, seen = [], set()
    versions = {}
    vm = re.search(r'\[versions\](.*?)(?:\[|\Z)', text, re.DOTALL)
    if vm:
        for m in re.finditer(r'([\w-]+)\s*=\s*["\']([^"\']+)["\']', vm.group(1)):
            k = m.group(1); versions[k] = m.group(2)
            versions[k.replace('-','.')] = m.group(2); versions[k.replace('-','_')] = m.group(2)
    lm = re.search(r'\[libraries\](.*?)(?:\[|\Z)', text, re.DOTALL)
    if not lm: return deps
    lib_sec = lm.group(1)
    for m in re.finditer(
        r'[\w.\-]+\s*=\s*\{[^}]*module\s*=\s*["\'](?P<g>[\w.\-]+):(?P<a>[\w.\-]+)["\']'
        r'[^}]*version(?:\.ref)?\s*=\s*["\'](?P<v>[\w.\-]+)["\'][^}]*\}', lib_sec):
        key = f"{m.group('g')}:{m.group('a')}"
        if key not in seen:
            seen.add(key); deps.append({"group": m.group("g"), "artifact": m.group("a"),
                "version": versions.get(m.group("v"), m.group("v")), "scope": "implementation", "is_direct": True, "depth": 0})
    for m in re.finditer(r'[\w.\-]+\s*=\s*["\'](?P<g>[\w.\-]+):(?P<a>[\w.\-]+):(?P<v>[\w.\-]+)["\']', lib_sec):
        key = f"{m.group('g')}:{m.group('a')}"
        if key not in seen:
            seen.add(key); deps.append({"group": m.group("g"), "artifact": m.group("a"),
                "version": m.group("v"), "scope": "implementation", "is_direct": True, "depth": 0})
    logger.info("TOML %s → %d libs", path.name, len(deps)); return deps

def parse_project(project_root: Path) -> list[dict]:
    all_deps, seen_keys = [], set()
    def _merge(new):
        for d in new:
            key = f"{d['group']}:{d['artifact']}"
            if key not in seen_keys: seen_keys.add(key); all_deps.append(d)
    if not project_root.exists():
        logger.error("Project root not found: %s", project_root); return []
    logger.info("Scanning: %s", project_root)
    for toml in project_root.rglob("libs.versions.toml"):
        if not _is_in_skip_dir(toml): logger.info("TOML: %s", toml); _merge(parse_version_catalog(toml))
    for gf in list(project_root.rglob("build.gradle")) + list(project_root.rglob("build.gradle.kts")):
        if not _is_in_skip_dir(gf): logger.info("Gradle: %s", gf); _merge(parse_gradle_file(gf))
    logger.info("Total deps: %d", len(all_deps)); return all_deps

def build_components(raw_deps):
    from app.core.models import Component
    components = []
    for d in raw_deps:
        g, a, v = d.get("group",""), d.get("artifact",""), d.get("version","unknown")
        if not g or not a: continue
        comp = Component(purl=_build_purl(g,a,v), name=f"{g}:{a}", group=g, artifact=a, version=v,
                         scope=_scope(d.get("scope","implementation")),
                         is_direct=d.get("is_direct",True), depth=d.get("depth",0))
        if d.get("parent_purl"): comp.direct_ancestor=d["parent_purl"]; comp.dependents.append(d["parent_purl"])
        if d.get("children"): comp.dependencies.extend(d["children"])
        components.append(comp)
    return components

def resolve_dependency_tree(project_root, **kwargs):
    """No-op: gradlew not available in Docker."""
    return []
