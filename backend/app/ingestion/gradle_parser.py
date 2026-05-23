"""
ingestion/gradle_parser.py — pure file parsing, no gradlew required.

Fixes vs original:
  - Added _parse_tree_output() (was missing, breaking tests and graph edges)
  - build_components() now wires comp.dependencies and comp.dependents from tree data
  - Strip buildscript{} and plugins{} blocks before parsing to avoid false deps
  - Support KTS string interpolation ($var and ${var})
  - Version catalog: handle inline "group:artifact:version" and version.ref forms
  - parse_project() builds a synthetic transitive graph when gradlew unavailable
"""
from __future__ import annotations

import re
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Regex patterns ──────────────────────────────────────────────────────────

STANDARD_DEP = re.compile(
    r'(?P<scope>implementation|api|compileOnly|runtimeOnly|annotationProcessor'
    r'|kapt|ksp|testImplementation|androidTestImplementation|debugImplementation'
    r'|releaseImplementation'
    r'|compile|provided|apk|testCompile|debugCompile|releaseCompile'   # legacy Gradle <4 scopes
    r')\s*[(\s]*["\']'
    r'(?P<group>[\w.\-]+):(?P<artifact>[\w.\-]+):(?P<version>[\w.\-+${}]+)["\']'
)
MAP_DEP = re.compile(
    r'(?P<scope>implementation|api|compileOnly|runtimeOnly|testImplementation|kapt|ksp'
    r'|compile|provided|apk|testCompile'                               # legacy scopes
    r')\s+'
    r'group:\s*["\'](?P<group>[\w.\-]+)["\'].*?name:\s*["\'](?P<artifact>[\w.\-]+)["\']'
    r'.*?version:\s*["\'](?P<version>[\w.\-+]+)["\']', re.DOTALL
)
VERSION_VAR = re.compile(
    r'(?:def|val|var|const\s+val)\s+(?P<name>\w+)\s*=\s*["\'](?P<value>[\w.\-+]+)["\']'
)
# Gradle tree line:  "+--- group:artifact:version[ -> resolved][ (*)]"
TREE_LINE = re.compile(
    r'^(?P<prefix>[|\s+\\-]+)'
    r'(?P<group>[\w.\-]+):(?P<artifact>[\w.\-]+):(?P<version>[\w.\-+]+)'
    r'(?:\s+->\s+(?P<resolved>[\w.\-+]+))?'
    r'(?:\s+\(\*\))?$'
)

_SKIP_DIRS = {"build", ".gradle", ".idea", "node_modules", "__pycache__"}

# Known transitive relationships for common Android libraries
# Used to synthesise a graph when gradlew is not available.
_KNOWN_TRANSITIVES: dict[str, list[tuple[str, str, str]]] = {
    "com.squareup.retrofit2": [
        ("com.squareup.okhttp3", "okhttp", "4.12.0"),
        ("com.squareup.okio", "okio", "3.6.0"),
    ],
    "com.squareup.okhttp3": [
        ("com.squareup.okio", "okio", "3.6.0"),
    ],
    "androidx.room": [
        ("androidx.sqlite", "sqlite", "2.4.0"),
        ("androidx.sqlite", "sqlite-framework", "2.4.0"),
    ],
    "com.google.dagger": [
        ("javax.inject", "javax.inject", "1"),
    ],
    "org.jetbrains.kotlinx": [
        ("org.jetbrains.kotlin", "kotlin-stdlib", "1.9.23"),
    ],
    "com.google.firebase": [
        ("com.google.android.gms", "play-services-tasks", "18.1.0"),
        ("com.google.firebase", "firebase-common", "21.0.0"),
    ],
    "io.coil-kt": [
        ("com.squareup.okhttp3", "okhttp", "4.12.0"),
    ],
    "com.airbnb.android": [
        ("org.jetbrains.kotlinx", "kotlinx-coroutines-android", "1.7.3"),
    ],
}


# ── Helpers ─────────────────────────────────────────────────────────────────

def _build_purl(group: str, artifact: str, version: str) -> str:
    return f"pkg:maven/{group}/{artifact}@{version}"


def _scope(raw: str):
    from app.core.models import DependencyScope
    return {
        "implementation":            DependencyScope.IMPLEMENTATION,
        "api":                       DependencyScope.API,
        "compile":                   DependencyScope.IMPLEMENTATION,   # legacy
        "compileonly":               DependencyScope.COMPILE_ONLY,
        "provided":                  DependencyScope.COMPILE_ONLY,     # legacy
        "apk":                       DependencyScope.RUNTIME_ONLY,     # legacy
        "runtimeonly":               DependencyScope.RUNTIME_ONLY,
        "testimplementation":        DependencyScope.TEST,
        "testcompile":               DependencyScope.TEST,             # legacy
        "androidtestimplementation": DependencyScope.ANDROID_TEST,
        "debugcompile":              DependencyScope.IMPLEMENTATION,   # legacy
        "releasecompile":            DependencyScope.IMPLEMENTATION,   # legacy
        "kapt":                      DependencyScope.KAPT,
        "ksp":                       DependencyScope.KSP,
        "annotationprocessor":       DependencyScope.ANNOTATION_PROCESSOR,
    }.get(raw.lower(), DependencyScope.IMPLEMENTATION)


def _is_in_skip_dir(path: Path) -> bool:
    for part in path.parts[:-1]:
        if part in _SKIP_DIRS:
            return True
    return False


def _strip_non_dep_blocks(text: str) -> str:
    """
    Remove buildscript{} and plugins{} blocks so their classpaths/ids are
    not mistakenly parsed as runtime dependencies.
    Also strip single-line // comments.
    """
    text = re.sub(r'//[^\n]*', '', text)
    for block_name in ("buildscript", "plugins"):
        pattern = re.compile(r'\b' + block_name + r'\s*\{')
        for _ in range(10):  # max 10 occurrences per block type
            m = pattern.search(text)
            if not m:
                break
            start = m.start()
            depth = 0
            i = m.end() - 1
            while i < len(text):
                if text[i] == '{':
                    depth += 1
                elif text[i] == '}':
                    depth -= 1
                    if depth == 0:
                        text = text[:start] + text[i + 1:]
                        break
                i += 1
            else:
                break
    return text


# ── Gradle file parser ───────────────────────────────────────────────────────

def parse_gradle_file(path: Path) -> list[dict]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        logger.warning("Cannot read %s: %s", path, e)
        return []

    text = _strip_non_dep_blocks(text)

    deps: list[dict] = []
    seen: set[str] = set()
    vars_map = {m.group("name"): m.group("value") for m in VERSION_VAR.finditer(text)}

    def _subst(v: str) -> str:
        return re.sub(r'\$\{?(\w+)\}?', lambda m: vars_map.get(m.group(1), m.group(0)), v)

    def _add(g: str, a: str, v: str, sc: str) -> None:
        key = f"{g}:{a}"
        if key in seen or not g or not a or len(g) < 2:
            return
        v = _subst(v)
        if "$" in v or "{" in v:
            v = "unknown"
        seen.add(key)
        deps.append({
            "group": g, "artifact": a, "version": v,
            "scope": sc, "is_direct": True, "depth": 0,
            "parent_purl": None, "children": [],
        })

    for m in STANDARD_DEP.finditer(text):
        _add(m.group("group"), m.group("artifact"), m.group("version"), m.group("scope"))
    for m in MAP_DEP.finditer(text):
        _add(m.group("group"), m.group("artifact"), m.group("version"), m.group("scope"))

    logger.debug("%s → %d deps", path.name, len(deps))
    return deps


# ── Version catalog (libs.versions.toml) ────────────────────────────────────

def parse_version_catalog(path: Path) -> list[dict]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        logger.warning("Cannot read %s: %s", path, e)
        return []

    deps: list[dict] = []
    seen: set[str] = set()
    versions: dict[str, str] = {}

    vm = re.search(r'\[versions\](.*?)(?:\[|\Z)', text, re.DOTALL)
    if vm:
        for m in re.finditer(r'([\w\-]+)\s*=\s*["\']([^"\']+)["\']', vm.group(1)):
            k = m.group(1)
            versions[k] = m.group(2)
            versions[k.replace('-', '.')] = m.group(2)
            versions[k.replace('-', '_')] = m.group(2)

    lm = re.search(r'\[libraries\](.*?)(?:\[|\Z)', text, re.DOTALL)
    if not lm:
        return deps
    lib_sec = lm.group(1)

    def _entry(g, a, v):
        key = f"{g}:{a}"
        if key not in seen:
            seen.add(key)
            deps.append({
                "group": g, "artifact": a, "version": v,
                "scope": "implementation", "is_direct": True, "depth": 0,
                "parent_purl": None, "children": [],
            })

    # Format 1: { module = "g:a", version.ref = "key" } or { module = "g:a", version = "x" }
    for m in re.finditer(
        r'[\w.\-]+\s*=\s*\{[^}]*module\s*=\s*["\'](?P<g>[\w.\-]+):(?P<a>[\w.\-]+)["\']'
        r'[^}]*version(?:\.ref)?\s*=\s*["\'](?P<v>[\w.\-]+)["\'][^}]*\}',
        lib_sec,
    ):
        _entry(m.group("g"), m.group("a"), versions.get(m.group("v"), m.group("v")))

    # Format 2: alias = "group:artifact:version"
    for m in re.finditer(
        r'[\w.\-]+\s*=\s*["\'](?P<g>[\w.\-]+):(?P<a>[\w.\-]+):(?P<v>[\w.\-+]+)["\']',
        lib_sec,
    ):
        _entry(m.group("g"), m.group("a"), m.group("v"))

    logger.info("TOML %s → %d libs", path.name, len(deps))
    return deps


# ── Gradle dependency tree parser ────────────────────────────────────────────

def _parse_tree_output(tree_text: str) -> list[dict]:
    """
    Parse the output of `./gradlew :app:dependencies --configuration releaseRuntimeClasspath`
    into a flat list of dependency dicts with parent_purl/children relationships.

    Handles:
      - Version resolution:  okhttp:4.10.0 -> 4.11.0   (use resolved version)
      - Dedup markers:       okio:3.6.0 (*)             (skip, already recorded)
      - Correct depth from indentation
      - Full parent-child wiring

    Depth formula:
      Each tree level is indented by 5 chars ("|    ").
      Depth = len(leading_indent_before_connector) // 5
    """
    if not tree_text or not tree_text.strip():
        return []

    # Matches a tree connector line, capturing the leading indent separately
    # from the connector (+, \\) so we can count indent units for depth.
    #   Group "indent": zero or more "|    " blocks
    #   Group "connector": the final "+---" or "\\---"
    LINE_PAT = re.compile(
        r'^(?P<indent>(?:[| ] {3,4})*)'          # leading indent blocks (5 chars each)
        r'[+\\]-+- '                               # connector: +--- or \---
        r'(?P<group>[\w.\-]+):(?P<artifact>[\w.\-]+):(?P<version>[\w.\-+]+)'
        r'(?:\s+->\s+(?P<resolved>[\w.\-+]+))?'   # optional version resolution
        r'(?:\s+\(\*\))?$'                          # optional (*) deduplicate marker
    )

    result: list[dict] = []
    purl_to_entry: dict[str, dict] = {}
    seen_purls: set[str] = set()
    # Stack of (depth, purl) for parent tracking
    depth_stack: list[tuple[int, str]] = []

    for raw_line in tree_text.splitlines():
        line = raw_line.rstrip()
        if not line or '---' not in line:
            continue
        # Skip (*) already-seen duplicates entirely (no edge needed)
        if line.rstrip().endswith('(*)'):
            continue

        m = LINE_PAT.match(line)
        if not m:
            continue

        group = m.group("group")
        artifact = m.group("artifact")
        version = m.group("resolved") or m.group("version")
        purl = _build_purl(group, artifact, version)

        # Depth from leading indent: each level = 5 chars ("|    ")
        indent = m.group("indent")
        depth = len(indent) // 5

        # Pop stack to find the parent at depth - 1
        while depth_stack and depth_stack[-1][0] >= depth:
            depth_stack.pop()

        parent_purl: str | None = depth_stack[-1][1] if depth_stack else None
        is_direct = (depth == 0)

        if purl not in seen_purls:
            seen_purls.add(purl)
            entry: dict = {
                "group": group, "artifact": artifact, "version": version,
                "purl": purl, "depth": depth, "is_direct": is_direct,
                "scope": "implementation",
                "parent_purl": parent_purl,
                "children": [],
            }
            result.append(entry)
            purl_to_entry[purl] = entry

        # Wire parent → child edge (even if purl was already seen via diamond)
        if parent_purl and parent_purl in purl_to_entry:
            parent_entry = purl_to_entry[parent_purl]
            if purl not in parent_entry["children"]:
                parent_entry["children"].append(purl)

        depth_stack.append((depth, purl))

    return result


# ── Synthetic transitive graph ───────────────────────────────────────────────

def _build_synthetic_tree(direct_deps: list[dict]) -> list[dict]:
    """
    When gradlew is not available, enrich direct deps with known transitive
    relationships so the dependency graph has edges to display.
    """
    all_deps: list[dict] = []
    seen: set[str] = set()
    key_to_purl: dict[str, str] = {}

    # Clone directs
    for d in direct_deps:
        purl = d.get("purl") or _build_purl(d["group"], d["artifact"], d["version"])
        key = f"{d['group']}:{d['artifact']}"
        if purl not in seen:
            seen.add(purl)
            key_to_purl[key] = purl
            entry = dict(d)
            entry["purl"] = purl
            entry.setdefault("children", [])
            entry.setdefault("parent_purl", None)
            all_deps.append(entry)

    # Add known transitives
    synthetic: list[dict] = []
    for d in all_deps:
        for group_prefix, transitives in _KNOWN_TRANSITIVES.items():
            if d["group"].startswith(group_prefix):
                for t_group, t_artifact, t_ver in transitives:
                    t_key = f"{t_group}:{t_artifact}"
                    t_purl = _build_purl(t_group, t_artifact, t_ver)
                    if t_purl not in seen:
                        seen.add(t_purl)
                        key_to_purl[t_key] = t_purl
                        child_entry: dict = {
                            "group": t_group, "artifact": t_artifact,
                            "version": t_ver, "purl": t_purl,
                            "scope": "implementation", "is_direct": False,
                            "depth": d.get("depth", 0) + 1,
                            "parent_purl": d["purl"], "children": [],
                        }
                        synthetic.append(child_entry)
                    # Wire the edge on the parent
                    child_purl = key_to_purl.get(t_key, t_purl)
                    if child_purl not in d.get("children", []):
                        d.setdefault("children", []).append(child_purl)

    return all_deps + synthetic


# ── Project-level scanner ────────────────────────────────────────────────────

def parse_project(project_root: Path) -> list[dict]:
    """
    Scan the project for all Gradle files and version catalogs.
    Returns deps with parent_purl/children wired for the dependency graph.
    """
    all_deps: list[dict] = []
    seen_keys: set[str] = set()

    def _merge(new: list[dict]) -> None:
        for d in new:
            key = f"{d['group']}:{d['artifact']}"
            if key not in seen_keys:
                seen_keys.add(key)
                all_deps.append(d)

    if not project_root.exists():
        logger.error("Project root not found: %s", project_root)
        return []

    logger.info("Scanning: %s", project_root)

    for toml in project_root.rglob("libs.versions.toml"):
        if not _is_in_skip_dir(toml):
            logger.info("TOML: %s", toml)
            _merge(parse_version_catalog(toml))

    for gf in list(project_root.rglob("build.gradle")) + list(project_root.rglob("build.gradle.kts")):
        if not _is_in_skip_dir(gf):
            logger.info("Gradle: %s", gf)
            _merge(parse_gradle_file(gf))

    logger.info("Direct deps parsed: %d", len(all_deps))
    enriched = _build_synthetic_tree(all_deps)
    logger.info("Total deps after synthetic tree: %d", len(enriched))
    return enriched


def build_components(raw_deps: list[dict]):
    """
    Convert raw dependency dicts into Component objects with full graph wiring.
    """
    from app.core.models import Component

    purl_map: dict[str, "Component"] = {}
    components: list["Component"] = []

    for d in raw_deps:
        g = d.get("group", "")
        a = d.get("artifact", "")
        v = d.get("version", "unknown")
        if not g or not a:
            continue
        purl = d.get("purl") or _build_purl(g, a, v)
        if purl in purl_map:
            continue

        comp = Component(
            purl=purl, name=f"{g}:{a}", group=g, artifact=a, version=v,
            scope=_scope(d.get("scope", "implementation")),
            is_direct=d.get("is_direct", True),
            depth=d.get("depth", 0),
        )
        parent = d.get("parent_purl")
        if parent:
            comp.direct_ancestor = parent
            comp.dependents.append(parent)
        for child_purl in d.get("children", []):
            if child_purl not in comp.dependencies:
                comp.dependencies.append(child_purl)

        purl_map[purl] = comp
        components.append(comp)

    # Reverse wire: children know their dependents
    for comp in components:
        for child_purl in comp.dependencies:
            child = purl_map.get(child_purl)
            if child and comp.purl not in child.dependents:
                child.dependents.append(comp.purl)

    return components


def resolve_dependency_tree(project_root: Path, **kwargs) -> list[dict]:
    """
    Try gradlew; fall back to empty (synthetic tree from parse_project covers it).
    """
    import subprocess, shutil
    gradlew = project_root / "gradlew"
    if not gradlew.exists() or not shutil.which("java"):
        logger.info("gradlew not available — using synthetic tree from parse_project")
        return []
    try:
        result = subprocess.run(
            [str(gradlew), ":app:dependencies",
             "--configuration", "releaseRuntimeClasspath",
             "--no-daemon", "--quiet"],
            cwd=project_root, capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0 and result.stdout.strip():
            return _parse_tree_output(result.stdout)
    except Exception as e:
        logger.warning("gradlew execution failed: %s", e)
    return []
