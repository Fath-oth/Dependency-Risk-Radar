"""
ingestion/apk_analyzer.py

Multi-strategy APK component detection:
  1. androguard class names (works on unobfuscated APKs)
  2. META-INF/MANIFEST.MF  — lists every JAR with name + version
  3. Raw string scan of DEX/APK  — finds SDK names even in R8-shrunk apps
  4. Known file/folder paths inside APK  — e.g. assets/crashlytics-build.properties
  5. build-data.properties / version files bundled by SDKs
"""
from __future__ import annotations

import hashlib
import logging
import re
import zipfile
from pathlib import Path

from app.core.models import Component, DependencyScope

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# Master SDK database
# Each entry: prefix/pattern -> {group, artifact}
# Covers class prefixes, asset paths, string signatures
# ─────────────────────────────────────────────────────────────
KNOWN_SDK_PACKAGES: dict[str, dict] = {
    # Networking
    "com.squareup.retrofit2":      {"group": "com.squareup.retrofit2",       "artifact": "retrofit"},
    "retrofit2":                   {"group": "com.squareup.retrofit2",       "artifact": "retrofit"},
    "com.squareup.okhttp3":        {"group": "com.squareup.okhttp3",         "artifact": "okhttp"},
    "com.squareup.okhttp":         {"group": "com.squareup.okhttp",          "artifact": "okhttp"},
    "com.squareup.okio":           {"group": "com.squareup.okio",            "artifact": "okio"},
    "okhttp3":                     {"group": "com.squareup.okhttp3",         "artifact": "okhttp"},
    # Serialization
    "com.google.gson":             {"group": "com.google.code.gson",         "artifact": "gson"},
    "com.google.code.gson":        {"group": "com.google.code.gson",         "artifact": "gson"},
    "com.fasterxml.jackson":       {"group": "com.fasterxml.jackson.core",   "artifact": "jackson-databind"},
    "org.yaml.snakeyaml":          {"group": "org.yaml",                     "artifact": "snakeyaml"},
    # Firebase / Google
    "com.google.firebase":         {"group": "com.google.firebase",          "artifact": "firebase-bom"},
    "com.google.android.gms":      {"group": "com.google.android.gms",       "artifact": "play-services-base"},
    "com.google.android.material": {"group": "com.google.android.material",  "artifact": "material"},
    "com.google.zxing":            {"group": "com.google.zxing",             "artifact": "core"},
    # AndroidX
    "androidx.appcompat":          {"group": "androidx.appcompat",           "artifact": "appcompat"},
    "androidx.core":               {"group": "androidx.core",                "artifact": "core-ktx"},
    "androidx.lifecycle":          {"group": "androidx.lifecycle",           "artifact": "lifecycle-runtime"},
    "androidx.room":               {"group": "androidx.room",                "artifact": "room-runtime"},
    "androidx.work":               {"group": "androidx.work",                "artifact": "work-runtime"},
    "androidx.navigation":         {"group": "androidx.navigation",          "artifact": "navigation-fragment"},
    "androidx.compose":            {"group": "androidx.compose.ui",          "artifact": "ui"},
    "androidx.recyclerview":       {"group": "androidx.recyclerview",        "artifact": "recyclerview"},
    "androidx.fragment":           {"group": "androidx.fragment",            "artifact": "fragment"},
    "androidx.cardview":           {"group": "androidx.cardview",            "artifact": "cardview"},
    "androidx.constraintlayout":   {"group": "androidx.constraintlayout",    "artifact": "constraintlayout"},
    "androidx.viewpager":          {"group": "androidx.viewpager",           "artifact": "viewpager"},
    # Support lib (pre-AndroidX)
    "android.support.v7":          {"group": "com.android.support",          "artifact": "appcompat-v7"},
    "android.support.v4":          {"group": "com.android.support",          "artifact": "support-v4"},
    "android.support.design":      {"group": "com.android.support",          "artifact": "design"},
    "android.support.constraint":  {"group": "com.android.support.constraint","artifact": "constraint-layout"},
    "android.arch.lifecycle":      {"group": "android.arch.lifecycle",       "artifact": "runtime"},
    "android.arch.persistence":    {"group": "android.arch.persistence.room","artifact": "runtime"},
    # Kotlin
    "org.jetbrains.kotlin":        {"group": "org.jetbrains.kotlin",         "artifact": "kotlin-stdlib"},
    "kotlin":                      {"group": "org.jetbrains.kotlin",         "artifact": "kotlin-stdlib"},
    "kotlinx.coroutines":          {"group": "org.jetbrains.kotlinx",        "artifact": "kotlinx-coroutines-android"},
    "kotlinx.serialization":       {"group": "org.jetbrains.kotlinx",        "artifact": "kotlinx-serialization-json"},
    # Rx
    "io.reactivex.rxjava3":        {"group": "io.reactivex.rxjava3",         "artifact": "rxjava"},
    "io.reactivex.rxjava2":        {"group": "io.reactivex.rxjava2",         "artifact": "rxjava"},
    "io.reactivex":                {"group": "io.reactivex",                 "artifact": "rxjava"},
    # Image loading
    "com.bumptech.glide":          {"group": "com.github.bumptech.glide",    "artifact": "glide"},
    "com.facebook.fresco":         {"group": "com.facebook.fresco",          "artifact": "fresco"},
    "com.squareup.picasso":        {"group": "com.squareup.picasso",         "artifact": "picasso"},
    "io.coil":                     {"group": "io.coil-kt",                   "artifact": "coil"},
    # DI
    "com.google.dagger":           {"group": "com.google.dagger",            "artifact": "dagger"},
    "dagger":                      {"group": "com.google.dagger",            "artifact": "dagger"},
    "org.koin":                    {"group": "io.insert-koin",               "artifact": "koin-core"},
    # DB
    "net.sqlcipher":               {"group": "net.zetetic",                  "artifact": "android-database-sqlcipher"},
    "io.realm":                    {"group": "io.realm",                     "artifact": "realm-android"},
    "org.greenrobot":              {"group": "org.greenrobot",               "artifact": "eventbus"},
    # Security / Crypto
    "org.conscrypt":               {"group": "org.conscrypt",                "artifact": "conscrypt-android"},
    "org.bouncycastle":            {"group": "org.bouncycastle",             "artifact": "bcprov-jdk15on"},
    # Analytics
    "com.amplitude":               {"group": "com.amplitude",                "artifact": "analytics-android"},
    "com.mixpanel.android":        {"group": "com.mixpanel.android",         "artifact": "mixpanel-android"},
    "com.appsflyer":               {"group": "com.appsflyer",                "artifact": "af-android-sdk"},
    "com.adjust.sdk":              {"group": "com.adjust.sdk",               "artifact": "adjust-android"},
    "com.segment.analytics":       {"group": "com.segment.analytics.android","artifact": "analytics"},
    "com.clevertap.android":       {"group": "com.clevertap.android",        "artifact": "clevertap-android-sdk"},
    # Error reporting
    "io.sentry":                   {"group": "io.sentry",                    "artifact": "sentry-android"},
    "com.bugsnag.android":         {"group": "com.bugsnag.android",          "artifact": "bugsnag-android"},
    "com.crashlytics.sdk":         {"group": "com.crashlytics.sdk.android",  "artifact": "crashlytics"},
    "com.google.firebase.crashlytics": {"group": "com.google.firebase",      "artifact": "firebase-crashlytics"},
    # Ads
    "com.facebook.ads":            {"group": "com.facebook.android",         "artifact": "audience-network-sdk"},
    "com.unity3d.ads":             {"group": "com.unity3d.ads",              "artifact": "unity-ads"},
    # Push
    "com.onesignal":               {"group": "com.onesignal",                "artifact": "OneSignal"},
    "io.intercom.android":         {"group": "io.intercom.android",          "artifact": "intercom-sdk-android"},
    # Social
    "com.facebook.android":        {"group": "com.facebook.android",         "artifact": "facebook-android-sdk"},
    "com.twitter.sdk":             {"group": "com.twitter.sdk.android",      "artifact": "twitter"},
    # Maps
    "com.mapbox":                  {"group": "com.mapbox.maps",              "artifact": "android"},
    # Vulnerable libs
    "org.apache.log4j":            {"group": "log4j",                        "artifact": "log4j"},
    "org.apache.commons":          {"group": "org.apache.commons",           "artifact": "commons-lang3"},
    "com.thoughtworks.xstream":    {"group": "com.thoughtworks.xstream",     "artifact": "xstream"},
    "com.esotericsoftware":        {"group": "com.esotericsoftware",         "artifact": "kryo"},
    # Volley
    "com.android.volley":          {"group": "com.android.volley",           "artifact": "volley"},
    # Moshi
    "com.squareup.moshi":          {"group": "com.squareup.moshi",           "artifact": "moshi"},
}

# String signatures found in DEX/APK bytes for obfuscated apps
# These strings are embedded by SDKs and survive R8 shrinking
STRING_SIGNATURES: list[tuple[str, str, str]] = [
    # (search_string, group, artifact)
    ("OkHttp",              "com.squareup.okhttp3",        "okhttp"),
    ("okhttp3",             "com.squareup.okhttp3",        "okhttp"),
    ("Retrofit",            "com.squareup.retrofit2",      "retrofit"),
    ("GsonBuilder",         "com.google.code.gson",        "gson"),
    ("JsonObject",          "com.google.code.gson",        "gson"),
    ("Glide",               "com.github.bumptech.glide",   "glide"),
    ("RequestManager",      "com.github.bumptech.glide",   "glide"),
    ("Picasso",             "com.squareup.picasso",        "picasso"),
    ("firebase",            "com.google.firebase",         "firebase-bom"),
    ("FirebaseApp",         "com.google.firebase",         "firebase-bom"),
    ("Crashlytics",         "com.crashlytics.sdk.android", "crashlytics"),
    ("SentryAndroid",       "io.sentry",                   "sentry-android"),
    ("BugsnagReporter",     "com.bugsnag.android",         "bugsnag-android"),
    ("OneSignal",           "com.onesignal",               "OneSignal"),
    ("AppsFlyer",           "com.appsflyer",               "af-android-sdk"),
    ("amplitude",           "com.amplitude",               "analytics-android"),
    ("Mixpanel",            "com.mixpanel.android",        "mixpanel-android"),
    ("RxJava",              "io.reactivex.rxjava3",        "rxjava"),
    ("Observable",          "io.reactivex.rxjava3",        "rxjava"),
    ("SqlCipher",           "net.zetetic",                 "android-database-sqlcipher"),
    ("Realm",               "io.realm",                    "realm-android"),
    ("Dagger",              "com.google.dagger",           "dagger"),
    ("EventBus",            "org.greenrobot",              "eventbus"),
    ("Koin",                "io.insert-koin",              "koin-core"),
    ("LeakCanary",          "com.squareup.leakcanary",     "leakcanary-android"),
    ("Timber",              "com.jakewharton.timber",      "timber"),
    ("Moshi",               "com.squareup.moshi",          "moshi"),
    ("Volley",              "com.android.volley",          "volley"),
    ("FacebookSdk",         "com.facebook.android",        "facebook-android-sdk"),
    ("AdjustSdk",           "com.adjust.sdk",              "adjust-android"),
    ("BouncyCastle",        "org.bouncycastle",            "bcprov-jdk15on"),
    ("conscrypt",           "org.conscrypt",               "conscrypt-android"),
    ("snakeyaml",           "org.yaml",                    "snakeyaml"),
    ("XStream",             "com.thoughtworks.xstream",    "xstream"),
    ("log4j",               "log4j",                       "log4j"),
]

# Asset/resource paths that SDKs bundle inside APKs
ASSET_PATH_SIGNATURES: list[tuple[str, str, str]] = [
    ("assets/crashlytics-build.properties", "com.crashlytics.sdk.android", "crashlytics"),
    ("assets/com.google.firebase",          "com.google.firebase",          "firebase-bom"),
    ("assets/google-services.json",         "com.google.firebase",          "firebase-bom"),
    ("META-INF/services/retrofit2",         "com.squareup.retrofit2",       "retrofit"),
    ("META-INF/services/okhttp3",           "com.squareup.okhttp3",         "okhttp"),
    ("META-INF/glide",                      "com.github.bumptech.glide",    "glide"),
    ("kotlin/",                             "org.jetbrains.kotlin",         "kotlin-stdlib"),
    ("okhttp3/",                            "com.squareup.okhttp3",         "okhttp"),
]


# ─────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────

def analyze_apk(apk_path: Path) -> dict:
    result = {
        "sha256": _sha256(apk_path),
        "metadata": {},
        "permissions": [],
        "class_packages": [],
        "native_libs": [],
        "components": [],
        "strategy_used": "none",
        "errors": [],
    }

    found_components: dict[str, dict] = {}  # key -> component dict

    # ── Strategy 1: androguard (class names) ──
    try:
        ag_result = _analyze_with_androguard(apk_path)
        result.update({k: v for k, v in ag_result.items() if v})
        result["strategy_used"] = ag_result.get("strategy_used", "androguard")
        for c in _infer_from_packages(set(ag_result.get("class_packages", []))):
            key = f"{c['group']}:{c['artifact']}"
            found_components[key] = c
        logger.info("Strategy 1 (androguard): found %d components", len(found_components))
    except Exception as e:
        result["errors"].append(f"androguard: {e}")
        logger.warning("Androguard failed: %s", e)

    # ── Strategy 2: META-INF/MANIFEST.MF (most reliable, has versions) ──
    try:
        manifest_comps = _parse_meta_inf(apk_path)
        for c in manifest_comps:
            key = f"{c['group']}:{c['artifact']}"
            if key not in found_components:
                found_components[key] = c
        logger.info("Strategy 2 (META-INF): found %d components", len(manifest_comps))
    except Exception as e:
        result["errors"].append(f"meta_inf: {e}")

    # ── Strategy 3: raw string scan (survives R8/ProGuard obfuscation) ──
    try:
        string_comps = _scan_strings(apk_path)
        for c in string_comps:
            key = f"{c['group']}:{c['artifact']}"
            if key not in found_components:
                found_components[key] = c
        logger.info("Strategy 3 (string scan): found %d new components", len(string_comps))
    except Exception as e:
        result["errors"].append(f"string_scan: {e}")

    # ── Strategy 4: asset/file path detection ──
    try:
        path_comps = _scan_asset_paths(apk_path)
        for c in path_comps:
            key = f"{c['group']}:{c['artifact']}"
            if key not in found_components:
                found_components[key] = c
        logger.info("Strategy 4 (asset paths): found %d new components", len(path_comps))
    except Exception as e:
        result["errors"].append(f"asset_paths: {e}")

    result["components"] = list(found_components.values())
    logger.info("Total components detected: %d", len(result["components"]))
    return result


# ─────────────────────────────────────────────────────────────
# Strategy 1: Androguard (tries 4.x then 3.x API)
# ─────────────────────────────────────────────────────────────

def _analyze_with_androguard(apk_path: Path) -> dict:
    result = {"class_packages": [], "metadata": {}, "permissions": [],
              "native_libs": [], "strategy_used": "androguard_failed"}
    try:
        from androguard.core.apk import APK
        from androguard.core.dex import DEX
        a = APK(str(apk_path))
        result["strategy_used"] = "androguard4"
        result["metadata"] = {
            "package_name":  a.get_package(),
            "version_name":  a.get_androidversion_name(),
            "version_code":  a.get_androidversion_code(),
            "min_sdk":       a.get_min_sdk_version(),
            "target_sdk":    a.get_target_sdk_version(),
        }
        result["permissions"] = list(a.get_permissions())
        packages: set[str] = set()
        for dex_bytes in a.get_all_dex():
            try:
                d = DEX(dex_bytes)
                for cls in d.get_classes():
                    _add_pkg(cls.get_name(), packages)
            except Exception:
                pass
        result["class_packages"] = sorted(packages)
        return result
    except Exception as e1:
        pass

    try:
        from androguard.misc import AnalyzeAPK
        a, _, dx = AnalyzeAPK(str(apk_path))
        result["strategy_used"] = "androguard3"
        result["metadata"] = {"package_name": a.get_package(), "version_name": a.get_androidversion_name()}
        result["permissions"] = list(a.get_permissions())
        packages = set()
        for cls in dx.get_classes():
            _add_pkg(cls.name, packages)
        result["class_packages"] = sorted(packages)
        return result
    except Exception as e2:
        raise RuntimeError(f"Both androguard APIs failed: {e2}")


def _add_pkg(descriptor: str, packages: set) -> None:
    name = descriptor.lstrip("L").rstrip(";").replace("/", ".")
    parts = name.split(".")
    if len(parts) >= 2:
        packages.add(".".join(parts[:2]))
    if len(parts) >= 3:
        packages.add(".".join(parts[:3]))
    if len(parts) >= 4:
        packages.add(".".join(parts[:4]))


def _infer_from_packages(packages: set[str]) -> list[dict]:
    found = []
    seen: set[str] = set()
    for prefix, meta in KNOWN_SDK_PACKAGES.items():
        key = f"{meta['group']}:{meta['artifact']}"
        if key in seen:
            continue
        # Match if any package equals prefix OR starts with prefix + "."
        if any(p == prefix or p.startswith(prefix + ".") or p.startswith(prefix + "/") for p in packages):
            found.append(_make_comp(meta["group"], meta["artifact"], "unknown"))
            seen.add(key)
    return found


# ─────────────────────────────────────────────────────────────
# Strategy 2: META-INF/MANIFEST.MF — reliable, has versions
# ─────────────────────────────────────────────────────────────

def _parse_meta_inf(apk_path: Path) -> list[dict]:
    """
    Parse META-INF/MANIFEST.MF which lists every JAR file merged into the APK.
    Format: Name: com/example/lib.jar\nImplementation-Title: ...\nImplementation-Version: 1.2.3
    """
    components = []
    seen: set[str] = set()

    with zipfile.ZipFile(apk_path, "r") as zf:
        names = zf.namelist()

        # Parse MANIFEST.MF
        if "META-INF/MANIFEST.MF" in names:
            try:
                manifest = zf.read("META-INF/MANIFEST.MF").decode("utf-8", errors="ignore")
                components.extend(_parse_manifest_mf(manifest, seen))
            except Exception as e:
                logger.debug("MANIFEST.MF parse error: %s", e)

        # Parse individual *.kotlin_module and build property files
        for name in names:
            if name.startswith("META-INF/") and name.endswith(".kotlin_module"):
                key = "org.jetbrains.kotlin:kotlin-stdlib"
                if key not in seen:
                    components.append(_make_comp("org.jetbrains.kotlin", "kotlin-stdlib", "unknown"))
                    seen.add(key)
            # Gradle metadata files embed group:artifact:version
            if name.endswith("build-data.properties") or name.endswith(".properties"):
                try:
                    content = zf.read(name).decode("utf-8", errors="ignore")
                    for c in _parse_properties_file(content, seen):
                        components.append(c)
                        seen.add(f"{c['group']}:{c['artifact']}")
                except Exception:
                    pass

    return components


def _parse_manifest_mf(content: str, seen: set) -> list[dict]:
    """Extract library info from MANIFEST.MF sections."""
    components = []
    # Split into sections (blank-line separated)
    sections = re.split(r'\r?\n\r?\n', content)
    for section in sections:
        name_match    = re.search(r'^Name:\s*(.+)$',                     section, re.M)
        title_match   = re.search(r'^Implementation-Title:\s*(.+)$',     section, re.M)
        version_match = re.search(r'^Implementation-Version:\s*(.+)$',   section, re.M)
        bundle_match  = re.search(r'^Bundle-SymbolicName:\s*(.+)$',      section, re.M)
        bversion_match= re.search(r'^Bundle-Version:\s*(.+)$',           section, re.M)

        version = "unknown"
        if version_match:
            version = version_match.group(1).strip()
        elif bversion_match:
            version = bversion_match.group(1).strip()

        title = ""
        if title_match:
            title = title_match.group(1).strip()
        elif bundle_match:
            title = bundle_match.group(1).strip()
        elif name_match:
            title = name_match.group(1).strip().replace("/", ".").replace(".jar", "")

        if title:
            comp = _title_to_component(title, version, seen)
            if comp:
                components.append(comp)
                seen.add(f"{comp['group']}:{comp['artifact']}")

    return components


def _title_to_component(title: str, version: str, seen: set) -> dict | None:
    """Map a MANIFEST title string to a known component."""
    title_lower = title.lower()
    for prefix, meta in KNOWN_SDK_PACKAGES.items():
        key = f"{meta['group']}:{meta['artifact']}"
        if key in seen:
            continue
        if (prefix.lower() in title_lower or
            meta["artifact"].lower() in title_lower or
            meta["group"].lower().split(".")[-1] in title_lower):
            return _make_comp(meta["group"], meta["artifact"], version)
    return None


def _parse_properties_file(content: str, seen: set) -> list[dict]:
    """Parse key=value files for group/artifact/version info."""
    components = []
    group_match   = re.search(r'group\s*=\s*([^\s\n]+)',   content)
    artifact_match= re.search(r'artifact\s*=\s*([^\s\n]+)', content)
    version_match = re.search(r'version\s*=\s*([^\s\n]+)',  content)

    if group_match and artifact_match:
        group    = group_match.group(1).strip()
        artifact = artifact_match.group(1).strip()
        version  = version_match.group(1).strip() if version_match else "unknown"
        key      = f"{group}:{artifact}"
        if key not in seen and len(group) > 3 and len(artifact) > 2:
            components.append(_make_comp(group, artifact, version))

    return components


# ─────────────────────────────────────────────────────────────
# Strategy 3: Raw string scan — survives R8/ProGuard
# ─────────────────────────────────────────────────────────────

def _scan_strings(apk_path: Path) -> list[dict]:
    """
    Read the raw bytes of classes.dex and scan for SDK-identifying strings.
    Works even when class names are obfuscated (a.b.c style).
    """
    seen: set[str] = set()
    found = []

    with zipfile.ZipFile(apk_path, "r") as zf:
        dex_files = [n for n in zf.namelist() if re.match(r"classes\d*\.dex$", n)]
        # Also scan the whole APK for string resources
        all_scan_targets = dex_files + ["resources.arsc"]

        raw_bytes = b""
        for target in all_scan_targets:
            if target in zf.namelist():
                try:
                    raw_bytes += zf.read(target)
                except Exception:
                    pass

    if not raw_bytes:
        return []

    # Extract all printable ASCII strings >= 5 chars
    strings_found = set(re.findall(rb'[\x20-\x7e]{5,}', raw_bytes))
    strings_decoded = {s.decode("ascii", errors="ignore") for s in strings_found}

    for sig, group, artifact in STRING_SIGNATURES:
        key = f"{group}:{artifact}"
        if key in seen:
            continue
        if any(sig in s for s in strings_decoded):
            found.append(_make_comp(group, artifact, "unknown"))
            seen.add(key)
            logger.debug("String match: %s -> %s", sig, key)

    return found


# ─────────────────────────────────────────────────────────────
# Strategy 4: Asset/file path detection
# ─────────────────────────────────────────────────────────────

def _scan_asset_paths(apk_path: Path) -> list[dict]:
    seen: set[str] = set()
    found = []

    with zipfile.ZipFile(apk_path, "r") as zf:
        all_paths = set(zf.namelist())

    for path_sig, group, artifact in ASSET_PATH_SIGNATURES:
        key = f"{group}:{artifact}"
        if key in seen:
            continue
        if any(p.startswith(path_sig) or path_sig in p for p in all_paths):
            found.append(_make_comp(group, artifact, "unknown"))
            seen.add(key)
            logger.debug("Path match: %s -> %s", path_sig, key)

    return found


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _make_comp(group: str, artifact: str, version: str) -> dict:
    return {
        "group":     group,
        "artifact":  artifact,
        "version":   version,
        "scope":     "implementation",
        "is_direct": True,
        "depth":     0,
        "source":    "apk_inference",
    }


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_components_from_apk(apk_result: dict) -> list[Component]:
    from app.ingestion.gradle_parser import _build_purl
    components = []
    for raw in apk_result.get("components", []):
        g = raw.get("group", "")
        a = raw.get("artifact", "")
        v = raw.get("version", "unknown")
        if not g or not a:
            continue
        comp = Component(
            purl=_build_purl(g, a, v),
            name=f"{g}:{a}",
            group=g,
            artifact=a,
            version=v,
            scope=DependencyScope.IMPLEMENTATION,
            is_direct=True,
            depth=0,
        )
        components.append(comp)
    logger.info("Built %d Component objects from APK", len(components))
    return components
