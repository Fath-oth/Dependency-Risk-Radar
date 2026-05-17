"""
tests/test_gradle_parser.py
Unit tests for the Gradle dependency parser.
"""
import pytest
import tempfile
from pathlib import Path

from app.ingestion.gradle_parser import (
    parse_gradle_file,
    _parse_tree_output,
    build_components,
    _build_purl,
)


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _write_gradle(content: str) -> Path:
    """Write a temporary build.gradle file and return its path."""
    tmp = tempfile.NamedTemporaryFile(
        suffix=".gradle", mode="w", delete=False, encoding="utf-8"
    )
    tmp.write(content)
    tmp.flush()
    return Path(tmp.name)


# ─────────────────────────────────────────────
# parse_gradle_file
# ─────────────────────────────────────────────

class TestParseGradleFile:
    def test_standard_double_quote(self):
        path = _write_gradle('implementation "com.squareup.retrofit2:retrofit:2.9.0"')
        deps = parse_gradle_file(path)
        assert len(deps) == 1
        assert deps[0]["group"]    == "com.squareup.retrofit2"
        assert deps[0]["artifact"] == "retrofit"
        assert deps[0]["version"]  == "2.9.0"
        assert deps[0]["scope"]    == "implementation"

    def test_standard_single_quote(self):
        path = _write_gradle("api 'com.google.code.gson:gson:2.10.1'")
        deps = parse_gradle_file(path)
        assert len(deps) == 1
        assert deps[0]["artifact"] == "gson"
        assert deps[0]["scope"]    == "api"

    def test_map_form(self):
        path = _write_gradle(
            "implementation group: 'org.jetbrains.kotlin', name: 'kotlin-stdlib', version: '1.9.0'"
        )
        deps = parse_gradle_file(path)
        assert len(deps) == 1
        assert deps[0]["group"]    == "org.jetbrains.kotlin"
        assert deps[0]["artifact"] == "kotlin-stdlib"
        assert deps[0]["version"]  == "1.9.0"

    def test_version_variable_substitution(self):
        path = _write_gradle(
            'def retrofitVersion = "2.9.0"\n'
            'implementation "com.squareup.retrofit2:retrofit:$retrofitVersion"'
        )
        deps = parse_gradle_file(path)
        assert len(deps) == 1
        assert deps[0]["version"] == "2.9.0"

    def test_multiple_scopes(self):
        content = "\n".join([
            'implementation "com.squareup.retrofit2:retrofit:2.9.0"',
            'testImplementation "junit:junit:4.13.2"',
            'compileOnly "javax.annotation:javax.annotation-api:1.3.2"',
            'kapt "com.google.dagger:dagger-compiler:2.48"',
        ])
        path = _write_gradle(content)
        deps = parse_gradle_file(path)
        scopes = {d["scope"] for d in deps}
        assert "implementation"     in scopes
        assert "testImplementation" in scopes
        assert "compileOnly"        in scopes
        assert "kapt"               in scopes

    def test_deduplicates_same_artifact(self):
        content = "\n".join([
            'implementation "com.squareup.okhttp3:okhttp:4.11.0"',
            'implementation "com.squareup.okhttp3:okhttp:4.11.0"',  # duplicate
        ])
        path = _write_gradle(content)
        deps = parse_gradle_file(path)
        assert len(deps) == 1

    def test_ignores_project_references(self):
        # project() references should not be parsed as maven coordinates
        content = "implementation project(':feature-auth')"
        path = _write_gradle(content)
        deps = parse_gradle_file(path)
        assert len(deps) == 0

    def test_multiple_dependencies(self):
        content = "\n".join([
            'implementation "com.squareup.retrofit2:retrofit:2.9.0"',
            'implementation "com.google.code.gson:gson:2.10.1"',
            'implementation "io.reactivex.rxjava3:rxjava:3.1.6"',
        ])
        path = _write_gradle(content)
        deps = parse_gradle_file(path)
        assert len(deps) == 3
        artifacts = {d["artifact"] for d in deps}
        assert "retrofit" in artifacts
        assert "gson"     in artifacts
        assert "rxjava"   in artifacts


# ─────────────────────────────────────────────
# _parse_tree_output
# ─────────────────────────────────────────────

class TestParseTreeOutput:
    SAMPLE_TREE = """
releaseRuntimeClasspath - ...
+--- com.squareup.retrofit2:retrofit:2.9.0
|    +--- com.squareup.okhttp3:okhttp:4.11.0
|    |    \\--- com.squareup.okio:okio:3.6.0
|    \\--- com.squareup.okhttp3:okhttp-bom:4.11.0
+--- com.google.code.gson:gson:2.10.1
\\--- org.jetbrains.kotlin:kotlin-stdlib:1.9.0
"""

    def test_parses_direct_dependencies(self):
        result = _parse_tree_output(self.SAMPLE_TREE)
        purls = {r["purl"] for r in result}
        assert "pkg:maven/com.squareup.retrofit2/retrofit@2.9.0" in purls
        assert "pkg:maven/com.google.code.gson/gson@2.10.1"      in purls
        assert "pkg:maven/org.jetbrains.kotlin/kotlin-stdlib@1.9.0" in purls

    def test_parses_transitive_dependencies(self):
        result = _parse_tree_output(self.SAMPLE_TREE)
        purls = {r["purl"] for r in result}
        assert "pkg:maven/com.squareup.okhttp3/okhttp@4.11.0" in purls
        assert "pkg:maven/com.squareup.okio/okio@3.6.0"       in purls

    def test_depth_is_correct(self):
        result = _parse_tree_output(self.SAMPLE_TREE)
        by_artifact = {r["artifact"]: r for r in result}
        assert by_artifact["retrofit"]["depth"]      == 0
        assert by_artifact["okhttp"]["depth"]        == 1
        assert by_artifact["okio"]["depth"]          == 2

    def test_direct_flag(self):
        result = _parse_tree_output(self.SAMPLE_TREE)
        by_artifact = {r["artifact"]: r for r in result}
        assert by_artifact["retrofit"]["is_direct"]  is True
        assert by_artifact["gson"]["is_direct"]      is True
        assert by_artifact["okhttp"]["is_direct"]    is False
        assert by_artifact["okio"]["is_direct"]      is False

    def test_parent_purl_wired(self):
        result = _parse_tree_output(self.SAMPLE_TREE)
        by_artifact = {r["artifact"]: r for r in result}
        assert by_artifact["okhttp"]["parent_purl"] == "pkg:maven/com.squareup.retrofit2/retrofit@2.9.0"
        assert by_artifact["okio"]["parent_purl"]   == "pkg:maven/com.squareup.okhttp3/okhttp@4.11.0"

    def test_version_resolution_arrow(self):
        tree = """
releaseRuntimeClasspath - ...
+--- com.squareup.okhttp3:okhttp:4.10.0 -> 4.11.0
"""
        result = _parse_tree_output(tree)
        # Should use the resolved version (after ->)
        assert result[0]["version"] == "4.11.0"

    def test_empty_output_returns_empty_list(self):
        assert _parse_tree_output("") == []

    def test_duplicate_diamond_dependency_deduped(self):
        tree = """
releaseRuntimeClasspath - ...
+--- com.squareup.retrofit2:retrofit:2.9.0
|    \\--- com.squareup.okio:okio:3.6.0
\\--- com.squareup.okhttp3:okhttp:4.11.0
     \\--- com.squareup.okio:okio:3.6.0 (*)
"""
        result = _parse_tree_output(tree)
        okio_entries = [r for r in result if r["artifact"] == "okio"]
        # Diamond dependency should only appear once
        assert len(okio_entries) == 1


# ─────────────────────────────────────────────
# build_components
# ─────────────────────────────────────────────

class TestBuildComponents:
    def test_builds_component_objects(self):
        raw = [
            {
                "group": "com.squareup.retrofit2",
                "artifact": "retrofit",
                "version": "2.9.0",
                "scope": "implementation",
                "is_direct": True,
                "depth": 0,
            }
        ]
        comps = build_components(raw)
        assert len(comps) == 1
        c = comps[0]
        assert c.group    == "com.squareup.retrofit2"
        assert c.artifact == "retrofit"
        assert c.version  == "2.9.0"
        assert c.is_direct is True
        assert c.purl     == "pkg:maven/com.squareup.retrofit2/retrofit@2.9.0"

    def test_purl_format(self):
        purl = _build_purl("com.google.code.gson", "gson", "2.10.1")
        assert purl == "pkg:maven/com.google.code.gson/gson@2.10.1"
