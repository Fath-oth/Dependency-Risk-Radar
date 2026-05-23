"""
core/models.py
Central data models shared across all modules.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class RiskLevel(str, Enum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    BLOCKING = "BLOCKING"

    @classmethod
    def from_score(cls, score: float) -> "RiskLevel":
        if score < 20:
            return cls.LOW
        elif score < 50:
            return cls.MODERATE
        elif score < 75:
            return cls.HIGH
        elif score < 90:
            return cls.CRITICAL
        return cls.BLOCKING


class LicenseRisk(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DependencyScope(str, Enum):
    IMPLEMENTATION = "implementation"
    API = "api"
    COMPILE_ONLY = "compileOnly"
    RUNTIME_ONLY = "runtimeOnly"
    TEST = "testImplementation"
    ANDROID_TEST = "androidTestImplementation"
    KAPT = "kapt"
    KSP = "ksp"
    ANNOTATION_PROCESSOR = "annotationProcessor"


@dataclass
class CVE:
    id: str
    summary: str
    cvss_v3: Optional[float]
    has_fix: bool
    aliases: list[str] = field(default_factory=list)
    exploit_available: bool = False

    @property
    def severity_label(self) -> str:
        if not self.cvss_v3:
            return "UNKNOWN"
        if self.cvss_v3 >= 9.0:
            return "CRITICAL"
        elif self.cvss_v3 >= 7.0:
            return "HIGH"
        elif self.cvss_v3 >= 4.0:
            return "MEDIUM"
        return "LOW"


@dataclass
class License:
    spdx_id: str
    name: str
    risk_score: float        # 0-100
    is_copyleft: bool
    is_permissive: bool
    url: Optional[str] = None

    @classmethod
    def unknown(cls) -> "License":
        return cls(
            spdx_id="UNKNOWN",
            name="Unknown License",
            risk_score=65.0,
            is_copyleft=False,
            is_permissive=False,
        )


@dataclass
class Tracker:
    name: str
    categories: list[str]
    website: str
    code_signature: str
    risk_weight: float = 1.0   # multiplier based on category severity


@dataclass
class RiskScores:
    cve_score: float = 0.0
    obsolescence_score: float = 0.0
    licence_score: float = 0.0
    tracker_score: float = 0.0

    @property
    def global_score(self) -> float:
        return round(
            self.cve_score * 0.45
            + self.obsolescence_score * 0.25
            + self.licence_score * 0.20
            + self.tracker_score * 0.10,
            1,
        )

    @property
    def risk_level(self) -> RiskLevel:
        return RiskLevel.from_score(self.global_score)


@dataclass
class Component:
    purl: str
    name: str
    group: str
    artifact: str
    version: str
    scope: DependencyScope
    is_direct: bool
    depth: int = 0

    # Enrichment fields
    latest_version: Optional[str] = None
    last_release_ts: Optional[float] = None
    license: Optional[License] = None
    vulnerabilities: list[CVE] = field(default_factory=list)
    trackers: list[Tracker] = field(default_factory=list)
    scores: RiskScores = field(default_factory=RiskScores)

    # Graph fields
    direct_ancestor: Optional[str] = None      # nearest direct dependency that pulls this in
    dependents: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)

    # Computed transitive risk (set after graph analysis)
    transitive_risk_score: float = 0.0

    @property
    def coordinate(self) -> str:
        return f"{self.group}:{self.artifact}:{self.version}"

    @property
    def is_outdated(self) -> bool:
        return self.latest_version is not None and self.latest_version != self.version

    @property
    def cve_count(self) -> int:
        return len(self.vulnerabilities)

    @property
    def max_cvss(self) -> Optional[float]:
        scores = [v.cvss_v3 for v in self.vulnerabilities if v.cvss_v3 is not None]
        return max(scores) if scores else None

    def to_dict(self) -> dict:
        return {
            "purl": self.purl,
            "name": self.name,
            "group": self.group,
            "artifact": self.artifact,
            "version": self.version,
            "latest_version": self.latest_version,
            "scope": self.scope.value,
            "is_direct": self.is_direct,
            "depth": self.depth,
            "direct_ancestor": self.direct_ancestor,
            "license": {
                "spdx_id": self.license.spdx_id,
                "name": self.license.name,
                "is_copyleft": self.license.is_copyleft,
                "risk_score": self.license.risk_score,
            } if self.license else None,
            "vulnerabilities": [
                {
                    "id": v.id,
                    "summary": v.summary,
                    "cvss_v3": v.cvss_v3,
                    "severity": v.severity_label,
                    "has_fix": v.has_fix,
                }
                for v in self.vulnerabilities
            ],
            "trackers": [
                {"name": t.name, "categories": t.categories}
                for t in self.trackers
            ],
            "scores": {
                "global": self.scores.global_score,
                "cve": self.scores.cve_score,
                "obsolescence": self.scores.obsolescence_score,
                "licence": self.scores.licence_score,
                "tracker": self.scores.tracker_score,
                "risk_level": self.scores.risk_level.value,
            },
            "transitive_risk_score": self.transitive_risk_score,
        }


@dataclass
class AnalysisReport:
    report_id: str
    project_name: str
    project_version: str
    analyzed_at: str
    components: list[Component]
    sbom_path: Optional[str] = None
    update_plan: Optional[dict] = None

    @property
    def total_components(self) -> int:
        return len(self.components)

    @property
    def direct_components(self) -> list[Component]:
        return [c for c in self.components if c.is_direct]

    @property
    def vulnerable_components(self) -> list[Component]:
        return [c for c in self.components if c.vulnerabilities]

    @property
    def critical_components(self) -> list[Component]:
        return [c for c in self.components if c.scores.risk_level in (RiskLevel.CRITICAL, RiskLevel.BLOCKING)]

    @property
    def global_risk_score(self) -> float:
        if not self.components:
            return 0.0
        scores = [c.scores.global_score for c in self.components]
        # Weighted: top 10% of riskiest components drive the global score
        scores.sort(reverse=True)
        top = scores[: max(1, len(scores) // 10)]
        return round(sum(top) / len(top), 1)
