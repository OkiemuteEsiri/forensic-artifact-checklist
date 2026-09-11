from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass
from typing import Iterable

from .models import ArtifactRequirement

PRIORITY_WEIGHT = {"critical": 40, "high": 28, "medium": 16, "low": 8}
STATUS_WEIGHT = {"missing": 35, "partial": 18, "present": 0, "not_applicable": 0}


@dataclass(frozen=True)
class GapFinding:
    finding_id: str
    artifact_id: str
    title: str
    score: int
    severity: str
    rationale: str
    remediation: str
    validation: str
    attack_techniques: tuple[str, ...]


def _finding_id(artifact: ArtifactRequirement) -> str:
    raw = f"{artifact.artifact_id}|{artifact.category}|{artifact.status}|{artifact.priority}".encode()
    return "FG-" + hashlib.sha256(raw).hexdigest()[:10].upper()


def _severity(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def score_gap(artifact: ArtifactRequirement) -> int:
    if artifact.status in {"present", "not_applicable"}:
        return 0
    score = PRIORITY_WEIGHT[artifact.priority] + STATUS_WEIGHT[artifact.status]
    if artifact.category in {"identity", "process", "network", "edr", "timeline"}:
        score += 10
    if not artifact.source.strip():
        score += 5
    return min(score, 100)


def analyze_artifact(artifact: ArtifactRequirement) -> GapFinding | None:
    score = score_gap(artifact)
    if score == 0:
        return None
    status_phrase = "not collected" if artifact.status == "missing" else "only partially available"
    rationale = (
        f"{artifact.name} is {status_phrase}; this weakens {artifact.category} reconstruction "
        f"and reduces confidence in incident conclusions."
    )
    remediation = (
        "Acquire or recover the artifact through an approved forensic collection process, preserve "
        "chain-of-custody metadata, hash exported evidence where appropriate, and document any source limitations."
    )
    validation = (
        "Confirm the evidence reference is recorded, collection time is UTC-normalized, integrity metadata is preserved, "
        "and the artifact can be used to answer the investigation question it supports."
    )
    return GapFinding(
        finding_id=_finding_id(artifact),
        artifact_id=artifact.artifact_id,
        title=f"Evidence gap: {artifact.name}",
        score=score,
        severity=_severity(score),
        rationale=rationale,
        remediation=remediation,
        validation=validation,
        attack_techniques=tuple(sorted(artifact.attack_techniques)),
    )


def analyze(artifacts: Iterable[ArtifactRequirement]) -> list[GapFinding]:
    findings = [f for artifact in artifacts if (f := analyze_artifact(artifact)) is not None]
    return sorted(findings, key=lambda f: (-f.score, f.artifact_id))


def portfolio_metrics(artifacts: list[ArtifactRequirement], findings: list[GapFinding]) -> dict[str, object]:
    applicable = [a for a in artifacts if a.status != "not_applicable"]
    present = [a for a in applicable if a.status == "present"]
    evidence_coverage = round((len(present) / len(applicable) * 100), 1) if applicable else 100.0
    critical_high_gaps = sum(1 for f in findings if f.severity in {"critical", "high"})
    by_category = Counter(a.category for a in applicable)
    missing_by_category = Counter(a.category for a in applicable if a.status in {"missing", "partial"})
    return {
        "artifacts": len(artifacts),
        "applicable_artifacts": len(applicable),
        "present_artifacts": len(present),
        "evidence_coverage_percent": evidence_coverage,
        "open_gaps": len(findings),
        "critical_high_gaps": critical_high_gaps,
        "highest_gap_score": max((f.score for f in findings), default=0),
        "artifacts_by_category": dict(sorted(by_category.items())),
        "gaps_by_category": dict(sorted(missing_by_category.items())),
    }
