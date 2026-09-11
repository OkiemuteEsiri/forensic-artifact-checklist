from __future__ import annotations

from .analyzer import GapFinding, portfolio_metrics
from .models import ArtifactRequirement


def render_markdown(artifacts: list[ArtifactRequirement], findings: list[GapFinding]) -> str:
    metrics = portfolio_metrics(artifacts, findings)
    lines = [
        "# Forensic Artifact Coverage Assessment",
        "",
        "## Executive summary",
        "",
        f"- Applicable artifacts: **{metrics['applicable_artifacts']}**",
        f"- Present artifacts: **{metrics['present_artifacts']}**",
        f"- Evidence coverage: **{metrics['evidence_coverage_percent']}%**",
        f"- Open evidence gaps: **{metrics['open_gaps']}**",
        f"- Critical/high gaps: **{metrics['critical_high_gaps']}**",
        f"- Highest gap score: **{metrics['highest_gap_score']} / 100**",
        "",
        "## Prioritized evidence gaps",
        "",
    ]
    if not findings:
        lines.append("No open evidence gaps were identified in the supplied checklist.")
    for finding in findings:
        techniques = ", ".join(finding.attack_techniques) or "None assigned"
        lines.extend([
            f"### {finding.finding_id} — {finding.title}",
            "",
            f"- Severity: **{finding.severity.upper()}**",
            f"- Gap score: **{finding.score} / 100**",
            f"- Artifact ID: `{finding.artifact_id}`",
            f"- ATT&CK context: {techniques}",
            f"- Rationale: {finding.rationale}",
            f"- Remediation: {finding.remediation}",
            f"- Validation: {finding.validation}",
            "",
        ])
    lines.extend([
        "## Governance note",
        "",
        "This assessment measures evidence completeness and investigation readiness. Missing telemetry can reduce confidence, but a gap is not evidence that compromise occurred. ATT&CK mappings provide analytical context only.",
        "",
    ])
    return "\n".join(lines)
