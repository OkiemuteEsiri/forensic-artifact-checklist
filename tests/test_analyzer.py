import json
import tempfile
import unittest
from pathlib import Path

from src.analyzer import analyze, portfolio_metrics, score_gap
from src.io_utils import load_artifacts
from src.models import ArtifactRequirement, parse_utc
from src.reporting import render_markdown


class ForensicArtifactChecklistTests(unittest.TestCase):
    def setUp(self):
        self.synthetic_path = Path("data/synthetic_case.json")

    def test_loads_synthetic_case(self):
        artifacts = load_artifacts(self.synthetic_path)
        self.assertEqual(len(artifacts), 6)

    def test_present_artifact_has_zero_gap_score(self):
        artifact = load_artifacts(self.synthetic_path)[0]
        self.assertEqual(score_gap(artifact), 0)

    def test_missing_critical_edr_is_critical_gap(self):
        artifacts = load_artifacts(self.synthetic_path)
        edr = next(a for a in artifacts if a.artifact_id == "ART-005")
        findings = analyze([edr])
        self.assertEqual(findings[0].severity, "critical")
        self.assertGreaterEqual(findings[0].score, 70)

    def test_partial_process_artifact_generates_gap(self):
        artifacts = load_artifacts(self.synthetic_path)
        process = next(a for a in artifacts if a.artifact_id == "ART-002")
        findings = analyze([process])
        self.assertEqual(len(findings), 1)
        self.assertIn("partially available", findings[0].rationale)

    def test_findings_are_sorted_by_score(self):
        findings = analyze(load_artifacts(self.synthetic_path))
        scores = [f.score for f in findings]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_finding_ids_are_deterministic(self):
        artifacts = load_artifacts(self.synthetic_path)
        first = analyze(artifacts)
        second = analyze(artifacts)
        self.assertEqual([f.finding_id for f in first], [f.finding_id for f in second])

    def test_metrics_calculate_evidence_coverage(self):
        artifacts = load_artifacts(self.synthetic_path)
        metrics = portfolio_metrics(artifacts, analyze(artifacts))
        self.assertEqual(metrics["applicable_artifacts"], 6)
        self.assertEqual(metrics["present_artifacts"], 2)
        self.assertEqual(metrics["evidence_coverage_percent"], 33.3)

    def test_present_artifact_requires_evidence_reference(self):
        with self.assertRaises(ValueError):
            ArtifactRequirement(
                artifact_id="A-1",
                name="Example",
                category="identity",
                status="present",
                priority="high",
                source="synthetic",
                collected_at=parse_utc("2026-09-10T00:00:00Z"),
                evidence_reference=None,
                notes="",
                attack_techniques=frozenset(),
            )

    def test_duplicate_artifact_id_fails_closed(self):
        payload = [
            {"artifact_id": "A-1", "name": "One", "category": "identity", "status": "missing", "priority": "high", "source": "x"},
            {"artifact_id": "A-1", "name": "Two", "category": "network", "status": "missing", "priority": "high", "source": "y"},
        ]
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "input.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_artifacts(path)

    def test_report_contains_governance_and_attack_context(self):
        artifacts = load_artifacts(self.synthetic_path)
        report = render_markdown(artifacts, analyze(artifacts))
        self.assertIn("Governance note", report)
        self.assertIn("ATT&CK context", report)
        self.assertIn("not evidence that compromise occurred", report)


if __name__ == "__main__":
    unittest.main()
