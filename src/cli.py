from __future__ import annotations

import argparse
from pathlib import Path

from .analyzer import analyze
from .io_utils import load_artifacts
from .reporting import render_markdown


def main() -> None:
    parser = argparse.ArgumentParser(description="Assess forensic artifact coverage from a local JSON checklist")
    parser.add_argument("input", help="Path to artifact checklist JSON")
    parser.add_argument("--output", default="forensic-artifact-assessment.md", help="Markdown report path")
    args = parser.parse_args()

    artifacts = load_artifacts(args.input)
    findings = analyze(artifacts)
    report = render_markdown(artifacts, findings)
    Path(args.output).write_text(report, encoding="utf-8")
    print(f"Wrote {args.output} with {len(findings)} evidence gap(s).")


if __name__ == "__main__":
    main()
