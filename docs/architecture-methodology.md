# Architecture and Methodology

## Purpose

This project provides a defensible way to assess whether an incident investigation has enough evidence to support its conclusions. It does not collect evidence from live systems. It evaluates an analyst-supplied checklist and highlights missing or incomplete forensic artifacts.

## Architecture

1. **Input validation** — JSON records are validated into immutable `ArtifactRequirement` objects. Duplicate artifact IDs, invalid categories, invalid priorities, invalid statuses, and timezone-naive collection timestamps are rejected.
2. **Gap analysis** — each missing or partial artifact receives a deterministic evidence-gap score using artifact priority, availability status, and investigative importance of selected categories.
3. **Prioritization** — evidence gaps are converted into deterministic findings, sorted by residual investigation risk.
4. **Reporting** — the reporting layer calculates evidence coverage and produces an executive/technical Markdown assessment.
5. **Validation** — unit tests cover scoring, fail-closed parsing, deterministic IDs, evidence-reference requirements, metrics, and governance language.

## Evidence domains

The checklist supports identity, process, network, persistence, filesystem, registry, browser, email, memory, cloud, EDR, and timeline artifacts. These categories are intentionally broad so the project can model investigations across endpoint, identity, network, SaaS, and cloud environments without depending on a vendor-specific collector.

## Gap scoring

Gap score is bounded to 0–100 and is derived from:

- business/investigation priority of the artifact;
- whether the artifact is missing or only partial;
- additional weight for identity, process, network, EDR, and timeline evidence because gaps in those domains often weaken reconstruction quality materially;
- a small data-quality penalty where the source is not documented.

A score communicates investigation risk caused by missing evidence. It does **not** estimate attacker sophistication, malware severity, or probability of compromise.

## Chain-of-custody and integrity expectations

For evidence marked `present`, the model requires an evidence reference. In a real investigation, that reference should tie to approved evidence handling records. Appropriate workflows should preserve collection time, source, analyst, relevant hashes, export metadata, retention requirements, and access control according to organizational policy.

## ATT&CK mapping

MITRE ATT&CK technique IDs are optional contextual tags that help explain what investigation questions an artifact may support. ATT&CK mappings are never treated as proof that the mapped technique occurred.

## Remediation and revalidation

A gap should remain open until the artifact is acquired or formally determined unavailable, limitations are documented, evidence references are recorded, UTC collection metadata is preserved, and the investigation lead accepts the resulting level of confidence. Re-running the analyzer after checklist updates provides a simple revalidation workflow.

## Safety boundary

The repository contains no credential extraction, malware, live acquisition agent, memory dumper, persistence mechanism, exploitation logic, destructive tooling, or production targeting. All example data is synthetic.
