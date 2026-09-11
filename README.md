# Forensic Artifact Checklist

A recruiter-facing **Incident Response / Digital Forensics / Detection Engineering** project for assessing whether an investigation has enough evidence to support defensible conclusions.

This repository does **not** acquire evidence from live systems. Instead, it evaluates an analyst-maintained forensic checklist, validates evidence metadata, identifies missing or partial artifacts, calculates investigation-readiness metrics, prioritizes evidence gaps, and produces an auditable Markdown assessment.

## Problem statement

Incident investigations often fail for a simple reason: the evidence required to answer key questions is incomplete, inconsistent, or undocumented. Analysts may have endpoint telemetry but no proxy logs, authentication records but no process history, or a timeline that silently excludes important data sources.

This project treats evidence completeness as a measurable engineering problem.

## Architecture

```text
Synthetic / analyst checklist JSON
            |
            v
   Fail-closed validation
            |
            v
 Immutable artifact models
            |
            v
 Evidence gap scoring engine
            |
            v
 Prioritized investigation gaps
            |
            +--> coverage metrics
            +--> ATT&CK context
            +--> remediation / validation guidance
            |
            v
 Executive + technical Markdown report
```

## Security capabilities demonstrated

- Forensic evidence readiness assessment
- Fail-closed data validation
- Evidence-reference governance
- UTC-normalized collection timestamps
- Duplicate evidence-control detection
- Deterministic finding identifiers
- Explainable 0–100 evidence-gap scoring
- Critical/high evidence-gap prioritization
- Evidence coverage metrics
- ATT&CK contextual mapping
- Chain-of-custody-aware methodology
- Investigation limitation documentation
- Remediation and revalidation workflow
- Unit-tested Python implementation
- Least-privilege GitHub Actions CI

## Evidence domains

The model supports:

- Identity and authentication evidence
- Process execution telemetry
- Network / DNS / proxy evidence
- Persistence artifacts
- Filesystem evidence
- Registry evidence
- Browser artifacts
- Email evidence
- Memory evidence
- Cloud audit evidence
- EDR evidence
- Unified investigation timelines

## Repository structure

```text
.github/workflows/ci.yml        # compile, unit-test and synthetic CLI smoke test
src/models.py                   # immutable validated evidence models
src/io_utils.py                 # strict JSON ingestion
src/analyzer.py                 # gap scoring and portfolio metrics
src/reporting.py                # executive/technical Markdown reporting
src/cli.py                      # offline command-line interface
data/synthetic_case.json        # clearly fictional investigation data
tests/test_analyzer.py          # 10 meaningful unit tests
docs/architecture-methodology.md
reports/example-assessment.md
```

## Risk model

Evidence gaps are scored from **0–100** using:

1. Artifact priority
2. Availability status: missing vs partial
3. Investigative importance of selected telemetry domains
4. Basic source-documentation quality

Indicative severity tiers:

- **Critical:** 70–100
- **High:** 50–69
- **Medium:** 30–49
- **Low:** below 30

The score represents the risk that missing evidence weakens investigation confidence. It is **not** a probability of compromise and does not claim attacker activity occurred.

## Example synthetic scenario

The included fictional investigation contains six evidence requirements:

- IdP sign-in logs — present
- Endpoint process creation telemetry — partial
- DNS/proxy telemetry — missing
- Registry persistence evidence — present
- EDR alert / host timeline — missing
- Unified incident timeline — partial

This produces a realistic evidence-coverage problem for analysts to prioritize without using confidential or production data.

## MITRE ATT&CK context

The synthetic example references techniques such as:

| Technique | Context |
|---|---|
| T1078 | Valid Accounts / identity investigation |
| T1059.001 | PowerShell / process execution context |
| T1071.004 | DNS / network activity context |
| T1060 | Registry Run Keys / Startup Folder context |
| T1562.001 | Security-tool impairment context |
| T1021 | Remote Services / lateral-movement context |

ATT&CK mappings are used as analytical context only. A mapping is never treated as proof that a technique occurred.

## Usage

Run the synthetic assessment locally:

```bash
python -m src.cli data/synthetic_case.json --output forensic-artifact-assessment.md
```

Run tests:

```bash
python -m unittest discover -s tests -v
```

## Validation controls

The parser fails closed when it encounters:

- Duplicate artifact IDs
- Unsupported artifact categories
- Unsupported statuses
- Unsupported priorities
- Timezone-naive collection timestamps
- A `present` artifact without an evidence reference
- Malformed non-list JSON input

This makes data quality part of the forensic workflow instead of an afterthought.

## Metrics produced

The reporting layer calculates:

- Total artifacts
- Applicable artifacts
- Present artifacts
- Evidence coverage percentage
- Open evidence gaps
- Critical/high gaps
- Highest evidence-gap score
- Artifact distribution by category
- Missing/partial gaps by category

## Remediation and revalidation workflow

```text
Identify evidence gap
      |
      v
Determine approved evidence source
      |
      v
Acquire / recover evidence through authorized process
      |
      v
Record evidence reference and collection metadata
      |
      v
Validate integrity / usability / scope
      |
      v
Re-run assessment
      |
      v
Close gap or formally document limitation
```

A missing source should not be silently ignored. If evidence cannot be recovered, the limitation should remain visible and be accepted by the investigation owner before closure.

## Chain-of-custody principles

In a real investigation, evidence handling should preserve, as applicable:

- Evidence reference / case identifier
- Source system
- Collector / analyst
- UTC collection timestamp
- Integrity hash or export metadata
- Storage location
- Access controls
- Retention requirements
- Investigation notes and limitations

This project models the governance around those expectations without implementing live evidence acquisition.

## CI/CD

The GitHub Actions workflow uses read-only repository permissions and performs:

1. Python compilation
2. Unit-test discovery
3. Synthetic CLI smoke testing

No production integrations, secrets, or external security services are required.

## Design decisions

- **Immutable domain models** reduce accidental mutation during analysis.
- **Deterministic finding IDs** make repeated assessments comparable.
- **Offline analysis** keeps the project safe and reproducible.
- **Synthetic data** demonstrates capability without exposing client or employer information.
- **Evidence gaps are not compromise claims**; the project separates missing telemetry from security conclusions.

## Skills demonstrated

This repository demonstrates practical capability across:

- Incident response engineering
- Digital-forensics readiness
- Detection engineering
- Evidence governance
- Python security automation
- Risk prioritization
- Data validation
- Executive reporting
- ATT&CK-informed analysis
- Test-driven defensive tooling
- CI/CD security controls

## Roadmap

Potential future enhancements:

- CSV ingestion alongside JSON
- Case-level evidence dependency graphs
- Evidence aging / retention-risk analysis
- Timeline completeness scoring
- Optional Sigma / detection-rule linkage
- Evidence-to-investigation-question mapping
- HTML report output
- SARIF-compatible evidence-quality findings

## Safety and ethics

This is a defensive portfolio project. It contains **no malware, credential extraction, memory dumping utility, live collection agent, persistence mechanism, destructive tooling, bypass logic, exploitation, production targeting, or confidential client data**.

All example data is synthetic and clearly labeled as such.
