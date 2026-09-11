# Example Forensic Artifact Coverage Assessment

> Synthetic example only. No production or client data is represented.

## Executive summary

The fictional investigation has six applicable evidence requirements. Two are fully present, producing an evidence coverage rate of 33.3%. Four evidence gaps remain open, including critical/high gaps affecting EDR, process, network, and timeline reconstruction.

The most important gap is the missing EDR alert/host timeline. A partial endpoint process history and absent DNS/proxy telemetry further reduce confidence in reconstructing execution and network activity. The unified timeline is also incomplete because it depends on those missing sources.

## Priority actions

1. Recover or export the synthetic EDR host timeline and document collection metadata.
2. Determine whether the missing process-creation interval can be reconstructed from another approved evidence source.
3. Recover DNS/proxy telemetry if retained, or document that it is unavailable and explicitly state the resulting analytical limitation.
4. Rebuild the unified incident timeline after the evidence gaps above are resolved or formally accepted.

## Investigation governance

Evidence marked present should have a traceable evidence reference. Acquisition should preserve source, collection time, integrity metadata where appropriate, and chain-of-custody records. The investigation lead should document limitations before closing an evidence gap as unavailable.

## ATT&CK context

The synthetic checklist contains context for T1078, T1059.001, T1071.004, T1060, T1562.001, and T1021. These mappings identify investigation questions the evidence may help answer; they do not establish that the techniques occurred.

## Closure standard

A forensic evidence gap is considered resolved only when the required artifact is available and referenced, or when the organization formally accepts that it cannot be recovered and records the resulting confidence limitation.
