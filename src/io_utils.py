from __future__ import annotations

import json
from pathlib import Path

from .models import ArtifactRequirement, parse_utc


def load_artifacts(path: str | Path) -> list[ArtifactRequirement]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("input must be a JSON list")
    seen: set[str] = set()
    artifacts: list[ArtifactRequirement] = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("each artifact must be a JSON object")
        artifact_id = str(item["artifact_id"])
        if artifact_id in seen:
            raise ValueError(f"duplicate artifact_id: {artifact_id}")
        seen.add(artifact_id)
        collected_at = item.get("collected_at")
        artifacts.append(
            ArtifactRequirement(
                artifact_id=artifact_id,
                name=str(item["name"]),
                category=str(item["category"]),
                status=str(item["status"]),
                priority=str(item["priority"]),
                source=str(item.get("source", "")),
                collected_at=parse_utc(collected_at) if collected_at else None,
                evidence_reference=item.get("evidence_reference"),
                notes=str(item.get("notes", "")),
                attack_techniques=frozenset(str(v) for v in item.get("attack_techniques", [])),
            )
        )
    return artifacts
