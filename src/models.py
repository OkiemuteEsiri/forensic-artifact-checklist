from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import FrozenSet

VALID_CATEGORIES = {
    "identity", "process", "network", "persistence", "filesystem",
    "registry", "browser", "email", "memory", "cloud", "edr", "timeline",
}
VALID_STATUSES = {"present", "missing", "partial", "not_applicable"}
VALID_PRIORITIES = {"critical", "high", "medium", "low"}


def parse_utc(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class ArtifactRequirement:
    artifact_id: str
    name: str
    category: str
    status: str
    priority: str
    source: str
    collected_at: datetime | None
    evidence_reference: str | None
    notes: str
    attack_techniques: FrozenSet[str]

    def __post_init__(self) -> None:
        if not self.artifact_id.strip():
            raise ValueError("artifact_id is required")
        if self.category not in VALID_CATEGORIES:
            raise ValueError(f"invalid category: {self.category}")
        if self.status not in VALID_STATUSES:
            raise ValueError(f"invalid status: {self.status}")
        if self.priority not in VALID_PRIORITIES:
            raise ValueError(f"invalid priority: {self.priority}")
        if self.status == "present" and not self.evidence_reference:
            raise ValueError("present artifacts require evidence_reference")
        if self.collected_at is not None and self.collected_at.tzinfo is None:
            raise ValueError("collected_at must be timezone-aware")
