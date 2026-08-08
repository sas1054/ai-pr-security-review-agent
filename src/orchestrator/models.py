"""Shared domain models for the review pipeline."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ReviewJob:
    job_version: int
    event_id: str
    event_type: str
    organization_url: str
    project: str
    repo_id: str
    repo_name: str
    pr_id: int
    source_branch: str
    target_branch: str
    title: str = ""

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ReviewJob":
        required = (
            "event_type",
            "organization_url",
            "project",
            "repo_id",
            "repo_name",
            "pr_id",
            "source_branch",
            "target_branch",
        )
        missing = [name for name in required if value.get(name) in (None, "")]
        if missing:
            raise ValueError(f"Review job missing required fields: {', '.join(missing)}")

        event_id = str(value.get("event_id") or "")
        if not event_id:
            canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
            event_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        return cls(
            job_version=int(value.get("job_version", 1)),
            event_id=event_id,
            event_type=str(value["event_type"]),
            organization_url=str(value["organization_url"]).rstrip("/"),
            project=str(value["project"]),
            repo_id=str(value["repo_id"]),
            repo_name=str(value["repo_name"]),
            pr_id=int(value["pr_id"]),
            source_branch=str(value["source_branch"]),
            target_branch=str(value["target_branch"]),
            title=str(value.get("title") or ""),
        )


@dataclass
class TriageItem:
    fingerprint: str
    priority: str
    likely_false_positive: bool
    explanation: str
    fix_hint: str = ""


@dataclass
class TriageResult:
    summary: str
    items: list[TriageItem] = field(default_factory=list)
    error: str = ""

    @property
    def succeeded(self) -> bool:
        return not self.error


@dataclass
class ReviewResult:
    run_id: str
    job: ReviewJob
    status: str
    findings: list[Any] = field(default_factory=list)
    triage: TriageResult | None = None
    summary: str = ""
    counts: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    duration_ms: int = 0
    iteration_id: int | None = None
    policy_versions: list[str] = field(default_factory=list)
    regulation_context: list[dict[str, Any]] = field(default_factory=list)
    suppressed_findings: list[Any] = field(default_factory=list)
    applicable_exceptions: list[dict[str, Any]] = field(default_factory=list)
    coverage_gaps: list[str] = field(default_factory=list)
    control_snapshot: list[dict[str, Any]] = field(default_factory=list)
