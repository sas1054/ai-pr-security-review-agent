"""No-network fixture runner for the full review pipeline."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from ado_client import ChangedFile, PrDiff
from models import ReviewJob, ReviewResult
from orchestrator import process_review
from scanner import scan
from triage import NoopTriageClient


class FixtureAdoClient:
    def __init__(self, diff: PrDiff):
        self.diff = diff

    def fetch_diff(self, job: ReviewJob) -> PrDiff:
        return self.diff


class ConsoleReporter:
    def publish(self, result: ReviewResult) -> None:
        print(
            json.dumps(
                {
                    "run_id": result.run_id,
                    "status": result.status,
                    "summary": result.summary,
                    "findings": [finding.__dict__ for finding in result.findings],
                    "errors": result.errors,
                },
                indent=2,
            )
        )


def _empty_semgrep_runner(*args: Any, **kwargs: Any):
    return subprocess.CompletedProcess(args[0], 0, '{"results": []}', "")


def run_fixture(path: str) -> None:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    job = ReviewJob.from_dict(payload["job"])
    changed_files = [ChangedFile(**item) for item in payload.get("changed_files", [])]
    diff = PrDiff(
        pr_id=job.pr_id,
        repo_name=job.repo_name,
        source_branch=job.source_branch,
        target_branch=job.target_branch,
        iteration_id=int(payload.get("iteration_id", 1)),
        changed_files=changed_files,
        raw_diff=payload.get("raw_diff", ""),
        truncated=bool(payload.get("truncated", False)),
    )
    scanner = lambda files: scan(files, semgrep_runner=_empty_semgrep_runner)
    process_review(
        job,
        ado=FixtureAdoClient(diff),
        scanner=scanner,
        triage_client=NoopTriageClient(),
        reporter=ConsoleReporter(),
        run_id="local-fixture",
    )
