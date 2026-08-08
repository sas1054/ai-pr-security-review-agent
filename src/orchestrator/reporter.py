"""Idempotent advisory comments and status reporting back to Azure DevOps."""

from __future__ import annotations

import base64
import logging
import time
from html import escape
from typing import Any, Callable
from urllib.parse import quote

import httpx

from models import ReviewJob, ReviewResult
from ado_client import get_ado_pat

logger = logging.getLogger(__name__)


class ReporterError(RuntimeError):
    """Raised when the ADO reporting API cannot accept the review result."""


class AdoReporter:
    @staticmethod
    def _policy_body(finding: Any, marker: str, triage: Any) -> str:
        source = finding.source_reference or {}
        safe = lambda value: escape(str(value or ""), quote=False).replace("`", "\\`")
        location = ", ".join(
            part
            for part in (
                f"page {source.get('page')}" if source.get("page") else "",
                f"section “{safe(source.get('section'))}”" if source.get("section") else "",
                f"paragraph {source.get('paragraph')}" if source.get("paragraph") else "",
            )
            if part
        ) or "source clause recorded with the control"
        return (
            f"{marker}\n**{safe(finding.severity)} — {safe(finding.message)}**\n\n"
            f"Matched evidence: `{safe(finding.matched_value)}`\n\n"
            f"**Policy:** {safe(finding.policy_document)}, version {safe(finding.policy_version)}\n\n"
            f"**Source:** {location}\n\n"
            f"**Policy statement:** “{safe(source.get('excerpt'))}”\n\n"
            f"**Reason:** {safe(finding.reason)}\n\n"
            f"**Suggested action:** {safe(triage.fix_hint if triage and triage.fix_hint else finding.fix_hint)}\n\n"
            f"Control `{safe(finding.control_id)}` version `{safe(finding.control_version)}` · Confidence {finding.confidence:.2f}"
        )

    API_VERSION = "7.1"

    def __init__(
        self,
        *,
        http_client: httpx.Client | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
        max_retries: int = 3,
    ):
        self._http = http_client or httpx.Client()
        self._sleep = sleep_fn
        self.max_retries = max_retries

    def _base_url(self, job: ReviewJob) -> str:
        return (
            f"{job.organization_url.rstrip('/')}/{quote(job.project, safe='')}/_apis/git/"
            f"repositories/{quote(job.repo_id, safe='')}/"
        )

    def _request(
        self,
        job: ReviewJob,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
    ) -> httpx.Response:
        headers = {
            "Authorization": "Basic " + base64.b64encode(f":{get_ado_pat()}".encode()).decode(),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        url = self._base_url(job) + path
        for attempt in range(self.max_retries + 1):
            try:
                response = self._http.request(
                    method,
                    url,
                    headers=headers,
                    params={"api-version": self.API_VERSION},
                    json=body,
                    timeout=30,
                )
            except httpx.RequestError as exc:
                if attempt >= self.max_retries:
                    raise ReporterError("ADO reporting request failed") from exc
                self._sleep(min(2**attempt, 8))
                continue
            if response.status_code not in ({408, 429} | set(range(500, 600))):
                response.raise_for_status()
                return response
            if attempt >= self.max_retries:
                response.raise_for_status()
            retry_after = response.headers.get("retry-after")
            try:
                delay = float(retry_after) if retry_after else min(2**attempt, 8)
            except ValueError:
                delay = min(2**attempt, 8)
            self._sleep(delay)
        raise ReporterError("ADO reporting retry loop exhausted")

    def _threads(self, job: ReviewJob, pr_id: int) -> list[dict[str, Any]]:
        response = self._request(job, "GET", f"pullRequests/{pr_id}/threads")
        payload = response.json()
        return payload.get("value", []) if isinstance(payload, dict) else []

    @staticmethod
    def _all_thread_text(threads: list[dict[str, Any]]) -> str:
        parts: list[str] = []
        for thread in threads:
            for comment in thread.get("comments", []):
                parts.append(str(comment.get("content", "")))
        return "\n".join(parts)

    def publish(self, result: ReviewResult) -> None:
        job = result.job
        iteration_id = result.iteration_id or 0
        marker = f"<!-- ai-pr-security-review: pr={job.pr_id}:iteration={iteration_id} -->"
        threads = self._threads(job, job.pr_id)
        existing = self._all_thread_text(threads)

        summary = result.summary or "Security review completed."
        if result.policy_versions:
            summary += "\n\nActive policy packs: " + ", ".join(f"`{version}`" for version in result.policy_versions)
        if result.regulation_context:
            references = ", ".join(
                f"{item.get('title', 'Regulation')} v{item.get('version', '')}" for item in result.regulation_context
            )
            summary += f"\n\nApproved regulation context considered: {references}"
        if result.triage and result.triage.error:
            summary += f"\n\nLLM triage was unavailable; deterministic findings are shown unchanged."
        if result.coverage_gaps:
            summary += "\n\nCoverage gaps (not a clean compliance result):\n" + "\n".join(
                f"- {item}" for item in result.coverage_gaps
            )
        unpositioned = [finding for finding in result.findings if not finding.file or finding.line <= 0 or not finding.inline_comment]
        if unpositioned:
            summary += "\n\nFindings without an inline location:\n" + "\n".join(
                f"- **{finding.severity}** `{finding.rule_id}` — {finding.message}"
                for finding in unpositioned
            )
        policy_unpositioned = [finding for finding in unpositioned if finding.control_id]
        if policy_unpositioned:
            summary += "\n\nPolicy evidence for findings outside this diff:\n"
            for finding in policy_unpositioned:
                summary += "\n" + self._policy_body(finding, "", None) + f"\n\nRepository location: `{finding.file}:{finding.line}`\n"
        summary_content = (
            f"{marker}\n## AI PR Security Review\n\n{summary}\n\n"
            f"Findings: {len(result.findings)} | Run: `{result.run_id}`"
        )
        if marker not in existing:
            self._request(
                job,
                "POST",
                f"pullRequests/{job.pr_id}/threads",
                {
                    "comments": [{"parentCommentId": 0, "content": summary_content, "commentType": 1}],
                    "status": "active",
                },
            )

        triage_by_fingerprint = {
            item.fingerprint: item for item in (result.triage.items if result.triage else [])
        }
        for finding in result.findings:
            finding_marker = f"{marker[:-4]}:fingerprint={finding.fingerprint} -->"
            if finding_marker in existing:
                continue
            if not finding.file or finding.line <= 0 or not finding.inline_comment:
                continue
            triage = triage_by_fingerprint.get(finding.fingerprint)
            body = self._policy_body(finding, finding_marker, triage) if finding.control_id else (
                f"{finding_marker}\n**{finding.severity}** `{finding.rule_id}` — {finding.message}\n\n"
                f"OWASP: {finding.owasp}\n\n"
                f"{triage.explanation if triage and triage.explanation else finding.fix_hint}"
            )
            thread: dict[str, Any] = {
                "comments": [{"parentCommentId": 0, "content": body, "commentType": 1}],
                "status": "active",
            }
            if finding.file and finding.line > 0:
                thread["threadContext"] = {
                    "filePath": finding.file,
                    "rightFileStart": {"line": finding.line, "offset": 1},
                    "rightFileEnd": {"line": finding.end_line or finding.line, "offset": 1},
                }
            self._request(job, "POST", f"pullRequests/{job.pr_id}/threads", thread)

        state = "succeeded" if result.status.startswith("completed") else "error"
        self._request(
            job,
            "POST",
            f"pullRequests/{job.pr_id}/statuses",
            {
                "state": state,
                "description": f"Advisory review completed with {len(result.findings)} finding(s)",
                "context": {"name": "ai-pr-security-review", "genre": "security"},
                "targetUrl": "",
            },
        )
