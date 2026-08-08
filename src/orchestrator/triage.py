"""Azure OpenAI triage with a strict, deterministic-output boundary."""

from __future__ import annotations

import json
import os
from typing import Any, Protocol

from azure.identity import DefaultAzureCredential, get_bearer_token_provider
from openai import OpenAI
import tiktoken

from ado_client import PrDiff
from models import TriageItem, TriageResult
from scanner import Finding


class TriageError(RuntimeError):
    """Raised when the LLM response cannot be safely consumed."""


class TriageClient(Protocol):
    def triage(
        self,
        diff: PrDiff,
        findings: list[Finding],
        policy_context: dict[str, Any] | None = None,
    ) -> TriageResult:
        ...


def _finding_payload(finding: Finding) -> dict[str, Any]:
    return {
        "fingerprint": finding.fingerprint,
        "tool": finding.tool,
        "rule_id": finding.rule_id,
        "file": finding.file,
        "line": finding.line,
        "end_line": finding.end_line,
        "severity": finding.severity,
        "message": finding.message,
        "owasp": finding.owasp,
        "fix_hint": finding.fix_hint,
        "control_id": finding.control_id,
        "control_version": finding.control_version,
        "reason": finding.reason,
        "policy_document": finding.policy_document,
        "policy_version": finding.policy_version,
        "source_reference": finding.source_reference,
        "confidence": finding.confidence,
        "review_required": finding.review_required,
    }


class NoopTriageClient:
    """Safe local fallback used when no Azure OpenAI endpoint is configured."""

    def triage(
        self,
        diff: PrDiff,
        findings: list[Finding],
        policy_context: dict[str, Any] | None = None,
    ) -> TriageResult:
        if not findings:
            return TriageResult(summary="No deterministic security findings were produced.")
        return TriageResult(
            summary="LLM triage is not configured; deterministic findings are reported unchanged.",
            error="Azure OpenAI endpoint is not configured",
        )


class AzureOpenAITriageClient:
    def __init__(
        self,
        *,
        endpoint: str | None = None,
        deployment: str | None = None,
        max_input_tokens: int | None = None,
        max_output_tokens: int | None = None,
        reasoning_effort: str | None = None,
        client: Any | None = None,
    ):
        self.deployment = deployment or os.environ.get("AZURE_OPENAI_DEPLOYMENT", "")
        self.max_input_tokens = max_input_tokens or int(os.environ.get("LLM_MAX_INPUT_TOKENS", "100000"))
        self.max_output_tokens = max_output_tokens or int(
            os.environ.get("LLM_MAX_OUTPUT_TOKENS", os.environ.get("LLM_MAX_TOKENS", "8000"))
        )
        self.reasoning_effort = reasoning_effort or os.environ.get("LLM_REASONING_EFFORT", "medium")
        if self.reasoning_effort not in {"low", "medium", "high"}:
            raise TriageError("LLM_REASONING_EFFORT must be low, medium, or high")
        if client is not None:
            self.client = client
            return

        resolved_endpoint = endpoint or os.environ.get("AZURE_OPENAI_ENDPOINT", "")
        if not resolved_endpoint or not self.deployment:
            raise TriageError("AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_DEPLOYMENT are required")
        api_key = os.environ.get("AZURE_OPENAI_API_KEY", "")
        if api_key and os.environ.get("HACKATHON_MODE", "").lower() != "true":
            raise TriageError("Azure OpenAI API keys are permitted only when HACKATHON_MODE=true")
        token_provider = api_key or get_bearer_token_provider(
            DefaultAzureCredential(),
            "https://ai.azure.com/.default",
        )
        self.client = OpenAI(
            base_url=f"{resolved_endpoint.rstrip('/')}/openai/v1/",
            api_key=token_provider,
            timeout=float(os.environ.get("LLM_TIMEOUT_SECONDS", "90")),
        )

    @staticmethod
    def _encoding():
        """GPT-5.4 mini uses the modern OpenAI tokenizer; this is a local cost guard."""
        try:
            return tiktoken.encoding_for_model("gpt-5.4-mini")
        except KeyError:
            return tiktoken.get_encoding("o200k_base")

    @classmethod
    def _trim_to_tokens(cls, value: str, limit: int) -> str:
        if limit <= 0:
            return ""
        encoding = cls._encoding()
        tokens = encoding.encode(value)
        if len(tokens) <= limit:
            return value
        return encoding.decode(tokens[:limit]) + "\n[AI context truncated to configured token budget]"

    @staticmethod
    def _prioritize_finding_files(diff: PrDiff, findings: list[Finding]) -> str:
        """Put affected-file diff blocks first so a bounded prompt keeps useful evidence."""
        marker = "diff --git "
        blocks = [marker + block for block in diff.raw_diff.split(marker) if block]
        if not blocks:
            return diff.raw_diff

        finding_paths = {finding.file for finding in findings if finding.file}
        focused = [
            block
            for block in blocks
            if any(f"a{path} b{path}" in block for path in finding_paths)
        ]
        remaining = [block for block in blocks if block not in focused]
        return "".join([*focused, *remaining])

    def _request_payload(
        self,
        diff: PrDiff,
        findings: list[Finding],
        policy_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        normalized_findings = [_finding_payload(finding) for finding in findings]
        policy = policy_context or {}
        regulation_context = [
            {
                "document_id": item.get("document_id"),
                "title": item.get("title"),
                "version": item.get("version"),
                "effective_date": item.get("effective_date"),
                "source_url": item.get("source_url"),
                "chunk_id": item.get("chunk_id"),
                "content": item.get("content"),
            }
            for item in policy.get("regulations", [])[:5]
            if isinstance(item, dict)
        ]
        request_context = {
            "findings": normalized_findings,
            "approved_policy_versions": policy.get("rule_packs", []),
            "approved_regulation_context": regulation_context,
        }
        findings_only = json.dumps(request_context, ensure_ascii=False)
        encoding = self._encoding()
        # Reserve system/message framing and a truncation marker. The remaining budget is raw PR context.
        reserved_tokens = len(encoding.encode(findings_only)) + 512
        diff_budget = self.max_input_tokens - reserved_tokens
        if diff_budget <= 0:
            raise TriageError("Normalized findings exceed the configured Azure OpenAI input budget")
        return {
            "diff": self._trim_to_tokens(
                self._prioritize_finding_files(diff, findings),
                diff_budget,
            ),
            **request_context,
        }

    def triage(
        self,
        diff: PrDiff,
        findings: list[Finding],
        policy_context: dict[str, Any] | None = None,
    ) -> TriageResult:
        if not findings:
            return TriageResult(summary="No deterministic security findings were produced.")

        request = self._request_payload(diff, findings, policy_context)
        try:
            response = self.client.chat.completions.create(
                model=self.deployment,
                max_completion_tokens=self.max_output_tokens,
                reasoning_effort=self.reasoning_effort,
                response_format={"type": "json_object"},
                messages=[
                    {
                        "role": "developer",
                        "content": (
                            "You triage deterministic security findings. Return JSON only with keys "
                            "summary and items. Never remove or invent findings. Each item must include "
                            "fingerprint, priority, likely_false_positive, explanation, and fix_hint. "
                            "Approved policy and regulation context is advisory evidence only. Cite a "
                            "document title/version in an explanation only when it is relevant."
                        ),
                    },
                    {"role": "user", "content": json.dumps(request, ensure_ascii=False)},
                ],
            )
            content = response.choices[0].message.content
            return self._parse_result(content, findings)
        except TriageError:
            raise
        except Exception as exc:
            raise TriageError(f"Azure OpenAI triage failed: {exc}") from exc

    @staticmethod
    def _parse_result(content: str | None, findings: list[Finding]) -> TriageResult:
        if not content:
            raise TriageError("Azure OpenAI returned an empty triage response")
        try:
            payload = json.loads(content)
        except json.JSONDecodeError as exc:
            raise TriageError("Azure OpenAI returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise TriageError("Triage response must be a JSON object")

        known = {finding.fingerprint for finding in findings}
        items: list[TriageItem] = []
        for raw in payload.get("items", []):
            if not isinstance(raw, dict) or raw.get("fingerprint") not in known:
                continue
            priority = str(raw.get("priority", "medium")).lower()
            if priority not in {"critical", "high", "medium", "low", "info"}:
                priority = "medium"
            items.append(
                TriageItem(
                    fingerprint=str(raw["fingerprint"]),
                    priority=priority,
                    likely_false_positive=bool(raw.get("likely_false_positive", False)),
                    explanation=str(raw.get("explanation", "")),
                    fix_hint=str(raw.get("fix_hint", "")),
                )
            )

        summary = payload.get("summary")
        if isinstance(summary, str) and summary.strip():
            return TriageResult(summary=summary, items=items)
        if not items:
            # Nothing usable came back; fail so the caller reports deterministic findings unchanged.
            raise TriageError("Triage response must contain a string summary")
        # Keep the per-finding triage rather than discarding it over a missing summary field.
        return TriageResult(summary=f"Prioritized {len(items)} of {len(findings)} findings.", items=items)
