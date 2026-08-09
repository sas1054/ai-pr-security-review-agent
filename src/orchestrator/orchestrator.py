"""Service Bus worker and pure review-pipeline orchestration."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import uuid
from collections.abc import Callable
from typing import Any

from azure.identity import DefaultAzureCredential
from azure.servicebus import ServiceBusClient

from ado_client import AdoClient, PrDiff
from models import ReviewJob, ReviewResult, TriageResult
from prsa_control import ControlPlane, get_control_plane
from policy_engine import AzureOpenAISemanticControlScanner, process_policy_job
from reporter import AdoReporter
from scanner import Finding, scan
from telemetry import configure_telemetry
from triage import AzureOpenAITriageClient, NoopTriageClient, TriageClient, TriageError

configure_telemetry()

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)


class RunContext(logging.LoggerAdapter):
    def process(self, msg: str, kwargs: dict[str, Any]):
        return f"run_id={self.extra['run_id']} {msg}", kwargs


def _summary(findings: list[Finding], triage: TriageResult | None) -> str:
    if not findings:
        return "No deterministic security findings were found in the changed files."
    if triage and triage.summary:
        return triage.summary
    return f"Security review found {len(findings)} deterministic finding(s)."


def _review_record(result: ReviewResult) -> dict[str, Any]:
    """Persist review evidence without retaining the raw source diff."""
    return {
        "run_id": result.run_id,
        "status": result.status,
        "phase": "Review completed and advisory results were published.",
        "summary": result.summary,
        "duration_ms": result.duration_ms,
        "iteration_id": result.iteration_id,
        "repo_id": result.job.repo_id,
        "repo_name": result.job.repo_name,
        "project": result.job.project,
        "pr_id": result.job.pr_id,
        "title": result.job.title,
        "counts": result.counts,
        "errors": result.errors,
        "job": {
            "job_version": result.job.job_version,
            "event_id": result.job.event_id,
            "event_type": result.job.event_type,
            "organization_url": result.job.organization_url,
            "project": result.job.project,
            "repo_id": result.job.repo_id,
            "repo_name": result.job.repo_name,
            "pr_id": result.job.pr_id,
            "source_branch": result.job.source_branch,
            "target_branch": result.job.target_branch,
            "title": result.job.title,
        },
        "findings": [
            {
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
                "matched_value": finding.matched_value,
                "review_required": finding.review_required,
                "exception_id": finding.exception_id,
                "inline_comment": finding.inline_comment,
            }
            for finding in result.findings
        ],
        "suppressed_findings": [
            {
                "fingerprint": finding.fingerprint,
                "control_id": finding.control_id,
                "control_version": finding.control_version,
                "file": finding.file,
                "line": finding.line,
                "matched_value": finding.matched_value,
                "exception_id": finding.exception_id,
            }
            for finding in result.suppressed_findings
        ],
        "applicable_exceptions": [
            {
                key: item.get(key)
                for key in (
                    "exception_id", "control_id", "control_version", "repository_id", "project", "approved_value",
                    "business_justification", "approver", "approved_at", "expiration_date", "reference_ticket",
                )
            }
            for item in result.applicable_exceptions
        ],
        "coverage_gaps": result.coverage_gaps,
        "control_snapshot": result.control_snapshot,
        "triage": {
            "summary": result.triage.summary,
            "error": result.triage.error,
            "items": [item.__dict__ for item in result.triage.items],
        }
        if result.triage
        else None,
        "policy_versions": result.policy_versions,
        "regulation_context": [
            {
                key: item.get(key, "")
                for key in ("document_id", "title", "version", "effective_date", "source_url", "chunk_id")
            }
            for item in result.regulation_context
        ],
    }


def _apply_exceptions(
    findings: list[Finding], exceptions: list[dict[str, Any]], job: ReviewJob
) -> tuple[list[Finding], list[Finding], list[dict[str, Any]]]:
    visible: list[Finding] = []
    suppressed: list[Finding] = []
    applied: dict[str, dict[str, Any]] = {}
    for finding in findings:
        match: dict[str, Any] | None = None
        for exception in exceptions:
            if exception.get("status") != "approved" or exception.get("control_id") != finding.control_id:
                continue
            if str(exception.get("control_version") or "*") not in {"*", finding.control_version}:
                continue
            if str(exception.get("repository_id") or "*") not in {"*", job.repo_id}:
                continue
            if str(exception.get("project") or "*") not in {"*", job.project}:
                continue
            approved_value = str(exception.get("approved_value") or "*")
            if approved_value != "*" and approved_value.casefold() != finding.matched_value.casefold():
                continue
            match = exception
            break
        if match:
            finding.exception_id = str(match.get("exception_id") or "")
            suppressed.append(finding)
            applied[finding.exception_id] = match
        else:
            visible.append(finding)
    return visible, suppressed, list(applied.values())


def _applicable_controls(controls: list[dict[str, Any]], job: ReviewJob) -> list[dict[str, Any]]:
    applicable: list[dict[str, Any]] = []
    for control in controls:
        scope = control.get("scope") if isinstance(control.get("scope"), dict) else {}
        repositories = {str(item) for item in scope.get("repository_ids", scope.get("repositories", []))}
        projects = {str(item) for item in scope.get("projects", [])}
        branches = {str(item) for item in scope.get("target_branches", [])}
        if repositories and job.repo_id not in repositories and job.repo_name not in repositories:
            continue
        if projects and job.project not in projects:
            continue
        if branches and job.target_branch not in branches and job.target_branch.removeprefix("refs/heads/") not in branches:
            continue
        applicable.append(control)
    return applicable


def process_review(
    job: ReviewJob | dict[str, Any],
    *,
    ado: AdoClient,
    scanner: Callable[[dict[str, str]], list[Finding]] = scan,
    triage_client: TriageClient | None = None,
    reporter: AdoReporter | None = None,
    control_plane: ControlPlane | None = None,
    run_id: str | None = None,
    semantic_scanner: Any | None = None,
) -> ReviewResult:
    """Process one review without coupling the domain flow to Service Bus."""
    review_job = job if isinstance(job, ReviewJob) else ReviewJob.from_dict(job)
    run_id = run_id or str(uuid.uuid4())
    run_logger = RunContext(logger, {"run_id": run_id})
    started = time.monotonic()
    run_logger.info("Review started for PR #%s", review_job.pr_id)
    controls = control_plane or get_control_plane()

    if not controls.review_enabled_for(review_job.repo_id):
        result = ReviewResult(
            run_id=run_id,
            job=review_job,
            status="skipped_disabled",
            summary="Security review is disabled for this repository by an administrator.",
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        controls.record_review(_review_record(result))
        run_logger.info("Review skipped because the repository is disabled")
        return result

    diff = ado.fetch_diff(review_job)
    changed_paths = {changed.path.lstrip("/") for changed in diff.changed_files}
    scannable = {
        changed.path: changed.content
        for changed in diff.changed_files
        if changed.change_type != "delete" and changed.content
    }
    policy_rules, legacy_policy_versions = controls.active_rules()
    all_active_controls, _ = controls.active_controls()
    active_controls = _applicable_controls(all_active_controls, review_job)
    coverage_gaps: list[str] = []
    feature_settings = controls.get_settings()
    scanner_flags = {
        "literal_value": "scanner_literal_enabled",
        "pattern": "scanner_pattern_enabled",
        "ast": "scanner_ast_enabled",
        "dependency": "scanner_dependency_enabled",
        "url_domain": "scanner_domain_enabled",
        "config_iac": "scanner_config_iac_enabled",
        "semantic_review": "semantic_review_enabled",
        "manual_review": "semantic_review_enabled",
    }
    disabled_controls = [
        item for item in active_controls
        if not feature_settings.get(scanner_flags.get(str(item.get("control_type")), "policy_engine_enabled"), True)
    ]
    if disabled_controls:
        coverage_gaps.append(
            "Active controls skipped by scanner feature flags: "
            + ", ".join(f"{item.get('control_id')}@{item.get('version')}" for item in disabled_controls)
        )
    active_controls = [item for item in active_controls if item not in disabled_controls]
    control_versions = [f"{item['control_id']}@{item['version']}" for item in active_controls]
    relevant_types = {str(item.get("control_type") or "") for item in active_controls}
    if "dependency" in relevant_types:
        unsupported = [
            path
            for path in scannable
            if path.rsplit("/", 1)[-1].lower()
            in {"cargo.toml", "cargo.lock", "gemfile", "gemfile.lock", "composer.json", "composer.lock", "mix.exs", "pubspec.yaml"}
        ]
        if unsupported:
            coverage_gaps.append("Unsupported dependency manifests changed: " + ", ".join(sorted(unsupported)[:10]))
    if hasattr(ado, "fetch_relevant_policy_files") and relevant_types & {"dependency", "config_iac"}:
        try:
            supplemental, supplemental_gaps = ado.fetch_relevant_policy_files(
                review_job.source_branch.removeprefix("refs/heads/"), set(scannable), relevant_types
            )
            scannable.update(supplemental)
            coverage_gaps.extend(supplemental_gaps)
        except Exception as exc:
            coverage_gaps.append(f"Could not fetch relevant policy files: {exc}")
    if scannable:
        findings = scan(scannable, policy_rules=policy_rules, controls=active_controls) if scanner is scan else scanner(scannable)
    else:
        findings = []
    manual_controls = [item for item in active_controls if item.get("control_type") in {"semantic_review", "manual_review"}]
    if manual_controls and scannable:
        semantic_findings: list[Finding] = []
        if semantic_scanner is not None:
            try:
                semantic_findings = semantic_scanner.scan(scannable, manual_controls)
                findings.extend(semantic_findings)
            except Exception as exc:
                coverage_gaps.append(f"Semantic policy review failed: {exc}")
        else:
            coverage_gaps.append("Semantic policy controls were active but no semantic scanner was configured")
        represented = {item.control_id for item in semantic_findings}
        for control in manual_controls:
            if control.get("control_type") != "manual_review" or control.get("control_id") in represented:
                continue
            # This control matched nothing; it asks for a human decision about the whole change.
            # Leave it unpositioned so the reporter puts it in the summary instead of blaming a file.
            findings.append(
                Finding(
                    tool="policy-manual-review",
                    rule_id=str(control.get("control_id") or "manual-review"),
                    file="",
                    line=0,
                    severity="WARNING",
                    message=f"Human review required: {control.get('title', 'policy control')}",
                    fix_hint=str(control.get("fix_hint") or "Have Security Engineering review this change."),
                    control_id=str(control.get("control_id") or ""),
                    control_version=str(control.get("version") or ""),
                    reason=str(control.get("prohibited_condition") or control.get("description") or ""),
                    policy_document=str(control.get("policy_title") or control.get("policy_document_id") or ""),
                    policy_version=str(control.get("policy_version") or ""),
                    source_reference=dict(control.get("source_reference") or {}),
                    confidence=0.0,
                    matched_value="",
                    review_required=True,
                    inline_comment=False,
                )
            )
    for finding in findings:
        if finding.file.lstrip("/") not in changed_paths:
            finding.inline_comment = False
    findings, suppressed_findings, applicable_exceptions = _apply_exceptions(
        findings, controls.list_exceptions(include_expired=False), review_job
    )
    policy_versions = [*legacy_policy_versions, *control_versions]
    run_logger.info("Deterministic scan completed: %d findings", len(findings))
    regulation_query = " ".join(
        [review_job.repo_name, review_job.title, *[f"{finding.rule_id} {finding.message}" for finding in findings]]
    )
    regulation_context = controls.search_regulations(regulation_query) if findings else []
    policy_context = {"rule_packs": policy_versions, "regulations": regulation_context}

    triage = triage_client or NoopTriageClient()
    triage_result: TriageResult | None = None
    errors: list[str] = []
    status = "completed"
    try:
        try:
            triage_result = triage.triage(diff, findings, policy_context=policy_context)
        except TypeError as exc:
            # Existing custom test adapters remain compatible during this optional extension.
            if "policy_context" not in str(exc):
                raise
            triage_result = triage.triage(diff, findings)
        if triage_result.error:
            status = "completed_with_triage_error"
            errors.append(triage_result.error)
    except TriageError as exc:
        status = "completed_with_triage_error"
        errors.append(str(exc))
        triage_result = TriageResult(
            summary="LLM triage failed; deterministic findings are reported unchanged.",
            error=str(exc),
        )
        run_logger.exception("LLM triage failed")

    review_summary = _summary(findings, triage_result)
    if manual_controls and not findings:
        review_summary = (
            "No deterministic policy findings were found. Active semantic/manual-review controls do not establish a clean compliance decision."
        )
    result = ReviewResult(
        run_id=run_id,
        job=review_job,
        status=status,
        findings=findings,
        triage=triage_result,
        summary=review_summary,
        counts={
            "findings": len(findings),
            "suppressed_findings": len(suppressed_findings),
            "scannable_files": len(scannable),
            "errors": sum(finding.severity == "ERROR" for finding in findings),
            "warnings": sum(finding.severity == "WARNING" for finding in findings),
            "info": sum(finding.severity == "INFO" for finding in findings),
        },
        errors=errors,
        duration_ms=int((time.monotonic() - started) * 1000),
        iteration_id=diff.iteration_id,
        policy_versions=policy_versions,
        regulation_context=regulation_context,
        suppressed_findings=suppressed_findings,
        applicable_exceptions=applicable_exceptions,
        coverage_gaps=coverage_gaps,
        control_snapshot=[
            {
                "control_id": item.get("control_id"),
                "control_version": item.get("version"),
                "policy_document_id": item.get("policy_document_id"),
                "policy_version": item.get("policy_version"),
                "detector_sha256": item.get("detector_sha256"),
            }
            for item in active_controls
        ],
    )

    controls.record_review(_review_record(result))
    if reporter:
        reporter.publish(result)
    run_logger.info("Review completed with status=%s", result.status)
    return result


def process_job(job: dict[str, Any]) -> ReviewResult:
    """Production entry point used by the queue worker."""
    review_job = ReviewJob.from_dict(job)
    controls = get_control_plane()
    run_id = str(job.get("run_id") or review_job.event_id)
    controls.mark_review_running(job, run_id)
    settings = controls.get_settings()
    ado = AdoClient(
        org_url=review_job.organization_url,
        project=review_job.project,
        repo_id=review_job.repo_id,
        max_files=int(settings["max_changed_files"]),
        max_file_bytes=int(settings["max_file_bytes"]),
        max_total_bytes=int(settings["max_total_bytes"]),
    )
    if os.environ.get("AZURE_OPENAI_ENDPOINT") and os.environ.get("AZURE_OPENAI_DEPLOYMENT"):
        triage: TriageClient = AzureOpenAITriageClient(
            max_input_tokens=int(settings["llm_max_input_tokens"]),
            max_output_tokens=int(settings["llm_max_output_tokens"]),
        )
    else:
        triage = NoopTriageClient()
    reporter = AdoReporter()
    semantic_scanner = None
    if settings.get("semantic_review_enabled") and os.environ.get("AZURE_OPENAI_ENDPOINT") and os.environ.get("AZURE_OPENAI_DEPLOYMENT"):
        semantic_scanner = AzureOpenAISemanticControlScanner()
    return process_review(
        review_job,
        ado=ado,
        triage_client=triage,
        reporter=reporter,
        control_plane=controls,
        run_id=run_id,
        semantic_scanner=semantic_scanner,
    )


def dispatch_job(job: dict[str, Any]) -> Any:
    if job.get("job_kind") == "policy_ingestion":
        return process_policy_job(job, get_control_plane())
    return process_job(job)


def handle_message(
    message: Any,
    receiver: Any,
    *,
    process_fn: Callable[[dict[str, Any]], Any] = dispatch_job,
) -> bool:
    """Process and acknowledge one message, or abandon it on any failure."""
    job: dict[str, Any] | None = None
    try:
        job = json.loads(str(message))
        process_fn(job)
        receiver.complete_message(message)
        logging.LoggerAdapter(logger, {"run_id": job.get("event_id", "-")}).info("Message completed")
        return True
    except Exception as exc:
        if job and job.get("job_kind") == "policy_ingestion":
            try:
                get_control_plane().update_policy_job(str(job.get("job_id") or ""), status="failed", phase="Policy ingestion failed", errors=[str(exc)[:1000]])
            except Exception:
                logger.exception("Could not persist failed policy ingestion state")
        elif job:
            run_id = str(job.get("run_id") or job.get("event_id") or uuid.uuid4())
            try:
                get_control_plane().mark_review_failed(job, run_id, str(exc))
            except Exception:  # pragma: no cover - a monitoring failure must not acknowledge work
                logger.exception("Could not persist failed review state")
        logging.LoggerAdapter(logger, {"run_id": "-"}).exception("Failed to process job: %s", exc)
        receiver.abandon_message(message)
        return False


def _service_bus_client() -> ServiceBusClient:
    """Use a scoped connection string only in the temporary hackathon profile."""
    connection_string = os.environ.get("SERVICE_BUS_CONNECTION_STRING", "")
    if connection_string:
        return ServiceBusClient.from_connection_string(connection_string)

    sb_ns = os.environ["SERVICE_BUS_NAMESPACE"]
    return ServiceBusClient(
        fully_qualified_namespace=f"{sb_ns}.servicebus.windows.net",
        credential=DefaultAzureCredential(),
    )


def run_once() -> None:
    """Receive one Service Bus message and acknowledge only after reporting."""
    queue = os.environ.get("SERVICE_BUS_QUEUE", "pr-review-jobs")

    with _service_bus_client() as client:
        with client.get_queue_receiver(queue_name=queue, max_wait_time=30) as receiver:
            messages = receiver.receive_messages(max_message_count=1, max_wait_time=30)
            if not messages:
                logging.LoggerAdapter(logger, {"run_id": "-"}).info("No messages — nothing to do")
                return

            message = messages[0]
            if not handle_message(message, receiver):
                sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", help="Run a local fixture instead of Service Bus")
    args = parser.parse_args()
    if args.fixture:
        from local_runner import run_fixture

        run_fixture(args.fixture)
        return
    run_once()


if __name__ == "__main__":
    main()
