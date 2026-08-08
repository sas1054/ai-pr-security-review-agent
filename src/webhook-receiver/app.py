"""
Webhook receiver — Azure Functions HTTP trigger (US-04).

Receives Azure DevOps pull request service hook events and enqueues a
versioned PR review job on Service Bus. Request authentication is enforced by
the Azure Functions host through a Function key; Azure DevOps Web Hooks do not
produce HMAC signatures.
"""

import hashlib
import json
import logging
import os
from typing import Any

from azure.identity import DefaultAzureCredential
from azure.servicebus import ServiceBusClient, ServiceBusMessage
from prsa_control import get_control_plane

logger = logging.getLogger(__name__)

# ── Lazy-initialised clients (one instance per cold start) ───────────────────

_credential: DefaultAzureCredential | None = None
_sb_client: ServiceBusClient | None = None


def _get_credential() -> DefaultAzureCredential:
    global _credential
    if _credential is None:
        _credential = DefaultAzureCredential()
    return _credential


def _get_sb_client() -> ServiceBusClient | None:
    """Use a limited connection string in hackathon mode, otherwise managed identity."""
    global _sb_client
    connection_string = os.environ.get("SERVICE_BUS_CONNECTION_STRING")
    sb_ns = os.environ.get("SERVICE_BUS_NAMESPACE")
    if not connection_string and not sb_ns:
        return None
    if _sb_client is None:
        if connection_string:
            _sb_client = ServiceBusClient.from_connection_string(connection_string)
        else:
            _sb_client = ServiceBusClient(
                fully_qualified_namespace=f"{sb_ns}.servicebus.windows.net",
                credential=_get_credential(),
            )
    return _sb_client


# ── Payload extraction ───────────────────────────────────────────────────────

def build_job_payload(event: dict, event_id: str | None = None) -> dict:
    """Extracts the versioned job envelope from an ADO PR event."""
    resource = event.get("resource", {})
    repo = resource.get("repository", {})
    collection = event.get("resourceContainers", {}).get("collection", {})
    return {
        "job_version": 1,
        "event_id": event_id or str(event.get("id") or ""),
        "pr_id": resource.get("pullRequestId"),
        "title": resource.get("title"),
        "source_branch": resource.get("sourceRefName"),
        "target_branch": resource.get("targetRefName"),
        "repo_id": repo.get("id"),
        "repo_name": repo.get("name"),
        "project": repo.get("project", {}).get("name"),
        "organization_url": (
            collection.get("href")
            or collection.get("baseUrl", "")
                 .rstrip("/")
        ),
        "event_type": event.get("eventType"),
    }


def validate_job_payload(job: dict[str, Any]) -> list[str]:
    """Returns missing required fields before a job is put on the queue."""
    required = (
        "event_id",
        "event_type",
        "organization_url",
        "project",
        "repo_id",
        "repo_name",
        "pr_id",
        "source_branch",
        "target_branch",
    )
    return [name for name in required if job.get(name) in (None, "")]


# ── Service Bus enqueue ───────────────────────────────────────────────────────

def enqueue_job(job: dict) -> bool:
    """
    Sends the job payload to the Service Bus queue.
    Raises when Service Bus has not been configured.
    """
    queue_name = os.environ.get("SERVICE_BUS_QUEUE", "pr-review-jobs")
    sb = _get_sb_client()
    if sb is None:
        raise RuntimeError("SERVICE_BUS_NAMESPACE or SERVICE_BUS_CONNECTION_STRING is required")
    with sb.get_queue_sender(queue_name=queue_name) as sender:
        sender.send_messages(ServiceBusMessage(json.dumps(job)))
    logger.info("Enqueued PR #%s to %s", job.get("pr_id"), queue_name)
    return True


def review_run_id(job: dict[str, Any]) -> str:
    """Create a stable run identifier so duplicate webhook deliveries stay one visible run."""
    identity = "|".join(
        str(job.get(key, ""))
        for key in ("organization_url", "repo_id", "pr_id", "event_id", "event_type")
    )
    return f"run-{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:24]}"


def queue_review_job(job: dict[str, Any], controls: Any | None = None) -> dict[str, Any]:
    """Persist queued state, enqueue the work, and preserve failures for the monitoring UI."""
    controls = controls or get_control_plane()
    queued_job = dict(job)
    run_id = str(queued_job.get("run_id") or review_run_id(queued_job))
    queued_job["run_id"] = run_id
    existing = controls.get_review(run_id)
    if existing:
        return {"run_id": run_id, "queued": False, "status": str(existing.get("status", "queued"))}

    controls.record_review_queued(queued_job, run_id)
    try:
        enqueue_job(queued_job)
    except Exception as exc:
        controls.mark_review_failed(queued_job, run_id, str(exc), enqueue_failed=True)
        raise
    return {"run_id": run_id, "queued": True, "status": "queued"}


def queue_policy_job(document_id: str, version: str, *, actor: str = "admin", controls: Any | None = None) -> dict[str, Any]:
    """Persist and enqueue an asynchronous natural-language policy ingestion job."""
    controls = controls or get_control_plane()
    record = controls.record_policy_job(document_id, version, actor=actor)
    job = {
        "job_version": 1,
        "job_kind": "policy_ingestion",
        "job_id": record["job_id"],
        "document_id": document_id,
        "policy_version": version,
    }
    try:
        enqueue_job(job)
    except Exception as exc:
        controls.update_policy_job(record["job_id"], status="failed", phase="Queue delivery failed", errors=[str(exc)[:1000]])
        raise
    return record


# ── Main handler ─────────────────────────────────────────────────────────────

def handler(request_body: bytes) -> dict:
    """
    Business-logic entry point called after Azure Functions host authentication.
    Returns {'status': int, 'body': str}.
    """
    try:
        event = json.loads(request_body)
    except json.JSONDecodeError:
        logger.error("Failed to parse request body as JSON")
        return {"status": 400, "body": "Bad Request"}

    event_type = event.get("eventType", "")
    accepted_events = {"git.pullrequest.created"}
    controls = get_control_plane()
    configured_updates = os.environ.get("REVIEW_ON_UPDATED_EVENTS")
    review_on_updates = (
        configured_updates.lower() == "true"
        if configured_updates is not None
        else bool(controls.get_settings().get("review_on_updated", True))
    )
    if review_on_updates:
        accepted_events.add("git.pullrequest.updated")
    if event_type not in accepted_events:
        return {"status": 200, "body": "OK (ignored)"}

    event_id = str(event.get("id") or hashlib.sha256(request_body).hexdigest())
    job = build_job_payload(event, event_id=event_id)
    missing = validate_job_payload(job)
    if missing:
        logger.error("PR event missing required fields: %s", ", ".join(missing))
        return {"status": 400, "body": "Bad Request"}
    if not controls.review_enabled_for(str(job["repo_id"])):
        logger.info("Review ignored because an administrator disabled this repository")
        return {"status": 200, "body": "OK (reviews disabled)"}
    logger.info("PR event received: %s / PR #%s", job["repo_name"], job["pr_id"])

    try:
        queued = queue_review_job(job, controls)
    except Exception:
        logger.exception("Could not enqueue PR review job")
        return {"status": 503, "body": "Service Unavailable"}
    if not queued["queued"]:
        logger.info("Duplicate PR event ignored for run_id=%s", queued["run_id"])
        return {"status": 200, "body": "OK (duplicate)"}
    return {"status": 202, "body": "Accepted"}
