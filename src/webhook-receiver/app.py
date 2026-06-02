"""
Webhook receiver — Azure Functions HTTP trigger (US-04 placeholder)

Receives Azure DevOps pull request service hook events, validates the HMAC
signature, and enqueues a PR review job on Service Bus.

This module is the Sprint 1 entry point. Sprint 0 provides:
  - The deployed Azure infrastructure (see infra/)
  - This Docker image built and pushed to ACR via CI

Sprint 1 (US-04) will replace the stub below with real signature validation
and Service Bus enqueue logic.
"""

import hashlib
import hmac
import json
import logging
import os

logger = logging.getLogger(__name__)


def validate_ado_signature(body: bytes, signature_header: str, secret: str) -> bool:
    """
    Validates the HMAC-SHA1 signature sent by Azure DevOps service hooks.
    ADO sends: X-Hub-Signature: sha1=<hex-digest>
    """
    if not signature_header or not signature_header.startswith("sha1="):
        return False
    expected = hmac.new(secret.encode(), body, hashlib.sha1).hexdigest()
    received = signature_header.removeprefix("sha1=")
    return hmac.compare_digest(expected, received)


def build_job_payload(event: dict) -> dict:
    """Extracts the fields the orchestrator needs from an ADO PR event."""
    resource = event.get("resource", {})
    repo = resource.get("repository", {})
    return {
        "pr_id": resource.get("pullRequestId"),
        "title": resource.get("title"),
        "source_branch": resource.get("sourceRefName"),
        "target_branch": resource.get("targetRefName"),
        "repo_id": repo.get("id"),
        "repo_name": repo.get("name"),
        "project": repo.get("project", {}).get("name"),
        "organization_url": event.get("resourceContainers", {})
                                  .get("collection", {})
                                  .get("href", ""),
        "event_type": event.get("eventType"),
    }


def handler(request_body: bytes, headers: dict) -> dict:
    """
    Entry point called by the Azure Functions HTTP trigger binding.
    Returns a dict with 'status' (int) and 'body' (str).

    Sprint 1 will wire this to:
      - real Key Vault secret retrieval (ado-webhook-secret)
      - Service Bus enqueue via azure-servicebus SDK
    """
    secret = os.environ.get("ADO_WEBHOOK_SECRET", "")

    sig = headers.get("x-hub-signature") or headers.get("X-Hub-Signature", "")
    if secret and not validate_ado_signature(request_body, sig, secret):
        logger.warning("Invalid webhook signature — request rejected")
        return {"status": 401, "body": "Unauthorized"}

    try:
        event = json.loads(request_body)
    except json.JSONDecodeError:
        logger.error("Failed to parse request body as JSON")
        return {"status": 400, "body": "Bad Request"}

    event_type = event.get("eventType", "")
    if event_type not in ("git.pullrequest.created", "git.pullrequest.updated"):
        # Ignore irrelevant event types silently
        return {"status": 200, "body": "OK (ignored)"}

    job = build_job_payload(event)
    logger.info("PR event received: %s / PR #%s", job["repo_name"], job["pr_id"])

    # TODO (US-04): enqueue `job` on Service Bus queue 'pr-review-jobs'
    # from azure.servicebus import ServiceBusClient, ServiceBusMessage
    # sb_client = ServiceBusClient(...)
    # with sb_client.get_queue_sender(queue_name) as sender:
    #     sender.send_messages(ServiceBusMessage(json.dumps(job)))

    return {"status": 202, "body": "Accepted"}
