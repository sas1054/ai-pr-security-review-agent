"""
Webhook receiver — Azure Functions HTTP trigger (US-04)

Receives Azure DevOps pull request service hook events, validates the HMAC
signature, and enqueues a PR review job on Service Bus.
Secrets are read from Key Vault via DefaultAzureCredential (managed identity
in Azure; az login / env vars locally).
"""

import hashlib
import hmac
import json
import logging
import os

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.servicebus import ServiceBusClient, ServiceBusMessage

logger = logging.getLogger(__name__)

# ── Lazy-initialised clients (one instance per cold start) ───────────────────

_credential: DefaultAzureCredential | None = None
_sb_client: ServiceBusClient | None = None
_kv_client: SecretClient | None = None


def _get_credential() -> DefaultAzureCredential:
    global _credential
    if _credential is None:
        _credential = DefaultAzureCredential()
    return _credential


def _get_kv_client() -> SecretClient | None:
    """Returns None when KV_URI is not set (local dev without Key Vault)."""
    global _kv_client
    kv_uri = os.environ.get("KEY_VAULT_URI")
    if not kv_uri:
        return None
    if _kv_client is None:
        _kv_client = SecretClient(vault_url=kv_uri, credential=_get_credential())
    return _kv_client


def _get_sb_client() -> ServiceBusClient | None:
    """Returns None when SB_NAMESPACE is not set (local dev without Service Bus)."""
    global _sb_client
    sb_ns = os.environ.get("SERVICE_BUS_NAMESPACE")
    if not sb_ns:
        return None
    if _sb_client is None:
        _sb_client = ServiceBusClient(
            fully_qualified_namespace=f"{sb_ns}.servicebus.windows.net",
            credential=_get_credential(),
        )
    return _sb_client


# ── Secret resolution ────────────────────────────────────────────────────────

def _get_webhook_secret() -> str:
    """
    Resolution order:
      1. ADO_WEBHOOK_SECRET env var (local dev / test)
      2. Key Vault secret 'ado-webhook-secret' (production)
    """
    env_val = os.environ.get("ADO_WEBHOOK_SECRET", "")
    if env_val:
        return env_val
    kv = _get_kv_client()
    if kv:
        try:
            return kv.get_secret("ado-webhook-secret").value or ""
        except Exception:
            logger.warning("Could not read ado-webhook-secret from Key Vault")
    return ""


# ── Signature validation ─────────────────────────────────────────────────────

def validate_ado_signature(body: bytes, signature_header: str, secret: str) -> bool:
    """Validates the HMAC-SHA1 signature sent by Azure DevOps service hooks."""
    if not signature_header or not signature_header.startswith("sha1="):
        return False
    expected = hmac.new(secret.encode(), body, hashlib.sha1).hexdigest()
    received = signature_header.removeprefix("sha1=")
    return hmac.compare_digest(expected, received)


# ── Payload extraction ───────────────────────────────────────────────────────

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
        "organization_url": (
            event.get("resourceContainers", {})
                 .get("collection", {})
                 .get("href", "")
                 .rstrip("/")
        ),
        "event_type": event.get("eventType"),
    }


# ── Service Bus enqueue ───────────────────────────────────────────────────────

def enqueue_job(job: dict) -> None:
    """
    Sends the job payload to the Service Bus queue.
    Falls back to a log-only warning when Service Bus is not configured
    (local dev mode).
    """
    queue_name = os.environ.get("SERVICE_BUS_QUEUE", "pr-review-jobs")
    sb = _get_sb_client()
    if sb is None:
        logger.warning("SERVICE_BUS_NAMESPACE not set — job not enqueued (dev mode): %s", job)
        return
    with sb.get_queue_sender(queue_name=queue_name) as sender:
        sender.send_messages(ServiceBusMessage(json.dumps(job)))
    logger.info("Enqueued PR #%s to %s", job.get("pr_id"), queue_name)


# ── Main handler ─────────────────────────────────────────────────────────────

def handler(request_body: bytes, headers: dict) -> dict:
    """
    Entry point called by the Azure Functions HTTP trigger binding.
    Returns {'status': int, 'body': str}.
    """
    secret = _get_webhook_secret()

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
        return {"status": 200, "body": "OK (ignored)"}

    job = build_job_payload(event)
    logger.info("PR event received: %s / PR #%s", job["repo_name"], job["pr_id"])

    enqueue_job(job)
    return {"status": 202, "body": "Accepted"}
