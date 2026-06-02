"""
Orchestrator — Container Apps job (US-05 + US-06 entry point)

Pulled triggered by a Service Bus message (one message = one PR review job).
Flow:
  1. Deserialise the job payload from Service Bus
  2. Fetch the PR diff from Azure DevOps (US-05)
  3. Run Semgrep + secret scan on changed files (US-06)
  4. (Sprint 2) LLM triage → post PR comments
"""

from __future__ import annotations

import json
import logging
import os
import sys

from azure.identity import DefaultAzureCredential
from azure.servicebus import ServiceBusClient

from ado_client import AdoClient
from scanner import scan

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


def process_job(job: dict) -> None:
    org_url  = job["organization_url"]
    project  = job["project"]
    repo_id  = job["repo_id"]
    pr_id    = int(job["pr_id"])
    source   = job["source_branch"]

    logger.info("Processing PR #%d in %s / %s", pr_id, project, job.get("repo_name"))

    # US-05 — fetch diff
    ado = AdoClient(org_url=org_url, project=project, repo_id=repo_id)
    diff = ado.fetch_diff(pr_id=pr_id, source_branch=source)

    # US-06 — scan changed files (skip deleted files, they have no content)
    scannable = {
        f.path: f.content
        for f in diff.changed_files
        if f.change_type != "delete" and f.content
    }

    if not scannable:
        logger.info("No scannable files in PR #%d — skipping", pr_id)
        return

    findings = scan(scannable)
    logger.info("Total findings for PR #%d: %d", pr_id, len(findings))

    # TODO (US-07): pass diff + findings to LLM triage
    # TODO (US-08): post summary + inline comments back to ADO

    for f in findings:
        logger.info("[%s] %s %s:%d — %s", f.severity, f.rule_id, f.file, f.line, f.message[:120])


def run_once() -> None:
    """Receive one message from Service Bus, process it, complete (ack) it."""
    sb_ns    = os.environ["SERVICE_BUS_NAMESPACE"]
    queue    = os.environ.get("SERVICE_BUS_QUEUE", "pr-review-jobs")
    cred     = DefaultAzureCredential()

    with ServiceBusClient(
        fully_qualified_namespace=f"{sb_ns}.servicebus.windows.net",
        credential=cred,
    ) as client:
        with client.get_queue_receiver(queue_name=queue, max_wait_time=30) as receiver:
            messages = receiver.receive_messages(max_message_count=1, max_wait_time=30)
            if not messages:
                logger.info("No messages — nothing to do")
                return

            msg = messages[0]
            try:
                job = json.loads(str(msg))
                process_job(job)
                receiver.complete_message(msg)
                logger.info("Message completed (ack)")
            except Exception as exc:
                logger.exception("Failed to process job: %s", exc)
                receiver.abandon_message(msg)
                sys.exit(1)


if __name__ == "__main__":
    run_once()
