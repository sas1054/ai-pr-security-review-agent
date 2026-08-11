"""Low-cost persistence and policy management backed by Azure Storage.

The control plane intentionally starts with Tables and Blobs already available to
the Function App and worker.  This keeps the MVP inexpensive while preserving a
stable model for a later vector-search/RAG implementation.
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from azure.core.exceptions import AzureError, ResourceExistsError
from azure.data.tables import TableServiceClient, UpdateMode
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient

logger = logging.getLogger(__name__)

REVIEWS_TABLE = "ReviewRuns"
SETTINGS_TABLE = "ControlSettings"
REPOSITORIES_TABLE = "Repositories"
RULE_PACKS_TABLE = "RulePacks"
REGULATIONS_TABLE = "Regulations"
REGULATION_CHUNKS_TABLE = "RegulationChunks"
AUDIT_TABLE = "AuditEvents"
POLICIES_TABLE = "PolicyDocuments"
POLICY_JOBS_TABLE = "PolicyIngestionJobs"
POLICY_CLAUSES_TABLE = "PolicyClauses"
CONTROLS_TABLE = "PolicyControls"
APPROVALS_TABLE = "ControlApprovals"
EXCEPTIONS_TABLE = "ControlExceptions"
DOCUMENTS_CONTAINER = "regulation-documents"
POLICY_CONTAINER = "policy-artifacts"
TERMINAL_REVIEW_STATUSES = {"completed", "completed_with_triage_error", "skipped_disabled", "failed", "enqueue_failed"}

CONTROL_STATES = {"draft", "needs_clarification", "approved", "active", "suspended", "retired"}
CONTROL_TYPES = {
    "literal_value",
    "pattern",
    "ast",
    "dependency",
    "url_domain",
    "config_iac",
    "semantic_review",
    "manual_review",
}
CONTROL_TRANSITIONS = {
    "draft": {"needs_clarification", "approved", "retired"},
    "needs_clarification": {"draft", "retired"},
    "approved": {"active", "retired"},
    "active": {"suspended", "retired"},
    "suspended": {"active", "retired"},
    "retired": set(),
}

DEFAULT_SETTINGS: dict[str, Any] = {
    "review_enabled": True,
    "review_on_updated": os.environ.get("REVIEW_ON_UPDATED_EVENTS", "true").lower() == "true",
    "max_changed_files": 100,
    "max_file_bytes": 200 * 1024,
    "max_total_bytes": 2 * 1024 * 1024,
    "llm_max_input_tokens": 100000,
    "llm_max_output_tokens": 8000,
    "rag_mode": "keyword",
    "policy_engine_enabled": True,
    "policy_ingestion_enabled": True,
    "control_activation_enabled": True,
    "scanner_literal_enabled": True,
    "scanner_pattern_enabled": True,
    "scanner_ast_enabled": True,
    "scanner_dependency_enabled": True,
    "scanner_domain_enabled": True,
    "scanner_config_iac_enabled": True,
    "semantic_review_enabled": True,
}

SETTING_KEYS = set(DEFAULT_SETTINGS)


def _utcnow() -> str:
    return datetime.now(UTC).isoformat()


def _slug(value: str, fallback: str = "item") -> str:
    normalized = re.sub(r"[^a-z0-9-]+", "-", value.strip().lower()).strip("-")
    return normalized[:120] or fallback


def _control_key(value: str, fallback: str = "control") -> str:
    normalized = re.sub(r"[^a-z0-9._-]+", "-", value.strip().lower()).strip("._-")
    return normalized[:120] or fallback


def _words(value: str) -> set[str]:
    return {word for word in re.findall(r"[a-zA-Z0-9_-]{3,}", value.lower())}


class ControlPlane:
    """Stores review evidence, configuration, policies, and regulation content.

    With no storage connection string (for example unit tests), an in-memory
    implementation provides the same public behavior for one process.
    """

    def __init__(self, connection_string: str | None = None):
        self.connection_string = connection_string or os.environ.get(
            "AZURE_STORAGE_CONNECTION_STRING", os.environ.get("AzureWebJobsStorage", "")
        )
        self._table_service: TableServiceClient | None = None
        self._blob_service: BlobServiceClient | None = None
        self._memory: dict[str, dict[str, dict[str, Any]]] = {}
        self._memory_blobs: dict[str, bytes] = {}
        if self.connection_string:
            try:
                self._table_service = TableServiceClient.from_connection_string(self.connection_string)
                self._blob_service = BlobServiceClient.from_connection_string(self.connection_string)
            except Exception as exc:  # pragma: no cover - defensive for broken local configuration
                logger.warning("Control-plane storage is unavailable; using process memory: %s", exc)
        elif account_name := os.environ.get("STORAGE_ACCOUNT_NAME", ""):
            try:
                credential = DefaultAzureCredential()
                self._table_service = TableServiceClient(
                    endpoint=f"https://{account_name}.table.core.windows.net",
                    credential=credential,
                )
                self._blob_service = BlobServiceClient(
                    account_url=f"https://{account_name}.blob.core.windows.net",
                    credential=credential,
                )
            except Exception as exc:  # pragma: no cover - Azure identity is runtime-specific
                logger.warning("Managed-identity control-plane storage is unavailable: %s", exc)

    @property
    def persistent(self) -> bool:
        return self._table_service is not None

    def _table(self, name: str):
        if not self._table_service:
            return None
        try:
            return self._table_service.create_table_if_not_exists(name)
        except AzureError as exc:
            logger.warning("Could not access control-plane table %s: %s", name, exc)
            return None

    @staticmethod
    def _key(partition_key: str, row_key: str) -> str:
        return f"{partition_key}|{row_key}"

    def _put(self, table_name: str, partition_key: str, row_key: str, payload: dict[str, Any]) -> None:
        entity = {
            "PartitionKey": partition_key,
            "RowKey": row_key,
            "payload": json.dumps(payload, ensure_ascii=False, default=str),
            "updated_at": _utcnow(),
        }
        table = self._table(table_name)
        if table:
            try:
                table.upsert_entity(entity, mode=UpdateMode.REPLACE)
                return
            except AzureError as exc:
                logger.warning("Could not save %s/%s: %s", table_name, row_key, exc)
        self._memory.setdefault(table_name, {})[self._key(partition_key, row_key)] = payload

    def _get(self, table_name: str, partition_key: str, row_key: str) -> dict[str, Any] | None:
        table = self._table(table_name)
        if table:
            try:
                entity = table.get_entity(partition_key=partition_key, row_key=row_key)
                return json.loads(entity["payload"])
            except AzureError:
                pass
            except (KeyError, TypeError, json.JSONDecodeError):
                logger.warning("Stored %s/%s has invalid JSON", table_name, row_key)
        return self._memory.get(table_name, {}).get(self._key(partition_key, row_key))

    def _list(self, table_name: str) -> list[dict[str, Any]]:
        table = self._table(table_name)
        values: list[dict[str, Any]] = []
        if table:
            try:
                for entity in table.list_entities():
                    payload = json.loads(entity.get("payload", "{}"))
                    if isinstance(payload, dict):
                        values.append(payload)
            except (AzureError, TypeError, json.JSONDecodeError) as exc:
                logger.warning("Could not list %s: %s", table_name, exc)
        if values:
            return values
        return list(self._memory.get(table_name, {}).values())

    def _delete(self, table_name: str, partition_key: str, row_key: str) -> None:
        table = self._table(table_name)
        if table:
            try:
                table.delete_entity(partition_key=partition_key, row_key=row_key)
            except AzureError as exc:
                logger.warning("Could not delete %s/%s: %s", table_name, row_key, exc)
        self._memory.get(table_name, {}).pop(self._key(partition_key, row_key), None)

    def put_blob(self, path: str, content: bytes, *, container_name: str = POLICY_CONTAINER) -> str:
        """Persist a policy artifact and return its stable container-relative path."""
        normalized = path.replace("\\", "/").strip("/")
        if not normalized or ".." in normalized.split("/"):
            raise ValueError("Unsafe blob path")
        key = f"{container_name}/{normalized}"
        if self._blob_service:
            try:
                container = self._blob_service.get_container_client(container_name)
                try:
                    container.create_container()
                except ResourceExistsError:
                    pass
                container.upload_blob(normalized, content, overwrite=True)
                return normalized
            except AzureError as exc:
                logger.warning("Could not store policy artifact %s: %s", normalized, exc)
        self._memory_blobs[key] = bytes(content)
        return normalized

    def get_blob(self, path: str, *, container_name: str = POLICY_CONTAINER) -> bytes | None:
        normalized = path.replace("\\", "/").strip("/")
        if not normalized or ".." in normalized.split("/"):
            return None
        if self._blob_service:
            try:
                return self._blob_service.get_blob_client(container_name, normalized).download_blob().readall()
            except AzureError:
                pass
        return self._memory_blobs.get(f"{container_name}/{normalized}")

    def get_settings(self) -> dict[str, Any]:
        values = dict(DEFAULT_SETTINGS)
        saved = self._get(SETTINGS_TABLE, "global", "settings")
        if saved:
            values.update({key: saved[key] for key in SETTING_KEYS if key in saved})
        return values

    def update_settings(self, updates: dict[str, Any], actor: str = "admin") -> dict[str, Any]:
        current = self.get_settings()
        for key, value in updates.items():
            if key not in SETTING_KEYS:
                continue
            if isinstance(DEFAULT_SETTINGS[key], bool):
                current[key] = bool(value)
            elif isinstance(DEFAULT_SETTINGS[key], int):
                current[key] = max(1, int(value))
            else:
                current[key] = str(value)
        self._put(SETTINGS_TABLE, "global", "settings", current)
        self.audit("settings.updated", actor, {"keys": sorted(set(updates) & SETTING_KEYS)})
        return current

    def list_repositories(self) -> list[dict[str, Any]]:
        return sorted(self._list(REPOSITORIES_TABLE), key=lambda item: item.get("repo_name", ""))

    def get_repository(self, repo_id: str) -> dict[str, Any] | None:
        return self._get(REPOSITORIES_TABLE, "repo", repo_id)

    def save_repository(self, repository: dict[str, Any], actor: str = "admin") -> dict[str, Any]:
        repo_id = str(repository.get("repo_id") or "")
        if not repo_id:
            raise ValueError("repo_id is required")
        value = {
            "repo_id": repo_id,
            "repo_name": str(repository.get("repo_name") or repo_id),
            "project": str(repository.get("project") or ""),
            "enabled": bool(repository.get("enabled", True)),
            "updated_at": _utcnow(),
        }
        self._put(REPOSITORIES_TABLE, "repo", repo_id, value)
        self.audit("repository.saved", actor, {"repo_id": repo_id, "enabled": value["enabled"]})
        return value

    def review_enabled_for(self, repo_id: str) -> bool:
        repo = self.get_repository(repo_id)
        return self.get_settings()["review_enabled"] and (repo is None or bool(repo.get("enabled", True)))

    @staticmethod
    def _review_job_snapshot(job: dict[str, Any]) -> dict[str, Any]:
        """Persist routing metadata only; raw PR source is never stored in the control plane."""
        fields = (
            "job_version",
            "event_id",
            "event_type",
            "organization_url",
            "project",
            "repo_id",
            "repo_name",
            "pr_id",
            "source_branch",
            "target_branch",
            "title",
        )
        return {field: job[field] for field in fields if job.get(field) not in (None, "")}

    def record_review(self, record: dict[str, Any]) -> dict[str, Any]:
        """Upsert a review while preserving its lifecycle history and timestamps."""
        run_id = str(record.get("run_id") or uuid.uuid4())
        repo_id = str(record.get("repo_id") or "unknown")
        existing = self._get(REVIEWS_TABLE, repo_id, run_id) or {}
        now = _utcnow()
        value = {**existing, **record, "run_id": run_id, "repo_id": repo_id, "recorded_at": now}
        value.setdefault("counts", {})
        value.setdefault("errors", [])
        status = str(value.get("status") or "completed")
        value["status"] = status
        if status in {"queued", "enqueue_failed"}:
            value.setdefault("queued_at", now)
        if status == "running":
            value.setdefault("queued_at", now)
            value.setdefault("started_at", now)
            value.pop("completed_at", None)
        if status in TERMINAL_REVIEW_STATUSES:
            value.setdefault("queued_at", now)
            value.setdefault("completed_at", now)
        self._put(REVIEWS_TABLE, repo_id, run_id, value)
        return value

    def record_review_queued(self, job: dict[str, Any], run_id: str) -> dict[str, Any]:
        """Create the visible run record before sending a message to Service Bus."""
        existing = self.get_review(run_id)
        if existing:
            return existing
        snapshot = self._review_job_snapshot(job)
        value = self.record_review(
            {
                "run_id": run_id,
                "repo_id": str(snapshot.get("repo_id") or "unknown"),
                "repo_name": snapshot.get("repo_name", ""),
                "project": snapshot.get("project", ""),
                "pr_id": snapshot.get("pr_id"),
                "title": snapshot.get("title", ""),
                "job": snapshot,
                "status": "queued",
                "phase": "Waiting for the scale-to-zero worker",
                "summary": "PR event accepted and queued for review.",
                "counts": {},
                "errors": [],
                "attempts": 0,
            }
        )
        self.audit("review.queued", "webhook", {"run_id": run_id, "pr_id": snapshot.get("pr_id")})
        return value

    def mark_review_running(self, job: dict[str, Any], run_id: str) -> dict[str, Any]:
        """Mark a run as actively fetching, scanning, triaging, and reporting the PR."""
        existing = self.get_review(run_id) or self.record_review_queued(job, run_id)
        return self.record_review(
            {
                **existing,
                "run_id": run_id,
                "status": "running",
                "phase": "Fetching PR changes, scanning, and publishing advisory results",
                "summary": "Review worker is processing this pull request.",
                "attempts": int(existing.get("attempts", 0)) + 1,
                "started_at": _utcnow(),
            }
        )

    def mark_review_failed(self, job: dict[str, Any], run_id: str, error: str, *, enqueue_failed: bool = False) -> dict[str, Any]:
        """Persist a failure before a queue message is abandoned or an HTTP request is rejected."""
        existing = self.get_review(run_id) or self.record_review_queued(job, run_id)
        message = str(error)[:1000]
        errors = [str(item) for item in existing.get("errors", [])]
        if message and message not in errors:
            errors.append(message)
        update = {
            **existing,
            "run_id": run_id,
            "status": "enqueue_failed" if enqueue_failed else "failed",
            "phase": "Queue delivery failed" if enqueue_failed else "Worker failed; the message will be retried",
            "summary": "The review could not be completed. See the recorded error before replaying it.",
            "errors": errors,
        }
        if enqueue_failed:
            update["completed_at"] = _utcnow()
        return self.record_review(update)

    def list_reviews(self, limit: int = 60) -> list[dict[str, Any]]:
        reviews = self._list(REVIEWS_TABLE)
        reviews.sort(key=lambda item: item.get("recorded_at", ""), reverse=True)
        return reviews[: max(1, min(limit, 200))]

    def get_review(self, run_id: str) -> dict[str, Any] | None:
        for review in self._list(REVIEWS_TABLE):
            if review.get("run_id") == run_id:
                return review
        return None

    # Natural-language policy engine -------------------------------------------------

    def save_policy_document(
        self,
        raw: dict[str, Any],
        content: bytes | str,
        *,
        actor: str = "admin",
    ) -> dict[str, Any]:
        title = str(raw.get("title") or raw.get("filename") or "").strip()
        if not title:
            raise ValueError("title is required")
        document_id = _slug(str(raw.get("document_id") or title), "policy")
        version = str(raw.get("version") or "1.0")[:40]
        if self._get(POLICIES_TABLE, document_id, version):
            raise ValueError("This policy version already exists; create a new version")
        body = content.encode("utf-8") if isinstance(content, str) else bytes(content)
        if not body:
            raise ValueError("policy content is required")
        if len(body) > 20 * 1024 * 1024:
            raise ValueError("policy document exceeds the 20 MB limit")
        filename = str(raw.get("filename") or f"{document_id}.txt")
        extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else "txt"
        if extension not in {"txt", "pdf", "docx"}:
            raise ValueError("Only PDF, DOCX, and TXT policy documents are supported")
        artifact = self.put_blob(f"{document_id}/{version}/source.{extension}", body)
        now = _utcnow()
        value = {
            "document_id": document_id,
            "title": title,
            "version": version,
            "status": "draft",
            "ingestion_status": "queued",
            "input_type": str(raw.get("input_type") or "upload"),
            "filename": filename,
            "media_type": str(raw.get("media_type") or "text/plain"),
            "source_url": str(raw.get("source_url") or ""),
            "owner": str(raw.get("owner") or ""),
            "effective_date": str(raw.get("effective_date") or ""),
            "tags": [str(item).strip() for item in raw.get("tags", []) if str(item).strip()],
            "source_blob": artifact,
            "source_sha256": sha256(body).hexdigest(),
            "source_bytes": len(body),
            "created_at": now,
            "created_by": actor,
            "updated_at": now,
            "revision": 1,
        }
        self._put(POLICIES_TABLE, document_id, version, value)
        self.audit("policy.created", actor, {"document_id": document_id, "version": version})
        return value

    def save_policy_reference(self, raw: dict[str, Any], *, actor: str = "admin") -> dict[str, Any]:
        """Create a queued URL policy without fetching it in the request process."""
        url = str(raw.get("source_url") or "").strip()
        if not url:
            raise ValueError("source_url is required")
        placeholder = dict(raw)
        placeholder["input_type"] = "url"
        placeholder["filename"] = str(raw.get("filename") or "source.txt")
        # The worker replaces this small placeholder with the verified fetched source.
        value = self.save_policy_document(placeholder, f"URL_PENDING:{url}", actor=actor)
        value["source_pending"] = True
        self._put(POLICIES_TABLE, value["document_id"], value["version"], value)
        return value

    def replace_policy_source(self, document_id: str, version: str, content: bytes, filename: str) -> dict[str, Any]:
        value = self.get_policy(document_id, version)
        if not value:
            raise ValueError("policy version was not found")
        extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else "txt"
        if extension not in {"txt", "pdf", "docx"}:
            raise ValueError("Fetched URL is not a supported policy document")
        path = self.put_blob(f"{document_id}/{version}/source.{extension}", content)
        value.update(
            {
                "filename": filename,
                "source_blob": path,
                "source_sha256": sha256(content).hexdigest(),
                "source_bytes": len(content),
                "source_pending": False,
                "updated_at": _utcnow(),
                "revision": int(value.get("revision", 1)) + 1,
            }
        )
        self._put(POLICIES_TABLE, document_id, version, value)
        return value

    def get_policy(self, document_id: str, version: str) -> dict[str, Any] | None:
        return self._get(POLICIES_TABLE, _slug(document_id), str(version))

    def update_policy_state(self, document_id: str, version: str, *, status: str, ingestion_status: str) -> dict[str, Any]:
        policy = self.get_policy(document_id, version)
        if not policy:
            raise ValueError("policy version was not found")
        policy.update(
            {
                "status": status,
                "ingestion_status": ingestion_status,
                "updated_at": _utcnow(),
                "revision": int(policy.get("revision", 1)) + 1,
            }
        )
        self._put(POLICIES_TABLE, policy["document_id"], version, policy)
        return policy

    def list_policies(self) -> list[dict[str, Any]]:
        return sorted(self._list(POLICIES_TABLE), key=lambda item: item.get("updated_at", ""), reverse=True)

    def record_policy_job(self, document_id: str, version: str, *, actor: str = "admin") -> dict[str, Any]:
        job_id = str(uuid.uuid4())
        value = {
            "job_id": job_id,
            "job_kind": "policy_ingestion",
            "document_id": _slug(document_id),
            "policy_version": str(version),
            "status": "queued",
            "phase": "Waiting for policy ingestion worker",
            "created_at": _utcnow(),
            "created_by": actor,
            "errors": [],
        }
        self._put(POLICY_JOBS_TABLE, value["document_id"], job_id, value)
        self.audit("policy.ingestion-queued", actor, {"job_id": job_id, "document_id": value["document_id"]})
        return value

    def update_policy_job(self, job_id: str, **updates: Any) -> dict[str, Any]:
        current = next((item for item in self._list(POLICY_JOBS_TABLE) if item.get("job_id") == job_id), None)
        if not current:
            raise ValueError("policy ingestion job was not found")
        value = {**current, **updates, "updated_at": _utcnow()}
        self._put(POLICY_JOBS_TABLE, str(value["document_id"]), job_id, value)
        return value

    def get_policy_job(self, job_id: str) -> dict[str, Any] | None:
        return next((item for item in self._list(POLICY_JOBS_TABLE) if item.get("job_id") == job_id), None)

    def list_policy_jobs(self, limit: int = 50) -> list[dict[str, Any]]:
        values = sorted(self._list(POLICY_JOBS_TABLE), key=lambda item: item.get("updated_at", item.get("created_at", "")), reverse=True)
        return values[: max(1, min(limit, 200))]

    def save_policy_extraction(
        self,
        document_id: str,
        version: str,
        *,
        text: str,
        clauses: list[dict[str, Any]],
        status: str = "ready",
    ) -> dict[str, Any]:
        policy = self.get_policy(document_id, version)
        if not policy:
            raise ValueError("policy version was not found")
        text_blob = self.put_blob(f"{document_id}/{version}/extracted.txt", text.encode("utf-8"))
        for raw_clause in clauses:
            clause_id = str(raw_clause.get("clause_id") or f"clause-{uuid.uuid4().hex[:8]}")
            value = {**raw_clause, "document_id": document_id, "policy_version": version, "clause_id": clause_id}
            self._put(POLICY_CLAUSES_TABLE, f"{document_id}@{version}", clause_id, value)
        policy.update(
            {
                "ingestion_status": status,
                "extracted_text_blob": text_blob,
                "clause_count": len(clauses),
                "updated_at": _utcnow(),
                "revision": int(policy.get("revision", 1)) + 1,
            }
        )
        self._put(POLICIES_TABLE, document_id, version, policy)
        return policy

    def list_policy_clauses(self, document_id: str, version: str) -> list[dict[str, Any]]:
        key = f"{_slug(document_id)}@{version}"
        return [item for item in self._list(POLICY_CLAUSES_TABLE) if f"{item.get('document_id')}@{item.get('policy_version')}" == key]

    def save_policy_analysis(self, document_id: str, version: str, analysis: dict[str, Any]) -> dict[str, Any]:
        policy = self.get_policy(document_id, version)
        if not policy:
            raise ValueError("policy version was not found")
        payload = json.dumps(analysis, ensure_ascii=False, sort_keys=True).encode("utf-8")
        path = self.put_blob(f"{document_id}/{version}/analysis.json", payload)
        policy.update(
            {
                "analysis_blob": path,
                "analysis_sha256": sha256(payload).hexdigest(),
                "obligation_count": len(analysis.get("obligations") or []),
                "coverage_complete": bool(analysis.get("coverage_complete")),
                "coverage_gap_count": len(analysis.get("coverage_questions") or []),
                "coverage_questions": [str(item) for item in (analysis.get("coverage_questions") or [])][:25],
                "defined_term_count": len(analysis.get("defined_terms") or {}),
                "exception_count": len(analysis.get("exceptions") or []),
                "updated_at": _utcnow(),
                "revision": int(policy.get("revision", 1)) + 1,
            }
        )
        self._put(POLICIES_TABLE, document_id, version, policy)
        return policy

    def get_policy_analysis(self, document_id: str, version: str) -> dict[str, Any]:
        policy = self.get_policy(document_id, version)
        payload = self.get_blob(str((policy or {}).get("analysis_blob") or ""))
        if not payload:
            return {}
        try:
            value = json.loads(payload)
            return value if isinstance(value, dict) else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}

    def reconcile_policy_coverage(self, document_id: str, version: str, *, actor: str = "policy-engine") -> dict[str, Any]:
        """Recompute coverage after generated or human-authored control changes."""
        policy = self.get_policy(document_id, version)
        if not policy:
            raise ValueError("policy version was not found")
        analysis = self.get_policy_analysis(document_id, version)
        obligations = [item for item in analysis.get("obligations", []) if isinstance(item, dict)]
        if not obligations:
            return policy
        related = [
            item
            for item in self.list_controls()
            if item.get("policy_document_id") == policy["document_id"]
            and item.get("policy_version") == version
            and item.get("state") != "retired"
            and not item.get("generated_coverage_placeholder")
        ]
        questions: list[str] = []
        coverage: list[dict[str, Any]] = []
        for obligation in obligations:
            obligation_id = str(obligation.get("obligation_id") or "")
            expected = {str(item) for item in obligation.get("detection_surfaces", []) if str(item)}
            linked = [item for item in related if obligation_id in item.get("obligation_ids", [])]
            covered = {str(surface) for item in linked for surface in item.get("detection_surfaces", []) if str(surface)}
            missing = sorted(expected - covered)
            if not expected:
                questions.append(f"Define the PR detection surfaces for obligation '{obligation_id}'.")
            if not linked:
                questions.append(f"No approvable control implements obligation '{obligation_id}'.")
            if missing:
                questions.append(f"Obligation '{obligation_id}' has no approvable control for: {', '.join(missing)}.")
            for item in linked:
                questions.extend(str(question) for question in item.get("clarification_questions", []) if str(question))
            coverage.append(
                {
                    "obligation_id": obligation_id,
                    "expected_surfaces": sorted(expected),
                    "covered_surfaces": sorted(covered),
                    "uncovered_surfaces": missing,
                    "control_ids": [str(item.get("control_id") or "") for item in linked],
                }
            )
        questions = list(dict.fromkeys(questions))[:25]
        changed = (
            bool(policy.get("coverage_complete")) != (not questions)
            or policy.get("coverage_questions", []) != questions
        )
        policy.update(
            {
                "coverage_complete": not questions,
                "coverage_gap_count": len(questions),
                "coverage_questions": questions,
                "coverage_reconciled_at": _utcnow(),
                "updated_at": _utcnow(),
                "revision": int(policy.get("revision", 1)) + 1,
            }
        )
        self._put(POLICIES_TABLE, policy["document_id"], version, policy)
        if changed:
            self.audit(
                "policy.coverage-reconciled",
                actor,
                {"document_id": policy["document_id"], "version": version, "coverage_complete": not questions, "coverage": coverage},
            )
        return policy

    def save_control(self, raw: dict[str, Any], *, actor: str = "policy-engine") -> dict[str, Any]:
        control_id = _control_key(str(raw.get("control_id") or raw.get("title") or "control"))
        version = str(raw.get("version") or "1.0")[:40]
        if self._get(CONTROLS_TABLE, control_id, version):
            raise ValueError("This control version already exists; create a new version")
        control_type = str(raw.get("control_type") or "manual_review")
        if control_type not in CONTROL_TYPES:
            raise ValueError(f"Unsupported control type: {control_type}")
        severity = str(raw.get("severity") or "WARNING").upper()
        if severity not in {"ERROR", "WARNING", "INFO"}:
            raise ValueError("severity must be ERROR, WARNING, or INFO")
        state = str(raw.get("state") or "draft").lower()
        if state not in {"draft", "needs_clarification"}:
            raise ValueError("New controls must be draft or needs_clarification")
        source = raw.get("source_reference") or {}
        excerpt = str(source.get("excerpt") or "").strip()
        if not raw.get("policy_document_id") or not raw.get("policy_version") or not excerpt:
            raise ValueError("Control requires a policy version and source excerpt")
        detector = raw.get("detector") or {}
        detector_ref = ""
        detector_sha256 = ""
        if detector:
            payload = json.dumps(detector, ensure_ascii=False, sort_keys=True).encode("utf-8")
            detector_ref = self.put_blob(f"controls/{control_id}/{version}/detector.json", payload)
            detector_sha256 = sha256(payload).hexdigest()
        now = _utcnow()
        value = {
            "control_id": control_id,
            "version": version,
            "state": state,
            "title": str(raw.get("title") or control_id),
            "description": str(raw.get("description") or ""),
            "prohibited_condition": str(raw.get("prohibited_condition") or ""),
            "control_type": control_type,
            "obligation_ids": [str(item) for item in raw.get("obligation_ids", [])],
            "detection_surfaces": [str(item) for item in raw.get("detection_surfaces", [])],
            "detector_provenance": [item for item in raw.get("detector_provenance", []) if isinstance(item, dict)],
            "generated_coverage_placeholder": bool(raw.get("generated_coverage_placeholder")),
            "severity": severity,
            "scope": raw.get("scope") or {},
            "examples": raw.get("examples") or {"positive": [], "negative": []},
            "exclusions": [str(item) for item in raw.get("exclusions", [])],
            "clarification_questions": [str(item) for item in raw.get("clarification_questions", [])],
            "policy_document_id": _slug(str(raw["policy_document_id"])),
            "policy_version": str(raw["policy_version"]),
            "policy_title": str(raw.get("policy_title") or ""),
            "source_reference": source,
            "detector_ref": detector_ref,
            "detector_sha256": detector_sha256,
            "validation": raw.get("validation") or {"passed": False, "tests": []},
            "confidence": float(raw.get("confidence") or 0),
            "fix_hint": str(raw.get("fix_hint") or "Use an approved alternative or request a documented exception."),
            "created_at": now,
            "created_by": actor,
            "updated_at": now,
            "revision": 1,
        }
        self._put(CONTROLS_TABLE, control_id, version, value)
        self.audit("control.proposed", actor, {"control_id": control_id, "version": version, "state": state})
        return value

    def get_control(self, control_id: str, version: str) -> dict[str, Any] | None:
        return self._get(CONTROLS_TABLE, _control_key(control_id), str(version))

    def list_controls(self) -> list[dict[str, Any]]:
        return sorted(self._list(CONTROLS_TABLE), key=lambda item: item.get("updated_at", ""), reverse=True)

    def _control_detector(self, control: dict[str, Any]) -> dict[str, Any]:
        ref = str(control.get("detector_ref") or "")
        if not ref:
            return {}
        payload = self.get_blob(ref)
        if not payload:
            return {}
        try:
            value = json.loads(payload)
            return value if isinstance(value, dict) else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}

    def transition_control(
        self,
        control_id: str,
        version: str,
        target: str,
        *,
        actor: str = "admin",
        expected_revision: int | None = None,
    ) -> dict[str, Any]:
        control = self.get_control(control_id, version)
        if not control:
            raise ValueError("control version was not found")
        current = str(control.get("state") or "draft")
        target = target.lower()
        if expected_revision is not None and int(control.get("revision", 0)) != expected_revision:
            raise ValueError("control was changed by another user; reload and retry")
        if target not in CONTROL_TRANSITIONS.get(current, set()):
            raise ValueError(f"Invalid control transition: {current} to {target}")
        if target == "approved" and not bool(control.get("validation", {}).get("passed")):
            raise ValueError("control validation must pass before approval")
        if target == "approved" and control.get("generated_coverage_placeholder"):
            raise ValueError("coverage placeholders cannot be approved; author a real control or a new policy version")
        if target == "approved" and control.get("clarification_questions"):
            raise ValueError("clarification questions must be resolved before approval")
        if target == "active":
            if not self.get_settings().get("control_activation_enabled", True):
                raise ValueError("control activation is disabled by an administrator")
            approval = self._get(APPROVALS_TABLE, control["control_id"], version)
            if not approval:
                raise ValueError("control must have an approval record before activation")
            for other in self.list_controls():
                if other.get("control_id") == control["control_id"] and other.get("state") == "active":
                    other["state"] = "retired"
                    other["updated_at"] = _utcnow()
                    other["revision"] = int(other.get("revision", 1)) + 1
                    self._put(CONTROLS_TABLE, other["control_id"], str(other["version"]), other)
        control["state"] = target
        control["updated_at"] = _utcnow()
        control["updated_by"] = actor
        control["revision"] = int(control.get("revision", 1)) + 1
        self._put(CONTROLS_TABLE, control["control_id"], version, control)
        if target == "retired" and control.get("policy_document_id") and control.get("policy_version"):
            self.reconcile_policy_coverage(
                str(control["policy_document_id"]), str(control["policy_version"]), actor=actor
            )
        self.audit("control.transitioned", actor, {"control_id": control["control_id"], "version": version, "from": current, "to": target})
        return control

    def approve_control(self, control_id: str, version: str, *, actor: str, notes: str = "") -> dict[str, Any]:
        control = self.get_control(control_id, version)
        if not control:
            raise ValueError("control version was not found")
        if control.get("state") != "draft":
            raise ValueError("only a draft control can be approved")
        if not bool(control.get("validation", {}).get("passed")):
            raise ValueError("control validation must pass before approval")
        if control.get("generated_coverage_placeholder"):
            raise ValueError("coverage placeholders cannot be approved; author a real control or a new policy version")
        if control.get("clarification_questions"):
            raise ValueError("clarification questions must be resolved before approval")
        approval = {
            "control_id": control["control_id"],
            "control_version": version,
            "policy_document_id": control["policy_document_id"],
            "policy_version": control["policy_version"],
            "approver": actor,
            "approved_at": _utcnow(),
            "validation": control["validation"],
            "source_reference": control["source_reference"],
            "obligation_ids": control.get("obligation_ids", []),
            "detection_surfaces": control.get("detection_surfaces", []),
            "detector_provenance": control.get("detector_provenance", []),
            "clarification_answers": control.get("clarification_answers", []),
            "approved_exceptions": [
                item.get("exception_id")
                for item in self.list_exceptions(include_expired=False)
                if item.get("control_id") == control["control_id"]
                and str(item.get("control_version") or "*") in {"*", version}
            ],
            "notes": notes,
        }
        self._put(APPROVALS_TABLE, control["control_id"], version, approval)
        self.transition_control(control_id, version, "approved", actor=actor)
        self.audit("control.approved", actor, {"control_id": control["control_id"], "version": version})
        return approval

    def answer_control_clarifications(
        self, control_id: str, version: str, answers: list[dict[str, str]], *, actor: str = "admin"
    ) -> dict[str, Any]:
        control = self.get_control(control_id, version)
        if not control or control.get("state") != "needs_clarification":
            raise ValueError("control is not awaiting clarification")
        questions = [str(item) for item in control.get("clarification_questions", [])]
        provided = {str(item.get("question") or ""): str(item.get("answer") or "").strip() for item in answers}
        missing = [question for question in questions if not provided.get(question)]
        if missing:
            raise ValueError("Every clarification question requires an answer")
        control["clarification_answers"] = [{"question": question, "answer": provided[question]} for question in questions]
        control["clarification_questions"] = []
        control["state"] = "draft"
        control["updated_at"] = _utcnow()
        control["updated_by"] = actor
        control["revision"] = int(control.get("revision", 1)) + 1
        self._put(CONTROLS_TABLE, control["control_id"], version, control)
        related = [
            item
            for item in self.list_controls()
            if item.get("policy_document_id") == control.get("policy_document_id")
            and item.get("policy_version") == control.get("policy_version")
        ]
        if related and not any(item.get("clarification_questions") for item in related):
            policy = self.reconcile_policy_coverage(
                str(control["policy_document_id"]), str(control["policy_version"]), actor=actor
            )
            self.update_policy_state(
                str(control["policy_document_id"]),
                str(control["policy_version"]),
                status="ready" if policy.get("coverage_complete", True) else "partial_coverage",
                ingestion_status=str(policy.get("ingestion_status") or "completed"),
            )
        self.audit("control.clarified", actor, {"control_id": control["control_id"], "version": version})
        return control

    def revise_control(self, control_id: str, version: str, raw: dict[str, Any], *, actor: str = "admin") -> dict[str, Any]:
        current = self.get_control(control_id, version)
        if not current:
            raise ValueError("control version was not found")
        new_version = str(raw.get("new_version") or "").strip()
        if not new_version or new_version == version:
            raise ValueError("new_version must identify a new immutable control version")
        for protected in ("prohibited_condition", "scope", "examples", "exclusions", "detector"):
            if protected in raw and raw[protected] != current.get(protected):
                raise ValueError(f"Changing {protected} requires policy regeneration and new validation tests")
        clone = {
            **current,
            **{key: raw[key] for key in ("title", "description", "severity", "fix_hint") if key in raw},
            "version": new_version,
            "detector": self._control_detector(current),
            "state": "draft",
            "clarification_questions": [],
        }
        for key in ("detector_ref", "created_at", "created_by", "updated_at", "updated_by", "revision"):
            clone.pop(key, None)
        return self.save_control(clone, actor=actor)

    def active_controls(self) -> tuple[list[dict[str, Any]], list[str]]:
        controls: list[dict[str, Any]] = []
        versions: list[str] = []
        for control in self.list_controls():
            if control.get("state") != "active":
                continue
            hydrated = {**control, "detector": self._control_detector(control)}
            controls.append(hydrated)
            versions.append(f"{control['control_id']}@{control['version']}")
        return controls, versions

    def policy_coverage_gaps(self, active_controls: list[dict[str, Any]]) -> list[str]:
        """Declare incomplete policy compilation whenever any part is active."""
        policy_keys = {
            (str(item.get("policy_document_id") or ""), str(item.get("policy_version") or ""))
            for item in active_controls
            if item.get("policy_document_id") and item.get("policy_version")
        }
        gaps: list[str] = []
        for document_id, version in sorted(policy_keys):
            policy = self.get_policy(document_id, version) or {}
            if policy.get("coverage_complete", True):
                continue
            questions = [str(item) for item in policy.get("coverage_questions", []) if str(item)]
            detail = "; ".join(questions[:5]) or "the obligation-to-control coverage plan is incomplete"
            gaps.append(f"Policy {document_id}@{version} has partial PR coverage: {detail}")
        return gaps

    def save_exception(self, raw: dict[str, Any], *, actor: str = "admin") -> dict[str, Any]:
        control_id = _control_key(str(raw.get("control_id") or ""), "")
        if not control_id:
            raise ValueError("control_id is required")
        if not raw.get("business_justification") or not raw.get("expiration_date"):
            raise ValueError("business_justification and expiration_date are required")
        try:
            expiration = datetime.fromisoformat(str(raw["expiration_date"]).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("expiration_date must be ISO-8601") from exc
        if expiration.tzinfo is None:
            expiration = expiration.replace(tzinfo=UTC)
        if expiration <= datetime.now(UTC):
            raise ValueError("expiration_date must be in the future")
        exception_id = str(raw.get("exception_id") or uuid.uuid4())
        value = {
            "exception_id": exception_id,
            "control_id": control_id,
            "control_version": str(raw.get("control_version") or "*"),
            "repository_id": str(raw.get("repository_id") or "*"),
            "project": str(raw.get("project") or "*"),
            "approved_value": str(raw.get("approved_value") or "*"),
            "business_justification": str(raw["business_justification"]),
            "approver": str(raw.get("approver") or actor),
            "approved_at": _utcnow(),
            "expiration_date": expiration.astimezone(UTC).isoformat(),
            "reference_ticket": str(raw.get("reference_ticket") or ""),
            "status": "approved",
            "created_by": actor,
        }
        self._put(EXCEPTIONS_TABLE, control_id, exception_id, value)
        self.audit("exception.approved", actor, {"exception_id": exception_id, "control_id": control_id})
        return value

    def revoke_exception(self, exception_id: str, *, actor: str = "admin") -> dict[str, Any]:
        value = next((item for item in self._list(EXCEPTIONS_TABLE) if item.get("exception_id") == exception_id), None)
        if not value:
            raise ValueError("exception was not found")
        value.update({"status": "revoked", "revoked_at": _utcnow(), "revoked_by": actor})
        self._put(EXCEPTIONS_TABLE, str(value["control_id"]), exception_id, value)
        self.audit("exception.revoked", actor, {"exception_id": exception_id})
        return value

    def list_exceptions(self, *, include_expired: bool = True) -> list[dict[str, Any]]:
        now = datetime.now(UTC)
        values: list[dict[str, Any]] = []
        for item in self._list(EXCEPTIONS_TABLE):
            value = dict(item)
            try:
                expired = datetime.fromisoformat(str(value.get("expiration_date", "")).replace("Z", "+00:00")) <= now
            except ValueError:
                expired = True
            if value.get("status") == "approved" and expired:
                value["status"] = "expired"
            if include_expired or value.get("status") == "approved":
                values.append(value)
        return sorted(values, key=lambda item: item.get("expiration_date", ""), reverse=True)

    def save_rule_pack(self, raw: dict[str, Any], actor: str = "admin") -> dict[str, Any]:
        pack_id = _slug(str(raw.get("pack_id") or raw.get("title") or "policy-pack"))
        version = str(raw.get("version") or "1.0")[:40]
        rules = raw.get("rules") or []
        if not isinstance(rules, list):
            raise ValueError("rules must be a list")
        for rule in rules:
            if not isinstance(rule, dict) or not rule.get("rule_id") or not rule.get("message"):
                raise ValueError("Each rule needs rule_id and message")
            if not rule.get("pattern") and not rule.get("semgrep_yaml"):
                raise ValueError("Each rule needs a simple pattern or semgrep_yaml")
        status = str(raw.get("status") or "draft").lower()
        if status not in {"draft", "active", "retired"}:
            raise ValueError("status must be draft, active, or retired")
        if status == "active":
            for existing in self._list(RULE_PACKS_TABLE):
                if existing.get("pack_id") == pack_id and existing.get("status") == "active":
                    existing["status"] = "retired"
                    self._put(RULE_PACKS_TABLE, pack_id, str(existing.get("version")), existing)
        value = {
            "pack_id": pack_id,
            "title": str(raw.get("title") or pack_id),
            "version": version,
            "status": status,
            "description": str(raw.get("description") or ""),
            "rules": rules,
            "created_at": _utcnow(),
            "created_by": actor,
        }
        self._put(RULE_PACKS_TABLE, pack_id, version, value)
        self.audit("rule-pack.saved", actor, {"pack_id": pack_id, "version": version, "status": status})
        return value

    def list_rule_packs(self) -> list[dict[str, Any]]:
        return sorted(self._list(RULE_PACKS_TABLE), key=lambda item: (item.get("pack_id", ""), item.get("version", "")), reverse=True)

    def active_rules(self) -> tuple[list[dict[str, Any]], list[str]]:
        rules: list[dict[str, Any]] = []
        versions: list[str] = []
        for pack in self.list_rule_packs():
            if pack.get("status") != "active":
                continue
            versions.append(f"{pack.get('pack_id')}@{pack.get('version')}")
            rules.extend(rule for rule in pack.get("rules", []) if isinstance(rule, dict))
        return rules, versions

    def save_regulation(self, raw: dict[str, Any], actor: str = "admin") -> dict[str, Any]:
        title = str(raw.get("title") or "").strip()
        content = str(raw.get("content") or "").strip()
        if not title or not content:
            raise ValueError("title and content are required")
        document_id = _slug(str(raw.get("document_id") or title))
        version = str(raw.get("version") or "1.0")[:40]
        status = str(raw.get("status") or "draft").lower()
        if status not in {"draft", "approved", "retired"}:
            raise ValueError("status must be draft, approved, or retired")
        value = {
            "document_id": document_id,
            "title": title,
            "version": version,
            "status": status,
            "effective_date": str(raw.get("effective_date") or ""),
            "owner": str(raw.get("owner") or ""),
            "source_url": str(raw.get("source_url") or ""),
            "tags": [str(tag) for tag in raw.get("tags", []) if str(tag).strip()],
            "updated_at": _utcnow(),
            "updated_by": actor,
            "content_length": len(content),
        }
        self._put(REGULATIONS_TABLE, document_id, version, value)
        self._save_document(document_id, version, content)
        self._replace_chunks(value, content)
        self.audit("regulation.saved", actor, {"document_id": document_id, "version": version, "status": status})
        return value

    def _save_document(self, document_id: str, version: str, content: str) -> None:
        if not self._blob_service:
            return
        try:
            container = self._blob_service.get_container_client(DOCUMENTS_CONTAINER)
            try:
                container.create_container()
            except ResourceExistsError:
                pass
            container.upload_blob(f"{document_id}/{version}.txt", content.encode("utf-8"), overwrite=True)
        except AzureError as exc:
            logger.warning("Could not store regulation source document: %s", exc)

    @staticmethod
    def _chunk(content: str, size: int = 900, overlap: int = 160) -> list[str]:
        content = re.sub(r"\r\n?", "\n", content).strip()
        if not content:
            return []
        chunks: list[str] = []
        start = 0
        while start < len(content):
            end = min(len(content), start + size)
            if end < len(content):
                boundary = content.rfind("\n", start, end)
                if boundary > start + size // 2:
                    end = boundary
            chunks.append(content[start:end].strip())
            if end >= len(content):
                break
            start = max(end - overlap, start + 1)
        return [chunk for chunk in chunks if chunk]

    def _replace_chunks(self, document: dict[str, Any], content: str) -> None:
        doc_key = f"{document['document_id']}@{document['version']}"
        for chunk in self._list(REGULATION_CHUNKS_TABLE):
            if chunk.get("document_key") == doc_key:
                self._delete(REGULATION_CHUNKS_TABLE, doc_key, str(chunk.get("chunk_id")))
        for index, text in enumerate(self._chunk(content)):
            chunk = {
                "document_key": doc_key,
                "chunk_id": f"{index:05d}",
                "document_id": document["document_id"],
                "title": document["title"],
                "version": document["version"],
                "status": document["status"],
                "effective_date": document.get("effective_date", ""),
                "source_url": document.get("source_url", ""),
                "tags": document.get("tags", []),
                "content": text,
            }
            self._put(REGULATION_CHUNKS_TABLE, doc_key, chunk["chunk_id"], chunk)

    def list_regulations(self) -> list[dict[str, Any]]:
        return sorted(self._list(REGULATIONS_TABLE), key=lambda item: item.get("updated_at", ""), reverse=True)

    def transition_regulation(self, document_id: str, version: str, status: str, *, actor: str) -> dict[str, Any]:
        """Approve or retire a reference source without rewriting its immutable text."""
        document_id = str(document_id or "").strip()
        version = str(version or "").strip()
        status = str(status or "").lower()
        if not document_id or not version:
            raise ValueError("document_id and version are required")
        if status not in {"approved", "retired"}:
            raise ValueError("reference status must be approved or retired")
        existing = next(
            (
                item
                for item in self._list(REGULATIONS_TABLE)
                if item.get("document_id") == document_id and str(item.get("version")) == version
            ),
            None,
        )
        if not existing:
            raise ValueError("reference source version was not found")
        if existing.get("status") == "retired" and status == "approved":
            raise ValueError("retired reference sources cannot be re-approved; create a new version")

        value = {**existing, "status": status, "updated_at": _utcnow(), "updated_by": actor}
        self._put(REGULATIONS_TABLE, document_id, version, value)
        document_key = f"{document_id}@{version}"
        for chunk in self._list(REGULATION_CHUNKS_TABLE):
            if chunk.get("document_key") == document_key:
                self._put(
                    REGULATION_CHUNKS_TABLE,
                    document_key,
                    str(chunk.get("chunk_id")),
                    {**chunk, "status": status},
                )
        self.audit("reference.status-changed", actor, {"document_id": document_id, "version": version, "status": status})
        return value

    def search_regulations(self, query: str, limit: int = 5) -> list[dict[str, Any]]:
        """Keyword retrieval used now; the output shape is stable for vector RAG later."""
        terms = _words(query)
        if not terms:
            return []
        matches: list[dict[str, Any]] = []
        for chunk in self._list(REGULATION_CHUNKS_TABLE):
            if chunk.get("status") != "approved":
                continue
            content = str(chunk.get("content", ""))
            score = len(terms & _words(content + " " + str(chunk.get("title", ""))))
            if score:
                matches.append(
                    {
                        "document_id": chunk["document_id"],
                        "title": chunk["title"],
                        "version": chunk["version"],
                        "effective_date": chunk.get("effective_date", ""),
                        "source_url": chunk.get("source_url", ""),
                        "chunk_id": chunk["chunk_id"],
                        "content": content,
                        "score": score,
                    }
                )
        matches.sort(key=lambda item: (item["score"], item["title"]), reverse=True)
        return matches[: max(1, min(limit, 10))]

    def audit(self, action: str, actor: str, details: dict[str, Any]) -> None:
        event_id = str(uuid.uuid4())
        event = {"event_id": event_id, "action": action, "actor": actor, "details": details, "at": _utcnow()}
        self._put(AUDIT_TABLE, event["at"][:10], event_id, event)

    def list_audit_events(self, limit: int = 100) -> list[dict[str, Any]]:
        values = sorted(self._list(AUDIT_TABLE), key=lambda item: item.get("at", ""), reverse=True)
        return values[: max(1, min(limit, 500))]

    def dashboard(self) -> dict[str, Any]:
        reviews = self.list_reviews()
        policies = self.list_policies()
        controls = self.list_controls()
        exceptions = self.list_exceptions()
        policy_jobs = self.list_policy_jobs()
        findings = sum(int(review.get("counts", {}).get("findings", 0)) for review in reviews)
        return {
            "settings": self.get_settings(),
            "reviews": reviews,
            "repositories": self.list_repositories(),
            "rule_packs": self.list_rule_packs(),
            "regulations": self.list_regulations(),
            "policies": policies,
            "controls": controls,
            "exceptions": exceptions,
            "policy_jobs": policy_jobs,
            "stats": {
                "reviews": len(reviews),
                "findings": findings,
                "active_reviews": sum(review.get("status") in {"queued", "running"} for review in reviews),
                "failed_reviews": sum(review.get("status") in {"failed", "enqueue_failed"} for review in reviews),
                "active_rule_packs": sum(pack.get("status") == "active" for pack in self.list_rule_packs()),
                "approved_regulations": sum(doc.get("status") == "approved" for doc in self.list_regulations()),
                "policy_documents": len(policies),
                "active_controls": sum(item.get("state") == "active" for item in controls),
                "needs_clarification": sum(item.get("state") == "needs_clarification" for item in controls),
                "active_exceptions": sum(item.get("status") == "approved" for item in exceptions),
                "active_policy_jobs": sum(item.get("status") in {"queued", "running"} for item in policy_jobs),
                "persistence": "azure-storage" if self.persistent else "local-memory",
                "rag_mode": self.get_settings().get("rag_mode", "keyword"),
            },
        }


_control_plane: ControlPlane | None = None


def get_control_plane() -> ControlPlane:
    global _control_plane
    if _control_plane is None:
        _control_plane = ControlPlane()
    return _control_plane
