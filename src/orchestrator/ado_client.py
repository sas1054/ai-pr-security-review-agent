"""Small, retrying Azure DevOps REST client used by the review worker."""

from __future__ import annotations

import base64
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

from models import ReviewJob

logger = logging.getLogger(__name__)

_kv_client: SecretClient | None = None


def get_ado_pat() -> str:
    """Read the ADO PAT from Key Vault, with an explicit local/hackathon fallback."""
    global _kv_client
    kv_uri = os.environ.get("KEY_VAULT_URI")
    if kv_uri:
        if _kv_client is None:
            _kv_client = SecretClient(vault_url=kv_uri, credential=DefaultAzureCredential())
        try:
            return _kv_client.get_secret("ado-pat").value or ""
        except Exception:
            logger.warning("Could not read ado-pat from Key Vault")

    if (
        os.environ.get("ENVIRONMENT", "production").lower() == "local"
        or os.environ.get("HACKATHON_MODE", "").lower() == "true"
    ):
        return os.environ.get("ADO_PAT", "")
    return ""


def _auth_header(pat: str) -> dict[str, str]:
    token = base64.b64encode(f":{pat}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


@dataclass
class ChangedFile:
    path: str
    change_type: str
    content: str = ""
    truncated: bool = False
    binary: bool = False


@dataclass
class PrDiff:
    pr_id: int
    repo_name: str
    source_branch: str
    target_branch: str
    iteration_id: int = 0
    changed_files: list[ChangedFile] = field(default_factory=list)
    raw_diff: str = ""
    truncated: bool = False


class AdoClient:
    """Thin wrapper around the Azure DevOps Git REST API v7.1."""

    API_VERSION = "7.1"
    RETRYABLE_STATUS_CODES = {408, 429, *range(500, 600)}

    def __init__(
        self,
        org_url: str,
        project: str,
        repo_id: str,
        *,
        http_client: httpx.Client | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
        max_retries: int = 3,
        max_files: int | None = None,
        max_file_bytes: int | None = None,
        max_total_bytes: int | None = None,
    ):
        self.org_url = org_url.rstrip("/")
        self.project = project
        self.repo_id = repo_id
        self._http = http_client or httpx.Client()
        self._sleep = sleep_fn
        self.max_retries = max_retries
        self.max_files = max_files or int(os.environ.get("MAX_CHANGED_FILES", "100"))
        self.max_file_bytes = max_file_bytes or int(os.environ.get("MAX_FILE_BYTES", str(200 * 1024)))
        self.max_total_bytes = max_total_bytes or int(os.environ.get("MAX_TOTAL_BYTES", str(2 * 1024 * 1024)))
        self._headers = {
            **_auth_header(get_ado_pat()),
            "Accept": "application/json",
        }

    def _url(self, path: str) -> str:
        return f"{self.org_url}/{self.project}/_apis/git/repositories/{self.repo_id}/{path}"

    def _request(self, method: str, path: str, params: dict[str, Any] | None = None) -> httpx.Response:
        request_params = {**(params or {}), "api-version": self.API_VERSION}
        for attempt in range(self.max_retries + 1):
            try:
                response = self._http.request(
                    method,
                    self._url(path),
                    headers=self._headers,
                    params=request_params,
                    timeout=30,
                )
            except httpx.RequestError as exc:
                if attempt >= self.max_retries:
                    raise
                delay = min(2**attempt, 8)
                logger.warning("ADO request failed (%s); retrying in %ss", exc, delay)
                self._sleep(delay)
                continue

            if response.status_code not in self.RETRYABLE_STATUS_CODES:
                response.raise_for_status()
                return response
            if attempt >= self.max_retries:
                response.raise_for_status()

            retry_after = response.headers.get("retry-after")
            try:
                delay = float(retry_after) if retry_after else min(2**attempt, 8)
            except ValueError:
                delay = min(2**attempt, 8)
            logger.warning("ADO request returned %s; retrying in %ss", response.status_code, delay)
            self._sleep(delay)

        raise RuntimeError("ADO request retry loop exhausted")

    def _get_json(self, path: str, params: dict[str, Any] | None = None) -> tuple[dict, httpx.Response]:
        response = self._request("GET", path, params)
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError(f"Expected object response from {path}")
        return data, response

    def get_pr_iterations(self, pr_id: int) -> list[dict]:
        data, _ = self._get_json(f"pullRequests/{pr_id}/iterations")
        return data.get("value", [])

    def get_pr_changes(self, pr_id: int, iteration_id: int) -> list[dict]:
        changes: list[dict] = []
        continuation: str | None = None
        while True:
            params: dict[str, Any] = {"$top": 2000, "includeContentMetadata": "true"}
            if continuation:
                params["continuationToken"] = continuation
            data, response = self._get_json(
                f"pullRequests/{pr_id}/iterations/{iteration_id}/changes",
                params,
            )
            changes.extend(data.get("changeEntries", []))
            continuation = response.headers.get("x-ms-continuationtoken") or data.get("continuationToken")
            if not continuation:
                return changes

    def get_file_content(self, path: str, version: str) -> str:
        try:
            response = self._request(
                "GET",
                "items",
                {
                    "path": path,
                    "versionDescriptor.version": version,
                    "versionDescriptor.versionType": "branch",
                    "$format": "text",
                },
            )
        except httpx.HTTPStatusError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                return ""
            raise
        content = response.text
        if "\x00" in content:
            return ""
        return content

    def list_repository_files(self, version: str) -> list[str]:
        data, _ = self._get_json(
            "items",
            {
                "scopePath": "/",
                "recursionLevel": "Full",
                "includeContentMetadata": "true",
                "versionDescriptor.version": version,
                "versionDescriptor.versionType": "branch",
            },
        )
        return [
            str(item.get("path") or "")
            for item in data.get("value", [])
            if isinstance(item, dict) and not item.get("isFolder") and item.get("path")
        ]

    def fetch_relevant_policy_files(
        self, version: str, existing_paths: set[str], control_types: set[str]
    ) -> tuple[dict[str, str], list[str]]:
        """Fetch bounded repository context required by active non-diff controls."""
        if not control_types & {"dependency", "config_iac"}:
            return {}, []
        paths = self.list_repository_files(version)
        dependency_names = {
            "package.json", "package-lock.json", "npm-shrinkwrap.json", "pyproject.toml", "poetry.lock", "pdm.lock",
            "pipfile", "packages.config", "packages.lock.json", "pom.xml", "build.gradle", "build.gradle.kts",
            "go.mod", "go.sum",
        }
        selected: list[str] = []
        for path in paths:
            name = path.rsplit("/", 1)[-1].lower()
            is_dependency = (
                name in dependency_names
                or name.startswith("requirements") and name.endswith((".txt", ".in"))
                or name.endswith((".csproj", ".fsproj", ".vbproj"))
            )
            is_config = name in {"dockerfile", "docker-compose.yml", "docker-compose.yaml"} or path.lower().endswith(
                (".bicep", ".tf", ".tfvars", ".yaml", ".yml", ".json")
            )
            if path not in existing_paths and (("dependency" in control_types and is_dependency) or ("config_iac" in control_types and is_config)):
                selected.append(path)
        gaps: list[str] = []
        if "dependency" in control_types and not any(path.rsplit("/", 1)[-1].lower() in dependency_names or "requirements" in path.lower() for path in paths):
            gaps.append("No supported dependency manifest or lock file was found")
        if len(selected) > 50:
            gaps.append(f"Relevant policy file inventory was limited to 50 of {len(selected)} files")
            selected = selected[:50]
        files: dict[str, str] = {}
        total = 0
        for path in selected:
            content = self.get_file_content(path, version)
            raw = content.encode("utf-8", errors="replace")[: self.max_file_bytes]
            if total + len(raw) > self.max_total_bytes:
                gaps.append("Relevant policy files exceeded the configured total-byte limit")
                break
            files[path] = raw.decode("utf-8", errors="replace")
            total += len(raw)
        return files, gaps

    def fetch_diff(self, job: ReviewJob | dict[str, Any]) -> PrDiff:
        """Return changed source content with explicit truncation metadata."""
        review_job = job if isinstance(job, ReviewJob) else ReviewJob.from_dict(job)
        iterations = self.get_pr_iterations(review_job.pr_id)
        if not iterations:
            raise ValueError(f"No iterations found for PR #{review_job.pr_id}")

        latest = max(iterations, key=lambda item: int(item["id"]))
        iteration_id = int(latest["id"])
        changes = self.get_pr_changes(review_job.pr_id, iteration_id)
        branch = review_job.source_branch.removeprefix("refs/heads/")

        diff = PrDiff(
            pr_id=review_job.pr_id,
            repo_name=review_job.repo_name,
            source_branch=review_job.source_branch,
            target_branch=review_job.target_branch,
            iteration_id=iteration_id,
        )
        total_bytes = 0

        for index, entry in enumerate(changes):
            if index >= self.max_files:
                diff.truncated = True
                break

            item = entry.get("item", {})
            path = str(item.get("path", ""))
            change_type = str(entry.get("changeType", "")).lower()
            if not path or item.get("isFolder"):
                continue

            if change_type == "delete":
                diff.changed_files.append(ChangedFile(path=path, change_type="delete"))
                continue

            try:
                content = self.get_file_content(path, branch)
            except Exception as exc:
                logger.warning("Could not fetch %s: %s", path, exc)
                content = ""

            raw = content.encode("utf-8", errors="replace")
            file_truncated = len(raw) > self.max_file_bytes
            raw = raw[: self.max_file_bytes]
            remaining = self.max_total_bytes - total_bytes
            if remaining < len(raw):
                raw = raw[: max(0, remaining)]
                file_truncated = True
                diff.truncated = True
            content = raw.decode("utf-8", errors="replace")
            total_bytes += len(raw)
            diff.changed_files.append(
                ChangedFile(
                    path=path,
                    change_type=change_type,
                    content=content,
                    truncated=file_truncated,
                )
            )
            if file_truncated:
                diff.truncated = True
            if total_bytes >= self.max_total_bytes:
                break

        chunks = []
        for changed in diff.changed_files:
            if changed.change_type == "delete":
                chunks.append(f"diff --git a{changed.path} b{changed.path}\n(deleted file)\n")
            else:
                marker = "\n[content truncated]\n" if changed.truncated else "\n"
                chunks.append(f"diff --git a{changed.path} b{changed.path}\n+++ b{changed.path}\n{changed.content}{marker}")
        diff.raw_diff = "".join(chunks)
        logger.info(
            "Fetched diff for PR #%s — iteration %s, %d changed files, truncated=%s",
            review_job.pr_id,
            diff.iteration_id,
            len(diff.changed_files),
            diff.truncated,
        )
        return diff
