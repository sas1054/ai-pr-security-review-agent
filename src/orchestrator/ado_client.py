"""
Azure DevOps API client — US-05

Fetches PR diff and changed file list given a job payload.
Auth: PAT read from Key Vault (ado-pat) or ADO_PAT env var for local dev.
"""

from __future__ import annotations

import base64
import logging
import os
from dataclasses import dataclass, field

import httpx
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

logger = logging.getLogger(__name__)

_kv_client: SecretClient | None = None


def _get_pat() -> str:
    """Reads the ADO Personal Access Token. KV first, env var fallback."""
    global _kv_client
    kv_uri = os.environ.get("KEY_VAULT_URI")
    if kv_uri:
        if _kv_client is None:
            _kv_client = SecretClient(vault_url=kv_uri, credential=DefaultAzureCredential())
        try:
            return _kv_client.get_secret("ado-pat").value or ""
        except Exception:
            logger.warning("Could not read ado-pat from Key Vault, falling back to env var")
    return os.environ.get("ADO_PAT", "")


def _auth_header(pat: str) -> dict:
    token = base64.b64encode(f":{pat}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


@dataclass
class ChangedFile:
    path: str
    change_type: str   # "add" | "edit" | "delete"
    content: str = ""  # populated by fetch_file_content


@dataclass
class PrDiff:
    pr_id: int
    repo_name: str
    source_branch: str
    target_branch: str
    changed_files: list[ChangedFile] = field(default_factory=list)
    raw_diff: str = ""


class AdoClient:
    """
    Thin wrapper around the Azure DevOps REST API v7.1.

    org_url  — e.g. https://dev.azure.com/myorg
    project  — e.g. MyProject
    repo_id  — repository GUID or name
    """

    API_VERSION = "7.1"

    def __init__(self, org_url: str, project: str, repo_id: str):
        self.org_url = org_url.rstrip("/")
        self.project = project
        self.repo_id = repo_id
        pat = _get_pat()
        self._headers = {
            **_auth_header(pat),
            "Accept": "application/json",
        }

    def _get(self, path: str, params: dict | None = None) -> dict:
        url = f"{self.org_url}/{self.project}/_apis/git/repositories/{self.repo_id}/{path}"
        resp = httpx.get(url, headers=self._headers, params={**(params or {}), "api-version": self.API_VERSION}, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def get_pr_iterations(self, pr_id: int) -> list[dict]:
        data = self._get(f"pullRequests/{pr_id}/iterations")
        return data.get("value", [])

    def get_pr_changes(self, pr_id: int, iteration_id: int) -> list[dict]:
        data = self._get(f"pullRequests/{pr_id}/iterations/{iteration_id}/changes")
        return data.get("changeEntries", [])

    def get_file_content(self, path: str, version: str) -> str:
        url = f"{self.org_url}/{self.project}/_apis/git/repositories/{self.repo_id}/items"
        params = {
            "path": path,
            "versionDescriptor.version": version,
            "versionDescriptor.versionType": "branch",
            "$format": "text",
            "api-version": self.API_VERSION,
        }
        resp = httpx.get(url, headers=self._headers, params=params, timeout=30)
        if resp.status_code == 404:
            return ""
        resp.raise_for_status()
        return resp.text

    def fetch_diff(self, pr_id: int, source_branch: str) -> PrDiff:
        """
        Returns a PrDiff with the changed files + their content on the source branch.
        Skips binary files and deleted files (no content to scan).
        """
        iterations = self.get_pr_iterations(pr_id)
        if not iterations:
            raise ValueError(f"No iterations found for PR #{pr_id}")

        latest = max(iterations, key=lambda i: i["id"])
        changes = self.get_pr_changes(pr_id, latest["id"])

        diff = PrDiff(
            pr_id=pr_id,
            repo_name=self.repo_id,
            source_branch=source_branch,
            target_branch="",
        )

        branch = source_branch.removeprefix("refs/heads/")

        for entry in changes:
            item = entry.get("item", {})
            path = item.get("path", "")
            change_type = entry.get("changeType", "").lower()

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

            diff.changed_files.append(ChangedFile(path=path, change_type=change_type, content=content))

        logger.info("Fetched diff for PR #%s — %d changed files", pr_id, len(diff.changed_files))
        return diff
