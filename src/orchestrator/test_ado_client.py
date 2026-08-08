import base64

import httpx

from ado_client import AdoClient, get_ado_pat
from models import ReviewJob


def _job():
    return ReviewJob.from_dict(
        {
            "job_version": 1,
            "event_id": "event-1",
            "event_type": "git.pullrequest.created",
            "organization_url": "https://dev.azure.com/org",
            "project": "Project",
            "repo_id": "repo",
            "repo_name": "service",
            "pr_id": 7,
            "source_branch": "refs/heads/feature",
            "target_branch": "refs/heads/main",
        }
    )


def test_fetch_diff_handles_pagination_and_limits(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "local")
    monkeypatch.setenv("ADO_PAT", "pat-value")
    calls = []

    def handler(request: httpx.Request):
        calls.append(request)
        if request.url.path.endswith("/iterations"):
            return httpx.Response(200, json={"value": [{"id": 1}, {"id": 2}]})
        if request.url.path.endswith("/iterations/2/changes"):
            if request.url.params.get("continuationToken"):
                return httpx.Response(
                    200,
                    json={"changeEntries": [{"changeType": "add", "item": {"path": "/b.py"}}]},
                )
            return httpx.Response(
                200,
                headers={"x-ms-continuationtoken": "next"},
                json={"changeEntries": [{"changeType": "edit", "item": {"path": "/a.py"}}]},
            )
        if request.url.path.endswith("/items"):
            return httpx.Response(200, text="x" * 20)
        raise AssertionError(request.url)

    client = AdoClient(
        "https://dev.azure.com/org",
        "Project",
        "repo",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        sleep_fn=lambda _: None,
        max_file_bytes=10,
        max_total_bytes=15,
    )
    diff = client.fetch_diff(_job())
    assert diff.iteration_id == 2
    assert len(diff.changed_files) == 2
    assert diff.truncated is True
    assert calls[0].headers["Authorization"] == "Basic " + base64.b64encode(b":pat-value").decode()


def test_ado_retries_throttled_request():
    attempts = []

    def handler(request: httpx.Request):
        attempts.append(1)
        if len(attempts) == 1:
            return httpx.Response(429, headers={"retry-after": "0"})
        return httpx.Response(200, json={"value": []})

    client = AdoClient(
        "https://dev.azure.com/org",
        "Project",
        "repo",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        sleep_fn=lambda _: None,
    )
    assert client.get_pr_iterations(7) == []
    assert len(attempts) == 2


def test_missing_file_is_treated_as_empty():
    def handler(request: httpx.Request):
        return httpx.Response(404)

    client = AdoClient(
        "https://dev.azure.com/org",
        "Project",
        "repo",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert client.get_file_content("/missing.py", "feature") == ""


def test_hackathon_mode_reads_pat_from_environment(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "hackathon")
    monkeypatch.setenv("HACKATHON_MODE", "true")
    monkeypatch.setenv("ADO_PAT", "hackathon-pat")
    assert get_ado_pat() == "hackathon-pat"
