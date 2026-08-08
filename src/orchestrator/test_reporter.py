import json

import httpx

from models import ReviewJob, ReviewResult, TriageItem, TriageResult
from reporter import AdoReporter
from scanner import Finding


def test_reporter_posts_summary_inline_comment_and_status(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "local")
    monkeypatch.setenv("ADO_PAT", "pat")
    requests = []
    stored_comments = []

    def handler(request: httpx.Request):
        requests.append(request)
        if request.method == "GET":
            return httpx.Response(200, json={"value": [{"comments": [{"content": text} for text in stored_comments]}]})
        body = json.loads(request.content.decode())
        if request.url.path.endswith("/threads"):
            stored_comments.extend(comment["content"] for comment in body["comments"])
        return httpx.Response(200, json={"id": len(requests)})

    job = ReviewJob.from_dict(
        {
            "event_id": "event-1",
            "event_type": "git.pullrequest.created",
            "organization_url": "https://dev.azure.com/org",
            "project": "Project",
            "repo_id": "repo",
            "repo_name": "service",
            "pr_id": 7,
            "source_branch": "feature",
            "target_branch": "main",
        }
    )
    finding = Finding(
        "policy-config_iac", "sanctions.russia-location", "/app.py", 2, "ERROR", "Prohibited deployment location",
        fix_hint="Use an approved region.", control_id="sanctions.russia-location", control_version="1.0",
        reason="Russian locations are prohibited.", policy_document="Sanctions", policy_version="2026-01",
        source_reference={"page": 3, "section": "Geographic restrictions", "excerpt": "Software must not deploy to Russia."},
        confidence=0.97, matched_value="ru-central",
    )
    result = ReviewResult(
        run_id="run-1",
        job=job,
        status="completed",
        findings=[finding],
        triage=TriageResult(
            summary="Prioritized",
            items=[TriageItem(finding.fingerprint, "high", False, "Move it")],
        ),
        summary="Prioritized",
        iteration_id=3,
    )
    reporter = AdoReporter(http_client=httpx.Client(transport=httpx.MockTransport(handler)))
    reporter.publish(result)
    reporter.publish(result)
    post_paths = [request.url.path for request in requests if request.method == "POST"]
    assert sum(path.endswith("/threads") for path in post_paths) == 2
    assert sum(path.endswith("/statuses") for path in post_paths) == 2
    assert any("threadContext" in json.loads(request.content.decode()) for request in requests if request.method == "POST" and request.url.path.endswith("/threads"))
    assert any("Policy statement" in comment and "Sanctions" in comment for comment in stored_comments)


def test_reporter_puts_unpositioned_findings_in_summary(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "local")
    monkeypatch.setenv("ADO_PAT", "pat")
    bodies = []

    def handler(request: httpx.Request):
        if request.method == "GET":
            return httpx.Response(200, json={"value": []})
        bodies.append(json.loads(request.content.decode()))
        return httpx.Response(200, json={})

    job = ReviewJob.from_dict(
        {
            "event_id": "event-2",
            "event_type": "git.pullrequest.created",
            "organization_url": "https://dev.azure.com/org",
            "project": "Project",
            "repo_id": "repo",
            "repo_name": "service",
            "pr_id": 8,
            "source_branch": "feature",
            "target_branch": "main",
        }
    )
    finding = Finding("secret-scan", "hardcoded-password", "", 0, "ERROR", "secret")
    result = ReviewResult(
        run_id="run-2",
        job=job,
        status="completed",
        findings=[finding],
        summary="Review completed",
        iteration_id=1,
    )
    AdoReporter(http_client=httpx.Client(transport=httpx.MockTransport(handler))).publish(result)
    assert len(bodies) == 2
    assert "without an inline location" in bodies[0]["comments"][0]["content"]
    assert "threadContext" not in bodies[0]
