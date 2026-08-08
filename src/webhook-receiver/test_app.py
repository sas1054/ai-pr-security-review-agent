"""Unit tests for webhook business logic; Azure clients are not contacted."""

import hashlib
import json

from app import _get_sb_client, handler
from prsa_control import ControlPlane


ADO_PR_EVENT = {
    "eventType": "git.pullrequest.created",
    "resource": {
        "pullRequestId": 42,
        "title": "Add login feature",
        "sourceRefName": "refs/heads/feature/login",
        "targetRefName": "refs/heads/main",
        "repository": {
            "id": "repo-id-123",
            "name": "my-service",
            "project": {"name": "MyProject"},
        },
    },
    "resourceContainers": {
        "collection": {"href": "https://dev.azure.com/myorg"}
    },
}

def test_pr_created_is_accepted_after_host_authentication(monkeypatch):
    captured = {}
    controls = ControlPlane(connection_string="")
    monkeypatch.setattr("app.enqueue_job", lambda job: captured.update(job) or True)
    monkeypatch.setattr("app.get_control_plane", lambda: controls)
    body = json.dumps(ADO_PR_EVENT).encode()
    result = handler(body)
    assert result["status"] == 202
    assert captured["job_version"] == 1
    assert captured["event_id"]
    assert captured["run_id"].startswith("run-")
    assert captured["target_branch"] == "refs/heads/main"
    review = controls.get_review(captured["run_id"])
    assert review and review["status"] == "queued"


def test_duplicate_webhook_does_not_enqueue_a_second_run(monkeypatch):
    controls = ControlPlane(connection_string="")
    sent = []
    monkeypatch.setattr("app.get_control_plane", lambda: controls)
    monkeypatch.setattr("app.enqueue_job", lambda job: sent.append(job) or True)
    body = json.dumps(ADO_PR_EVENT).encode()
    assert handler(body)["status"] == 202
    assert handler(body) == {"status": 200, "body": "OK (duplicate)"}
    assert len(sent) == 1


def test_missing_service_bus_is_unavailable_in_production(monkeypatch):
    controls = ControlPlane(connection_string="")
    monkeypatch.delenv("SERVICE_BUS_CONNECTION_STRING", raising=False)
    monkeypatch.delenv("SERVICE_BUS_NAMESPACE", raising=False)
    monkeypatch.setattr("app._sb_client", None)
    monkeypatch.setattr("app.get_control_plane", lambda: controls)
    body = json.dumps(ADO_PR_EVENT).encode()
    result = handler(body)
    assert result["status"] == 503


def test_irrelevant_event_ignored(monkeypatch):
    event = {**ADO_PR_EVENT, "eventType": "build.complete"}
    body = json.dumps(event).encode()
    result = handler(body)
    assert result["status"] == 200
    assert "ignored" in result["body"]


def test_updated_pr_is_ignored_when_cost_control_is_enabled(monkeypatch):
    monkeypatch.setenv("REVIEW_ON_UPDATED_EVENTS", "false")
    event = {**ADO_PR_EVENT, "eventType": "git.pullrequest.updated"}
    result = handler(json.dumps(event).encode())
    assert result["status"] == 200
    assert "ignored" in result["body"]


def test_hackathon_mode_uses_service_bus_connection_string(monkeypatch):
    captured = {}

    class FakeServiceBusClient:
        @classmethod
        def from_connection_string(cls, value):
            captured["connection_string"] = value
            return "client"

    monkeypatch.setattr("app.ServiceBusClient", FakeServiceBusClient)
    monkeypatch.setattr("app._sb_client", None)
    monkeypatch.setenv("SERVICE_BUS_CONNECTION_STRING", "Endpoint=sb://hackathon/")
    assert _get_sb_client() == "client"
    assert captured["connection_string"] == "Endpoint=sb://hackathon/"


def test_invalid_json_rejected():
    result = handler(b"not-json")
    assert result["status"] == 400


def test_missing_required_pr_fields_rejected(monkeypatch):
    event = {**ADO_PR_EVENT, "resource": {**ADO_PR_EVENT["resource"], "pullRequestId": None}}
    result = handler(json.dumps(event).encode())
    assert result["status"] == 400
