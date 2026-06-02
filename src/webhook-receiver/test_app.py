"""Basic smoke tests for the webhook handler (no Azure dependencies)."""

import hashlib
import hmac
import json

from app import handler, validate_ado_signature


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


def _make_signature(body: bytes, secret: str) -> str:
    return "sha1=" + hmac.new(secret.encode(), body, hashlib.sha1).hexdigest()


def test_valid_signature():
    body = b"hello"
    secret = "mysecret"
    sig = _make_signature(body, secret)
    assert validate_ado_signature(body, sig, secret)


def test_invalid_signature():
    body = b"hello"
    assert not validate_ado_signature(body, "sha1=bad", "mysecret")


def test_missing_signature_with_no_secret_passes():
    body = json.dumps(ADO_PR_EVENT).encode()
    result = handler(body, {})
    # No secret configured → signature check skipped → 202 Accepted
    assert result["status"] == 202


def test_pr_created_accepted():
    body = json.dumps(ADO_PR_EVENT).encode()
    result = handler(body, {})
    assert result["status"] == 202


def test_irrelevant_event_ignored():
    event = {**ADO_PR_EVENT, "eventType": "build.complete"}
    body = json.dumps(event).encode()
    result = handler(body, {})
    assert result["status"] == 200
    assert "ignored" in result["body"]


def test_invalid_json_rejected():
    result = handler(b"not-json", {})
    assert result["status"] == 400
