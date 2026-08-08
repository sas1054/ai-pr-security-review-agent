import base64
import json

import azure.functions as func

import admin
from prsa_control import ControlPlane


def _request(method="GET", body=None, params=None, headers=None):
    return func.HttpRequest(
        method=method,
        url="http://localhost/api/admin/api/test",
        headers=headers or {},
        params=params or {},
        route_params={},
        body=json.dumps(body).encode() if body is not None else b"",
    )


def test_pasted_policy_is_stored_and_queued(monkeypatch):
    plane = ControlPlane(connection_string="")
    monkeypatch.setattr(admin, "get_control_plane", lambda: plane)
    monkeypatch.setattr(
        admin,
        "queue_policy_job",
        lambda document_id, version, **kwargs: {"job_id": "job-1", "document_id": document_id, "policy_version": version},
    )
    response = admin.policies(
        _request(
            "POST",
            {
                "input_type": "paste",
                "title": "Sanctions",
                "version": "2026-01",
                "content": "Software must not deploy to Russia.",
            },
        )
    )
    assert response.status_code == 202
    payload = json.loads(response.get_body())
    assert payload["policy"]["source_sha256"]
    assert payload["job"]["job_id"] == "job-1"


def test_upload_rejects_invalid_base64(monkeypatch):
    plane = ControlPlane(connection_string="")
    monkeypatch.setattr(admin, "get_control_plane", lambda: plane)
    response = admin.policies(
        _request("POST", {"input_type": "upload", "title": "Policy", "filename": "policy.pdf", "content_base64": "%%%"})
    )
    assert response.status_code == 400


def test_failed_policy_can_be_requeued_without_mutating_its_version(monkeypatch):
    plane = ControlPlane(connection_string="")
    policy = plane.save_policy_document(
        {"title": "Sanctions", "version": "2026-01", "filename": "policy.txt"},
        "Software must not deploy to Russia.",
    )
    monkeypatch.setattr(admin, "get_control_plane", lambda: plane)
    monkeypatch.setattr(
        admin,
        "queue_policy_job",
        lambda document_id, version, **kwargs: {"job_id": "job-retry", "document_id": document_id, "policy_version": version},
    )

    response = admin.policy_job(
        _request("POST", {"document_id": policy["document_id"], "version": policy["version"]})
    )

    assert response.status_code == 202
    assert json.loads(response.get_body())["job"]["job_id"] == "job-retry"


def test_entra_role_is_required_for_policy_authoring(monkeypatch):
    monkeypatch.setenv("ADMIN_REQUIRE_ENTRA", "true")
    response = admin.policies(
        _request(
            "POST",
            {"input_type": "paste", "title": "Policy", "content": "Requirement"},
            headers={"X-MS-CLIENT-PRINCIPAL-NAME": "author@example.com"},
        )
    )
    assert response.status_code == 401
    assert "Policy.Author" in json.loads(response.get_body())["error"]


def test_entra_role_claim_allows_policy_authoring(monkeypatch):
    plane = ControlPlane(connection_string="")
    monkeypatch.setenv("ADMIN_REQUIRE_ENTRA", "true")
    monkeypatch.setattr(admin, "get_control_plane", lambda: plane)
    monkeypatch.setattr(admin, "queue_policy_job", lambda *args, **kwargs: {"job_id": "job-2"})
    principal = base64.b64encode(
        json.dumps({"claims": [{"typ": "roles", "val": "Policy.Author"}]}).encode()
    ).decode()
    response = admin.policies(
        _request(
            "POST",
            {"input_type": "paste", "title": "Policy", "content": "Requirement"},
            headers={"X-MS-CLIENT-PRINCIPAL-NAME": "author@example.com", "X-MS-CLIENT-PRINCIPAL": principal},
        )
    )
    assert response.status_code == 202
