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


def test_portal_groups_navigation_and_supports_page_finder():
    response = admin.portal(_request())

    assert response.status_code == 200
    page = response.get_body().decode()
    assert 'id="nav-search"' in page
    assert 'data-nav-group' in page
    assert "Press Ctrl/Cmd + K to search" in page
    assert 'data-view="controls" data-search="controls rules safeguards generated controls"' in page
    assert "function filterNavigation(value)" in page


def test_portal_groups_and_filters_long_policy_and_control_lists():
    response = admin.portal(_request())

    page = response.get_body().decode()
    assert 'id="policy-list-search"' in page
    assert 'id="control-list-search"' in page
    assert 'id="control-state-filter"' in page
    assert 'id="control-policy-filter"' in page
    assert 'id="control-group-nav"' in page
    assert "const controlGroups=" in page
    assert "function renderGroupedPolicyEngine()" in page
    assert "Action required" in page and "Inactive or retired" in page


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


def test_only_retired_policy_without_controls_can_be_removed(monkeypatch):
    plane = ControlPlane(connection_string="")
    policy = plane.save_policy_document(
        {"title": "Retired policy", "version": "1.0", "filename": "policy.txt"},
        "A retired policy source.",
    )
    monkeypatch.setattr(admin, "get_control_plane", lambda: plane)

    assert admin.policy_action(_request("POST", {"action": "remove", "document_id": policy["document_id"], "version": "1.0"})).status_code == 400
    assert admin.policy_action(_request("POST", {"action": "retire", "document_id": policy["document_id"], "version": "1.0"})).status_code == 200
    assert admin.policy_action(_request("POST", {"action": "remove", "document_id": policy["document_id"], "version": "1.0"})).status_code == 200
    assert plane.get_policy(policy["document_id"], "1.0") is None


def _policy_with_clause(plane):
    text = "Software must not integrate crypto wallets or blockchain transaction services."
    policy = plane.save_policy_document(
        {"title": "Crypto", "version": "2026-01", "filename": "policy.txt"}, text
    )
    plane.save_policy_extraction(
        policy["document_id"],
        policy["version"],
        text=text,
        clauses=[{"clause_id": "clause-00001", "paragraph": 1, "excerpt": text}],
    )
    plane.save_policy_analysis(
        policy["document_id"],
        policy["version"],
        {
            "obligations": [{
                "obligation_id": "crypto-integration",
                "statement": text,
                "detection_surfaces": ["dependencies"],
                "source_reference": {"clause_id": "clause-00001", "paragraph": 1, "excerpt": text},
            }],
            "coverage_complete": False,
            "coverage_questions": ["No dependency control has been authored."],
        },
    )
    return policy, text


def test_deterministic_control_is_authored_only_after_server_side_tests(monkeypatch):
    plane = ControlPlane(connection_string="")
    policy, text = _policy_with_clause(plane)
    monkeypatch.setattr(admin, "get_control_plane", lambda: plane)
    response = admin.controls(
        _request(
            "POST",
            {
                "control_id": "crypto.prohibited-dependencies",
                "version": "2.0",
                "title": "Crypto dependency",
                "prohibited_condition": "Crypto dependencies are prohibited.",
                "control_type": "dependency",
                "severity": "ERROR",
                "policy_document_id": policy["document_id"],
                "policy_version": policy["version"],
                "source_reference": {"clause_id": "clause-00001", "excerpt": text},
                "detector": {"packages": ["web3"]},
                "tests": [
                    {"file": "requirements.txt", "content": "web3==7.0\n", "should_match": True},
                    {"file": "requirements.txt", "content": "requests==2.0\n", "should_match": False},
                ],
            },
        )
    )
    payload = json.loads(response.get_body())
    assert response.status_code == 201
    assert payload["control"]["validation"]["passed"] is True
    assert payload["control"]["state"] == "draft"
    assert payload["control"]["obligation_ids"] == ["crypto-integration"]
    assert plane.get_policy(policy["document_id"], policy["version"])["coverage_complete"] is True


def test_authored_control_rejects_unverified_citation(monkeypatch):
    plane = ControlPlane(connection_string="")
    policy, _ = _policy_with_clause(plane)
    monkeypatch.setattr(admin, "get_control_plane", lambda: plane)
    response = admin.controls(
        _request(
            "POST",
            {
                "control_id": "crypto.bad",
                "version": "2.0",
                "title": "Bad citation",
                "prohibited_condition": "Crypto dependencies are prohibited.",
                "control_type": "dependency",
                "policy_document_id": policy["document_id"],
                "policy_version": policy["version"],
                "source_reference": {"clause_id": "clause-00001", "excerpt": "invented text"},
                "detector": {"packages": ["web3"]},
                "tests": [
                    {"file": "requirements.txt", "content": "web3==7.0\n", "should_match": True},
                    {"file": "requirements.txt", "content": "requests==2.0\n", "should_match": False},
                ],
            },
        )
    )
    assert response.status_code == 400
    assert "exact excerpt" in json.loads(response.get_body())["error"]


def test_authored_control_is_not_saved_when_detector_fails_its_examples(monkeypatch):
    plane = ControlPlane(connection_string="")
    policy, text = _policy_with_clause(plane)
    monkeypatch.setattr(admin, "get_control_plane", lambda: plane)
    response = admin.controls(
        _request(
            "POST",
            {
                "control_id": "crypto.invalid-detector",
                "version": "2.0",
                "title": "Invalid detector",
                "prohibited_condition": "Crypto dependencies are prohibited.",
                "control_type": "dependency",
                "policy_document_id": policy["document_id"],
                "policy_version": policy["version"],
                "source_reference": {"clause_id": "clause-00001", "excerpt": text},
                "detector": {"packages": ["ethers"]},
                "tests": [
                    {"file": "requirements.txt", "content": "web3==7.0\n", "should_match": True},
                    {"file": "requirements.txt", "content": "requests==2.0\n", "should_match": False},
                ],
            },
        )
    )
    assert response.status_code == 400
    assert "validation failed" in json.loads(response.get_body())["error"]
    assert plane.get_control("crypto.invalid-detector", "2.0") is None


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


def test_reference_source_creation_and_approval_require_policy_roles(monkeypatch):
    plane = ControlPlane(connection_string="")
    monkeypatch.setenv("ADMIN_REQUIRE_ENTRA", "true")
    monkeypatch.setattr(admin, "get_control_plane", lambda: plane)
    author_principal = base64.b64encode(
        json.dumps({"claims": [{"typ": "roles", "val": "Policy.Author"}]}).encode()
    ).decode()
    approver_principal = base64.b64encode(
        json.dumps({"claims": [{"typ": "roles", "val": "Policy.Approver"}]}).encode()
    ).decode()
    created = admin.regulation(
        _request(
            "POST",
            {"title": "Reference", "version": "1.0", "status": "draft", "content": "Use TLS."},
            headers={"X-MS-CLIENT-PRINCIPAL-NAME": "author@example.com", "X-MS-CLIENT-PRINCIPAL": author_principal},
        )
    )
    assert created.status_code == 200
    document_id = json.loads(created.get_body())["regulation"]["document_id"]
    approved = admin.regulation(
        _request(
            "POST",
            {"action": "approve", "document_id": document_id, "version": "1.0"},
            headers={"X-MS-CLIENT-PRINCIPAL-NAME": "approver@example.com", "X-MS-CLIENT-PRINCIPAL": approver_principal},
        )
    )
    assert approved.status_code == 200
    assert json.loads(approved.get_body())["regulation"]["status"] == "approved"
