"""Route-level coverage for control and exception administration."""

import base64
import json
from datetime import UTC, datetime, timedelta

import azure.functions as func
import pytest

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


def _principal(*roles):
    claims = [{"typ": "roles", "val": role} for role in roles]
    encoded = base64.b64encode(json.dumps({"user_details": "user@example.com", "claims": claims}).encode()).decode()
    return {"X-MS-CLIENT-PRINCIPAL-NAME": "user@example.com", "X-MS-CLIENT-PRINCIPAL": encoded}


@pytest.fixture
def plane(monkeypatch):
    value = ControlPlane(connection_string="")
    value.save_policy_document(
        {"title": "Sanctions and Geographic Restrictions", "version": "2026-01", "filename": "sanctions.txt"},
        "Software must not set any deployment location to Russia or Russian territories.",
        actor="author@example.com",
    )
    monkeypatch.setattr(admin, "get_control_plane", lambda: value)
    return value


def _draft(plane, version="1.0", *, questions=None):
    return plane.save_control(
        {
            "control_id": "sanctions.russia-location",
            "version": version,
            "state": "needs_clarification" if questions else "draft",
            "title": "Prohibited deployment location",
            "prohibited_condition": "Deployment configuration must not target Russia.",
            "control_type": "config_iac",
            "severity": "ERROR",
            "policy_document_id": "sanctions-and-geographic-restrictions",
            "policy_version": "2026-01",
            "policy_title": "Sanctions and Geographic Restrictions",
            "source_reference": {"excerpt": "must not set any deployment location to Russia"},
            "detector": {"field_names": ["region"], "prohibited_values": ["ru-central"]},
            "validation": {"passed": True, "tests": []},
            "clarification_questions": questions or [],
        },
        actor="author@example.com",
    )


def _act(action, control, **extra):
    return admin.control_action(_request("POST", {"action": action, "control_id": control["control_id"], "version": control["version"], **extra}))


def test_controls_listing_never_exposes_detector_internals(plane):
    _draft(plane)

    payload = json.loads(admin.controls(_request()).get_body())

    [control] = payload["controls"]
    assert control["control_type"] == "config_iac"
    assert control["title"] == "Prohibited deployment location"
    assert "detector" not in control
    body = json.dumps(payload).lower()
    assert "prohibited_values" not in body and "semgrep" not in body and "regex" not in body


def test_full_approval_and_activation_walk_through_the_routes(plane):
    control = _draft(plane)

    approve = _act("approve", control, notes="Reviewed with AppSec")
    assert approve.status_code == 200
    approval = json.loads(approve.get_body())
    assert approval["control"]["state"] == "approved"
    assert approval["approval"]["approver"]

    assert json.loads(_act("activate", control).get_body())["control"]["state"] == "active"
    assert json.loads(_act("suspend", control).get_body())["control"]["state"] == "suspended"
    assert json.loads(_act("activate", control).get_body())["control"]["state"] == "active"
    assert json.loads(_act("retire", control).get_body())["control"]["state"] == "retired"


def test_clarify_route_answers_questions_and_returns_the_control_to_draft(plane):
    question = "Does this include test code?"
    control = _draft(plane, questions=[question])

    response = _act("clarify", control, answers=[{"question": question, "answer": "No."}])

    assert response.status_code == 200
    value = json.loads(response.get_body())["control"]
    assert value["state"] == "draft" and value["clarification_questions"] == []


def test_revise_route_creates_a_new_immutable_version(plane):
    control = _draft(plane)
    _act("approve", control)

    response = _act("revise", control, new_version="1.1", title="Prohibited deployment region")

    assert response.status_code == 201
    assert json.loads(response.get_body())["control"]["version"] == "1.1"
    assert plane.get_control(control["control_id"], "1.0")["state"] == "approved"


def test_unknown_and_invalid_control_actions_are_rejected(plane):
    control = _draft(plane)

    assert admin.control_action(_request("POST", {"action": "delete", "control_id": "x", "version": "1.0"})).status_code == 400
    assert _act("activate", control).status_code == 400  # never approved
    assert _act("approve", {"control_id": "missing", "version": "9.9"}).status_code == 400


def test_only_retired_controls_can_be_removed(plane):
    control = _draft(plane)

    assert _act("remove", control).status_code == 400
    assert _act("retire", control).status_code == 200
    assert _act("remove", control).status_code == 200
    assert plane.get_control(control["control_id"], control["version"]) is None


@pytest.mark.parametrize(
    "action, required_role, extra",
    [
        ("approve", "Policy.Approver", {}),
        ("activate", "Policy.Activator", {}),
        ("suspend", "Policy.Activator", {}),
        ("retire", "Policy.Activator", {}),
        ("revise", "Policy.Author", {"new_version": "1.1"}),
        ("clarify", "Policy.Author", {"answers": []}),
    ],
)
def test_control_actions_require_their_entra_role(plane, monkeypatch, action, required_role, extra):
    monkeypatch.setenv("ADMIN_REQUIRE_ENTRA", "true")
    control = _draft(plane)

    denied = admin.control_action(
        _request("POST", {"action": action, "control_id": control["control_id"], "version": "1.0", **extra}, headers=_principal("Viewer"))
    )

    assert denied.status_code == 401
    assert required_role in json.loads(denied.get_body())["error"]


def test_policy_admin_role_satisfies_every_control_action(plane, monkeypatch):
    monkeypatch.setenv("ADMIN_REQUIRE_ENTRA", "true")
    control = _draft(plane)

    response = admin.control_action(
        _request("POST", {"action": "approve", "control_id": control["control_id"], "version": "1.0"}, headers=_principal("Policy.Admin"))
    )

    assert response.status_code == 200
    assert json.loads(response.get_body())["approval"]["approver"]


def _exception_body(**extra):
    return {
        "control_id": "sanctions.russia-location",
        "control_version": "1.0",
        "repository_id": "repo-1",
        "approved_value": "ru-central",
        "business_justification": "Documented migration window",
        "expiration_date": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
        "reference_ticket": "SEC-1234",
        **extra,
    }


def test_exception_can_be_created_listed_and_revoked(plane):
    created = admin.exceptions(_request("POST", _exception_body()))
    assert created.status_code == 201
    value = json.loads(created.get_body())["exception"]
    assert value["status"] == "approved" and value["reference_ticket"] == "SEC-1234"

    listed = json.loads(admin.exceptions(_request()).get_body())["exceptions"]
    assert [item["exception_id"] for item in listed] == [value["exception_id"]]

    revoked = admin.exception_action(_request("POST", {"action": "revoke", "exception_id": value["exception_id"]}))
    assert json.loads(revoked.get_body())["exception"]["status"] == "revoked"


def test_exception_requires_justification_expiry_and_the_approver_role(plane, monkeypatch):
    assert admin.exceptions(_request("POST", _exception_body(business_justification=""))).status_code == 400
    assert admin.exceptions(_request("POST", _exception_body(expiration_date="2000-01-01T00:00:00Z"))).status_code == 400
    assert admin.exception_action(_request("POST", {"action": "delete", "exception_id": "x"})).status_code == 400

    monkeypatch.setenv("ADMIN_REQUIRE_ENTRA", "true")
    denied = admin.exceptions(_request("POST", _exception_body(), headers=_principal("Viewer")))
    assert denied.status_code == 401
    assert "Exception.Approver" in json.loads(denied.get_body())["error"]


def test_audit_log_records_who_changed_what(plane):
    control = _draft(plane)
    _act("approve", control)
    _act("activate", control)
    admin.exceptions(_request("POST", _exception_body()))

    events = json.loads(admin.audit_events(_request()).get_body())["events"]

    actions = {event["action"] for event in events}
    assert {"control.proposed", "control.approved", "control.transitioned", "exception.approved"} <= actions
    assert all(event.get("actor") for event in events)
