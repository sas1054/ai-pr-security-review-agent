"""Guards on the control lifecycle: legal transitions, approval gates, and immutability."""

import pytest

from prsa_control import ControlPlane
from prsa_control.store import CONTROL_TRANSITIONS

POLICY_TEXT = "Software must not set any deployment location to Russia or Russian territories."


@pytest.fixture
def plane():
    """A control plane holding the policy version that every control below cites."""
    value = ControlPlane(connection_string="")
    value.save_policy_document(
        {
            "title": "Sanctions and Geographic Restrictions",
            "version": "2026-01",
            "effective_date": "2026-01-01",
            "owner": "Security Engineering",
            "filename": "sanctions.txt",
            "input_type": "paste",
        },
        POLICY_TEXT,
        actor="author@example.com",
    )
    return value


def _control(plane, *, version="1.0", state="draft", passed=True, questions=None):
    return plane.save_control(
        {
            "control_id": "sanctions.russia-location",
            "version": version,
            "state": state,
            "title": "Prohibited deployment location",
            "prohibited_condition": "Deployment configuration must not target Russia.",
            "control_type": "config_iac",
            "severity": "ERROR",
            "policy_document_id": "sanctions-and-geographic-restrictions",
            "policy_version": "2026-01",
            "policy_title": "Sanctions and Geographic Restrictions",
            "source_reference": {"excerpt": "must not set any deployment location to Russia"},
            "detector": {"field_names": ["region"], "prohibited_values": ["ru-central"]},
            "validation": {"passed": passed, "tests": []},
            "clarification_questions": questions or [],
        },
        actor="author@example.com",
    )


def _approved(plane, version="1.0"):
    control = _control(plane, version=version)
    plane.approve_control(control["control_id"], version, actor="approver@example.com")
    return control


def test_new_controls_may_only_start_as_draft_or_needs_clarification(plane):
    with pytest.raises(ValueError):
        _control(plane, state="active")
    with pytest.raises(ValueError):
        _control(plane, state="approved")


@pytest.mark.parametrize(
    "start, target",
    sorted(
        (start, target)
        for start, allowed in CONTROL_TRANSITIONS.items()
        for target in CONTROL_TRANSITIONS
        if target not in allowed
    ),
)
def test_every_illegal_transition_is_rejected(plane, start, target):
    control = _control(plane, state="draft")
    control_id, version = control["control_id"], control["version"]

    # Walk the control into the starting state through legal steps only.
    if start == "needs_clarification":
        plane.transition_control(control_id, version, "needs_clarification", actor="a@example.com")
    elif start in {"approved", "active", "suspended", "retired"}:
        plane.approve_control(control_id, version, actor="approver@example.com")
        if start in {"active", "suspended"}:
            plane.transition_control(control_id, version, "active", actor="activator@example.com")
        if start == "suspended":
            plane.transition_control(control_id, version, "suspended", actor="activator@example.com")
        if start == "retired":
            plane.transition_control(control_id, version, "retired", actor="activator@example.com")

    assert plane.get_control(control_id, version)["state"] == start
    with pytest.raises(ValueError, match="Invalid control transition"):
        plane.transition_control(control_id, version, target, actor="activator@example.com")


def test_approval_requires_a_draft_that_passed_validation_without_open_questions(plane):
    failing = _control(plane, version="1.0", passed=False)
    with pytest.raises(ValueError, match="validation must pass"):
        plane.approve_control(failing["control_id"], "1.0", actor="approver@example.com")

    ambiguous = _control(plane, version="1.1", state="needs_clarification", questions=["Does this include tests?"])
    with pytest.raises(ValueError, match="only a draft control can be approved"):
        plane.approve_control(ambiguous["control_id"], "1.1", actor="approver@example.com")


def test_activation_requires_an_approval_record(plane):
    control = _control(plane)
    plane.transition_control(control["control_id"], "1.0", "needs_clarification", actor="a@example.com")
    plane.transition_control(control["control_id"], "1.0", "draft", actor="a@example.com")

    with pytest.raises(ValueError, match="Invalid control transition"):
        plane.transition_control(control["control_id"], "1.0", "active", actor="activator@example.com")


def test_activation_can_be_disabled_by_an_administrator(plane):
    control = _approved(plane)
    plane.update_settings({"control_activation_enabled": False}, actor="admin@example.com")

    with pytest.raises(ValueError, match="activation is disabled"):
        plane.transition_control(control["control_id"], "1.0", "active", actor="activator@example.com")


def test_activating_a_new_version_retires_the_previous_active_version(plane):
    first = _approved(plane, "1.0")
    plane.transition_control(first["control_id"], "1.0", "active", actor="activator@example.com")
    _approved(plane, "2.0")

    plane.transition_control(first["control_id"], "2.0", "active", actor="activator@example.com")

    assert plane.get_control(first["control_id"], "1.0")["state"] == "retired"
    assert plane.get_control(first["control_id"], "2.0")["state"] == "active"
    active, versions = plane.active_controls()
    assert versions == ["sanctions.russia-location@2.0"]
    assert active[0]["detector"]["prohibited_values"] == ["ru-central"]
    # The retired version is still readable so a historical review can be reproduced.
    assert plane.get_control(first["control_id"], "1.0")["validation"]["passed"] is True


def test_stale_revision_is_rejected_so_concurrent_edits_cannot_clobber_state(plane):
    control = _approved(plane)
    stale_revision = 1

    with pytest.raises(ValueError, match="changed by another user"):
        plane.transition_control(
            control["control_id"], "1.0", "active", actor="activator@example.com", expected_revision=stale_revision
        )

    current = plane.get_control(control["control_id"], "1.0")["revision"]
    plane.transition_control(control["control_id"], "1.0", "active", actor="activator@example.com", expected_revision=current)
    assert plane.get_control(control["control_id"], "1.0")["state"] == "active"


def test_clarification_answers_move_the_control_back_to_draft(plane):
    question = "Does this include test code?"
    control = _control(plane, state="needs_clarification", questions=[question])

    with pytest.raises(ValueError, match="Every clarification question requires an answer"):
        plane.answer_control_clarifications(control["control_id"], "1.0", [], actor="author@example.com")

    updated = plane.answer_control_clarifications(
        control["control_id"], "1.0", [{"question": question, "answer": "No, test code is excluded."}], actor="author@example.com"
    )

    assert updated["state"] == "draft"
    assert updated["clarification_questions"] == []
    assert updated["clarification_answers"] == [{"question": question, "answer": "No, test code is excluded."}]


def test_revision_creates_a_new_draft_and_never_mutates_the_approved_version(plane):
    control = _approved(plane)

    with pytest.raises(ValueError, match="new_version"):
        plane.revise_control(control["control_id"], "1.0", {"new_version": "1.0"}, actor="author@example.com")
    with pytest.raises(ValueError, match="requires policy regeneration"):
        plane.revise_control(
            control["control_id"],
            "1.0",
            {"new_version": "1.1", "detector": {"prohibited_values": ["anything"]}},
            actor="author@example.com",
        )

    revised = plane.revise_control(
        control["control_id"], "1.0", {"new_version": "1.1", "title": "Prohibited deployment region"}, actor="author@example.com"
    )

    assert revised["version"] == "1.1" and revised["state"] == "draft"
    assert revised["title"] == "Prohibited deployment region"
    assert plane.get_control(control["control_id"], "1.0")["state"] == "approved"
    assert plane.get_control(control["control_id"], "1.0")["title"] == "Prohibited deployment location"


def test_approval_record_captures_the_audit_evidence_required_for_review(plane):
    control = _control(plane)

    approval = plane.approve_control(control["control_id"], "1.0", actor="approver@example.com", notes="Reviewed with AppSec")

    assert approval["approver"] == "approver@example.com"
    assert approval["approved_at"]
    assert approval["policy_version"] == "2026-01"
    assert approval["control_version"] == "1.0"
    assert approval["validation"]["passed"] is True
    assert approval["source_reference"]["excerpt"]
    assert approval["notes"] == "Reviewed with AppSec"
    actions = {event["action"] for event in plane.list_audit_events()}
    assert {"control.proposed", "control.approved", "control.transitioned"} <= actions
