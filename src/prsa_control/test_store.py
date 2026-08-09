from prsa_control.store import ControlPlane
from datetime import UTC, datetime, timedelta
import pytest


def _job():
    return {
        "job_version": 1,
        "event_id": "event-1",
        "event_type": "git.pullrequest.created",
        "organization_url": "https://dev.azure.com/example",
        "project": "Platform",
        "repo_id": "repo-1",
        "repo_name": "payments",
        "pr_id": 12,
        "source_branch": "refs/heads/feature/monitoring",
        "target_branch": "refs/heads/main",
        "title": "Add PR monitor",
    }


def test_review_lifecycle_preserves_queued_and_started_timestamps():
    controls = ControlPlane(connection_string="")
    job = _job()
    queued = controls.record_review_queued(job, "run-1")
    assert queued["status"] == "queued"
    assert queued["queued_at"]

    running = controls.mark_review_running(job, "run-1")
    assert running["status"] == "running"
    assert running["attempts"] == 1
    assert running["queued_at"] == queued["queued_at"]
    assert running["started_at"]

    completed = controls.record_review(
        {
            "run_id": "run-1",
            "repo_id": "repo-1",
            "status": "completed",
            "summary": "Clean review",
            "counts": {"findings": 0},
        }
    )
    assert completed["queued_at"] == queued["queued_at"]
    assert completed["started_at"] == running["started_at"]
    assert completed["completed_at"]


def test_failed_run_is_counted_for_the_dashboard():
    controls = ControlPlane(connection_string="")
    controls.record_review_queued(_job(), "run-2")
    controls.mark_review_failed(_job(), "run-2", "ADO timeout")
    dashboard = controls.dashboard()
    assert dashboard["stats"]["failed_reviews"] == 1
    assert dashboard["reviews"][0]["status"] == "failed"


def _control(policy):
    return {
        "control_id": "sanctions.russia-location",
        "version": "1.0",
        "title": "Russian location restriction",
        "description": "Detects prohibited Russian deployment locations",
        "prohibited_condition": "Deployment location must not target Russia.",
        "control_type": "literal_value",
        "severity": "ERROR",
        "policy_document_id": policy["document_id"],
        "policy_version": policy["version"],
        "policy_title": policy["title"],
        "source_reference": {"paragraph": 1, "excerpt": "Software must not deploy to Russia."},
        "detector": {"prohibited_values": ["Russia", "RU"]},
        "validation": {"passed": True, "tests": [{"passed": True}]},
    }


def test_policy_control_lifecycle_is_versioned_and_approval_gated():
    plane = ControlPlane(connection_string="")
    policy = plane.save_policy_document({"title": "Sanctions", "version": "2026-01", "filename": "policy.txt"}, "Software must not deploy to Russia.")
    control = plane.save_control(_control(policy))
    with pytest.raises(ValueError, match="transition"):
        plane.transition_control(control["control_id"], "1.0", "active")
    approval = plane.approve_control(control["control_id"], "1.0", actor="approver@example.com")
    assert approval["policy_version"] == "2026-01"
    active = plane.transition_control(control["control_id"], "1.0", "active", actor="activator@example.com")
    assert active["state"] == "active"
    hydrated, versions = plane.active_controls()
    assert hydrated[0]["detector"]["prohibited_values"] == ["Russia", "RU"]
    assert versions == ["sanctions.russia-location@1.0"]


def test_policy_versions_cannot_be_overwritten():
    plane = ControlPlane(connection_string="")
    raw = {"title": "Sanctions", "version": "1.0", "filename": "policy.txt"}
    plane.save_policy_document(raw, "First")
    with pytest.raises(ValueError, match="already exists"):
        plane.save_policy_document(raw, "Second")


def test_activation_feature_flag_is_fail_closed():
    plane = ControlPlane(connection_string="")
    policy = plane.save_policy_document({"title": "Sanctions", "filename": "policy.txt"}, "Software must not deploy to Russia.")
    control = plane.save_control(_control(policy))
    plane.approve_control(control["control_id"], "1.0", actor="approver")
    plane.update_settings({"control_activation_enabled": False})
    with pytest.raises(ValueError, match="disabled"):
        plane.transition_control(control["control_id"], "1.0", "active", actor="activator")


def test_active_partially_compiled_policy_declares_coverage_gap():
    plane = ControlPlane(connection_string="")
    policy = plane.save_policy_document(
        {"title": "Repository Governance", "version": "1.0", "filename": "policy.txt"},
        "Repositories must require two reviewers.",
    )
    plane.save_policy_analysis(
        policy["document_id"],
        policy["version"],
        {
            "obligations": [{"obligation_id": "reviewers"}],
            "coverage_complete": False,
            "coverage_questions": ["No repository-settings adapter is configured."],
        },
    )
    control = plane.save_control(_control(policy))
    plane.approve_control(control["control_id"], control["version"], actor="approver")
    plane.transition_control(control["control_id"], control["version"], "active", actor="activator")
    active, _ = plane.active_controls()

    gaps = plane.policy_coverage_gaps(active)

    assert len(gaps) == 1
    assert "partial PR coverage" in gaps[0]
    assert "repository-settings adapter" in gaps[0]


def test_clarification_must_be_answered_before_approval():
    plane = ControlPlane(connection_string="")
    policy = plane.save_policy_document({"title": "Crypto", "filename": "policy.txt"}, "Anything related to cryptocurrency is prohibited.")
    raw = _control(policy)
    raw.update({"control_id": "crypto", "state": "needs_clarification", "clarification_questions": ["Does this include test code?"]})
    control = plane.save_control(raw)
    answered = plane.answer_control_clarifications(
        control["control_id"], control["version"], [{"question": "Does this include test code?", "answer": "No"}], actor="admin"
    )
    assert answered["state"] == "draft"
    assert answered["clarification_answers"][0]["answer"] == "No"
    assert plane.get_policy(policy["document_id"], policy["version"])["status"] == "ready"


def test_expiring_exception_is_only_returned_while_active():
    plane = ControlPlane(connection_string="")
    exception = plane.save_exception(
        {
            "control_id": "crypto",
            "repository_id": "repo-1",
            "approved_value": "approved-sdk",
            "business_justification": "Approved migration",
            "expiration_date": (datetime.now(UTC) + timedelta(days=2)).isoformat(),
            "reference_ticket": "SEC-42",
        },
        actor="security@example.com",
    )
    assert plane.list_exceptions(include_expired=False)[0]["exception_id"] == exception["exception_id"]
    plane.revoke_exception(exception["exception_id"], actor="security@example.com")
    assert plane.list_exceptions(include_expired=False) == []
