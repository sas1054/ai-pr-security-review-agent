"""Exception scoping, suppression, and automatic expiry."""

from datetime import UTC, datetime, timedelta

import pytest

from ado_client import ChangedFile, PrDiff
from models import ReviewJob
from orchestrator import _apply_exceptions, process_review
from prsa_control import ControlPlane
from prsa_control.store import EXCEPTIONS_TABLE
from scanner import Finding, run_typed_control_scan


CONTROL = {
    "control_id": "sanctions.russia-location",
    "version": "1.0",
    "control_type": "config_iac",
    "severity": "ERROR",
    "detector": {"field_names": ["region"], "prohibited_values": ["ru-central"], "file_globs": ["*.yaml"]},
    "policy_title": "Sanctions and Geographic Restrictions",
    "policy_version": "2026-01",
    "source_reference": {"excerpt": "must not set any deployment location to Russia"},
}


def _job(repo_id="repo-1", project="Platform"):
    return ReviewJob.from_dict(
        {
            "event_id": "event-exc",
            "event_type": "git.pullrequest.created",
            "organization_url": "https://dev.azure.com/org",
            "project": project,
            "repo_id": repo_id,
            "repo_name": "payments",
            "pr_id": 7,
            "source_branch": "refs/heads/feature",
            "target_branch": "refs/heads/main",
        }
    )


def _finding(matched="ru-central"):
    return Finding(
        tool="policy-config_iac",
        rule_id="sanctions.russia-location",
        file="/deploy.yaml",
        line=2,
        severity="ERROR",
        message="Deployment location is set to a prohibited Russian region.",
        control_id="sanctions.russia-location",
        control_version="1.0",
        matched_value=matched,
    )


def _exception(**overrides):
    value = {
        "exception_id": "exc-1",
        "control_id": "sanctions.russia-location",
        "control_version": "1.0",
        "repository_id": "repo-1",
        "project": "Platform",
        "approved_value": "ru-central",
        "status": "approved",
    }
    value.update(overrides)
    return value


def test_matching_approved_exception_suppresses_and_stamps_the_finding():
    visible, suppressed, applied = _apply_exceptions([_finding()], [_exception()], _job())

    assert visible == []
    assert suppressed[0].exception_id == "exc-1"
    assert [item["exception_id"] for item in applied] == ["exc-1"]


@pytest.mark.parametrize(
    "override",
    [
        {"status": "revoked"},
        {"status": "expired"},
        {"control_id": "crypto.prohibited-dependencies"},
        {"control_version": "2.0"},
        {"repository_id": "repo-other"},
        {"project": "OtherProject"},
        {"approved_value": "ru-north"},
    ],
)
def test_exception_outside_its_scope_does_not_suppress(override):
    visible, suppressed, applied = _apply_exceptions([_finding()], [_exception(**override)], _job())

    assert len(visible) == 1 and suppressed == [] and applied == []


@pytest.mark.parametrize("field", ["control_version", "repository_id", "project", "approved_value"])
def test_wildcard_scope_suppresses(field):
    visible, suppressed, _ = _apply_exceptions([_finding()], [_exception(**{field: "*"})], _job())

    assert visible == [] and len(suppressed) == 1


def test_approved_value_match_is_case_insensitive():
    visible, suppressed, _ = _apply_exceptions([_finding("RU-Central")], [_exception()], _job())

    assert visible == [] and len(suppressed) == 1


def test_exception_requires_justification_and_a_future_expiry():
    plane = ControlPlane(connection_string="")
    base = {
        "control_id": "sanctions.russia-location",
        "business_justification": "Approved migration window",
        "expiration_date": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
    }

    with pytest.raises(ValueError):
        plane.save_exception({**base, "business_justification": ""})
    with pytest.raises(ValueError):
        plane.save_exception({**base, "expiration_date": ""})
    with pytest.raises(ValueError):
        plane.save_exception({**base, "expiration_date": "not-a-date"})
    with pytest.raises(ValueError):
        plane.save_exception({**base, "expiration_date": (datetime.now(UTC) - timedelta(days=1)).isoformat()})

    saved = plane.save_exception(base, actor="approver@example.com")
    assert saved["status"] == "approved"
    assert saved["approver"] == "approver@example.com"
    assert saved["approved_at"]


def test_expired_exception_is_reported_as_expired_and_excluded_from_active_use():
    plane = ControlPlane(connection_string="")
    saved = plane.save_exception(
        {
            "control_id": "sanctions.russia-location",
            "approved_value": "ru-central",
            "business_justification": "Approved migration window",
            "expiration_date": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
            "reference_ticket": "SEC-1234",
        },
        actor="approver@example.com",
    )
    assert [item["status"] for item in plane.list_exceptions(include_expired=False)] == ["approved"]

    expired = {**saved, "expiration_date": (datetime.now(UTC) - timedelta(days=1)).isoformat()}
    plane._put(EXCEPTIONS_TABLE, expired["control_id"], expired["exception_id"], expired)

    assert plane.list_exceptions(include_expired=False) == []
    audited = plane.list_exceptions()
    assert len(audited) == 1
    assert audited[0]["status"] == "expired"
    assert audited[0]["reference_ticket"] == "SEC-1234"


def test_revoked_exception_stops_suppressing_immediately():
    plane = ControlPlane(connection_string="")
    saved = plane.save_exception(
        {
            "control_id": "sanctions.russia-location",
            "business_justification": "Approved migration window",
            "expiration_date": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
        },
        actor="approver@example.com",
    )

    revoked = plane.revoke_exception(saved["exception_id"], actor="approver@example.com")

    assert revoked["status"] == "revoked"
    assert plane.list_exceptions(include_expired=False) == []
    assert any(event["action"] == "exception.revoked" for event in plane.list_audit_events())


class _Ado:
    def fetch_diff(self, job):
        return PrDiff(
            pr_id=job.pr_id,
            repo_name=job.repo_name,
            source_branch=job.source_branch,
            target_branch=job.target_branch,
            iteration_id=1,
            changed_files=[ChangedFile("/deploy.yaml", "edit", "service: payments\nregion: ru-central\n")],
            raw_diff="",
        )


def _activate_control(plane):
    control = plane.save_control(
        {
            **CONTROL,
            "title": "Prohibited deployment location",
            "policy_document_id": "sanctions-and-geographic-restrictions",
            "detector": CONTROL["detector"],
            "validation": {"passed": True, "tests": []},
        },
        actor="author@example.com",
    )
    plane.approve_control(control["control_id"], control["version"], actor="approver@example.com")
    plane.transition_control(control["control_id"], control["version"], "active", actor="activator@example.com")
    return control


def test_review_suppresses_under_an_active_exception_and_reports_it_again_once_expired():
    plane = ControlPlane(connection_string="")
    control = _activate_control(plane)

    def typed_scanner(files):
        active, _ = plane.active_controls()
        return run_typed_control_scan(files, active)

    def review(run_id):
        return process_review(
            _job(),
            ado=_Ado(),
            scanner=typed_scanner,
            reporter=type("R", (), {"publish": lambda self, value: None})(),
            control_plane=plane,
            run_id=run_id,
        )

    assert len(review("run-before").findings) == 1

    saved = plane.save_exception(
        {
            "control_id": control["control_id"],
            "control_version": control["version"],
            "repository_id": "repo-1",
            "project": "Platform",
            "approved_value": "ru-central",
            "business_justification": "Documented migration window",
            "expiration_date": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
            "reference_ticket": "SEC-1234",
        },
        actor="approver@example.com",
    )

    during = review("run-during")
    assert during.findings == []
    assert len(during.suppressed_findings) == 1
    assert during.suppressed_findings[0].exception_id == saved["exception_id"]
    assert [item["exception_id"] for item in during.applicable_exceptions] == [saved["exception_id"]]

    expired = {**saved, "expiration_date": (datetime.now(UTC) - timedelta(days=1)).isoformat()}
    plane._put(EXCEPTIONS_TABLE, expired["control_id"], expired["exception_id"], expired)

    after = review("run-after")
    assert len(after.findings) == 1
    assert after.suppressed_findings == []
    assert after.findings[0].control_id == control["control_id"]
