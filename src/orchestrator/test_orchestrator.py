from ado_client import ChangedFile, PrDiff
from models import ReviewJob, TriageItem, TriageResult
from orchestrator import _applicable_controls, _service_bus_client, handle_message, process_review
from prsa_control import ControlPlane
from scanner import Finding
from triage import TriageError
from datetime import UTC, datetime, timedelta


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


class FakeAdo:
    def fetch_diff(self, job):
        return PrDiff(
            7,
            "service",
            job.source_branch,
            job.target_branch,
            iteration_id=3,
            changed_files=[ChangedFile("/app.py", "edit", "password = 'secret'")],
            raw_diff="diff",
        )


class FakeReporter:
    def __init__(self):
        self.results = []

    def publish(self, result):
        self.results.append(result)


class FakeTriage:
    def triage(self, diff, findings):
        return TriageResult(
            summary="Prioritized",
            items=[TriageItem(findings[0].fingerprint, "high", False, "Fix it")],
        )


def test_process_review_runs_all_adapters_and_reports():
    finding = Finding("secret-scan", "hardcoded-password", "/app.py", 1, "ERROR", "secret")
    reporter = FakeReporter()
    result = process_review(
        _job(),
        ado=FakeAdo(),
        scanner=lambda files: [finding],
        triage_client=FakeTriage(),
        reporter=reporter,
        run_id="run-1",
    )
    assert result.status == "completed"
    assert result.iteration_id == 3
    assert result.summary == "Prioritized"
    assert reporter.results == [result]


class FailingTriage:
    def triage(self, diff, findings):
        raise TriageError("timeout")


def test_triage_failure_preserves_deterministic_findings():
    finding = Finding("secret-scan", "hardcoded-password", "/app.py", 1, "ERROR", "secret")
    result = process_review(
        _job(),
        ado=FakeAdo(),
        scanner=lambda files: [finding],
        triage_client=FailingTriage(),
        run_id="run-2",
    )
    assert result.status == "completed_with_triage_error"
    assert result.findings == [finding]
    assert result.errors == ["timeout"]


class FakeMessage:
    def __init__(self, body):
        self.body = body

    def __str__(self):
        return self.body


class FakeReceiver:
    def __init__(self):
        self.completed = []
        self.abandoned = []

    def complete_message(self, message):
        self.completed.append(message)

    def abandon_message(self, message):
        self.abandoned.append(message)


def test_message_is_completed_after_processing():
    receiver = FakeReceiver()
    message = FakeMessage('{"event_id": "event-1"}')
    assert handle_message(message, receiver, process_fn=lambda job: None) is True
    assert receiver.completed == [message]
    assert receiver.abandoned == []


def test_message_is_abandoned_when_processing_fails():
    receiver = FakeReceiver()
    message = FakeMessage('{"event_id": "event-2"}')
    assert handle_message(message, receiver, process_fn=lambda job: (_ for _ in ()).throw(RuntimeError("boom"))) is False
    assert receiver.completed == []
    assert receiver.abandoned == [message]


def test_message_failure_is_visible_in_the_control_plane(monkeypatch):
    controls = ControlPlane(connection_string="")
    job = {
        "run_id": "run-visible-failure",
        "event_id": "event-visible-failure",
        "repo_id": "repo-visible",
        "repo_name": "service",
        "project": "Project",
        "pr_id": 9,
        "event_type": "git.pullrequest.created",
    }
    controls.record_review_queued(job, job["run_id"])
    monkeypatch.setattr("orchestrator.get_control_plane", lambda: controls)
    receiver = FakeReceiver()
    message = FakeMessage(__import__("json").dumps(job))
    assert handle_message(message, receiver, process_fn=lambda _: (_ for _ in ()).throw(RuntimeError("boom"))) is False
    assert controls.get_review(job["run_id"])["status"] == "failed"


def test_hackathon_mode_uses_service_bus_connection_string(monkeypatch):
    captured = {}

    class FakeServiceBusClient:
        @classmethod
        def from_connection_string(cls, value):
            captured["connection_string"] = value
            return "client"

    monkeypatch.setattr("orchestrator.ServiceBusClient", FakeServiceBusClient)
    monkeypatch.setenv("SERVICE_BUS_CONNECTION_STRING", "Endpoint=sb://hackathon/")
    assert _service_bus_client() == "client"
    assert captured["connection_string"] == "Endpoint=sb://hackathon/"


def test_approved_exception_suppresses_comment_but_preserves_evidence():
    controls = ControlPlane(connection_string="")
    controls.save_exception(
        {
            "control_id": "crypto-wallet",
            "repository_id": "repo",
            "approved_value": "approved-wallet-sdk",
            "business_justification": "Approved migration",
            "expiration_date": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        },
        actor="security",
    )
    finding = Finding(
        "policy-dependency", "crypto-wallet", "/package.json", 1, "ERROR", "Prohibited dependency",
        control_id="crypto-wallet", control_version="1.0", matched_value="approved-wallet-sdk"
    )
    result = process_review(
        _job(), ado=FakeAdo(), scanner=lambda files: [finding], control_plane=controls, run_id="excepted"
    )
    assert result.findings == []
    assert result.suppressed_findings[0].exception_id
    stored = controls.get_review("excepted")
    assert stored["suppressed_findings"][0]["control_id"] == "crypto-wallet"


def test_manual_review_control_always_creates_human_review_finding():
    controls = ControlPlane(connection_string="")
    policy = controls.save_policy_document({"title": "Ambiguous policy", "filename": "policy.txt"}, "Security must review special integrations.")
    proposed = controls.save_control(
        {
            "control_id": "special-integration-review",
            "version": "1.0",
            "title": "Special integration review",
            "description": "Requires security review.",
            "prohibited_condition": "Special integrations require approval.",
            "control_type": "manual_review",
            "policy_document_id": policy["document_id"],
            "policy_version": policy["version"],
            "policy_title": policy["title"],
            "source_reference": {"paragraph": 1, "excerpt": "Security must review special integrations."},
            "validation": {"passed": True, "tests": [{"passed": True}]},
        }
    )
    controls.approve_control(proposed["control_id"], "1.0", actor="approver")
    controls.transition_control(proposed["control_id"], "1.0", "active", actor="activator")

    class EmptySemanticScanner:
        def scan(self, files, active_controls):
            return []

    result = process_review(
        _job(), ado=FakeAdo(), scanner=lambda files: [], control_plane=controls,
        semantic_scanner=EmptySemanticScanner(), run_id="manual-review"
    )
    assert result.findings[0].review_required is True
    assert result.findings[0].confidence == 0.0


def test_active_control_scope_filters_repository_project_and_branch():
    controls = [
        {"control_id": "all", "scope": {}},
        {"control_id": "repo", "scope": {"repository_ids": ["repo"]}},
        {"control_id": "other-repo", "scope": {"repository_ids": ["other"]}},
        {"control_id": "branch", "scope": {"projects": ["Project"], "target_branches": ["main"]}},
    ]
    assert [item["control_id"] for item in _applicable_controls(controls, _job())] == ["all", "repo", "branch"]
