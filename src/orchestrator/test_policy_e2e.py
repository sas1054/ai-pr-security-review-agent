from ado_client import ChangedFile, PrDiff
from models import ReviewJob
from orchestrator import process_review
from policy_engine import process_policy_job
from prsa_control import ControlPlane
from scanner import run_typed_control_scan


POLICY = "Software must not set any deployment location to Russia or Russian territories."


class Interpreter:
    def interpret(self, policy, text, clauses):
        return {
            "obligations": ["Do not deploy to Russia"],
            "exceptions": [],
            "effective_dates": [policy.get("effective_date")],
            "defined_terms": {"Russian territories": "Territories covered by the sanctions policy"},
            "controls": [
                {
                    "control_id": "sanctions.russia-location",
                    "title": "Prohibited deployment location",
                    "description": "Detects prohibited Russian deployment locations.",
                    "prohibited_condition": "Deployment location must not target Russia.",
                    "control_type": "config_iac",
                    "severity": "ERROR",
                    "scope": {"file_globs": ["*.yaml"]},
                    "exclusions": ["Documentation and rejection tests"],
                    "clarification_questions": [],
                    "source_reference": {**clauses[0], "excerpt": POLICY},
                    "confidence": 0.97,
                    "match": {
                        "prohibited_values": ["Russia", "ru-central", "Russian Federation", "RU"],
                        "field_names": ["region", "location", "countryCode", "deployment_region"],
                        "file_globs": ["*.yaml"],
                    },
                    "tests": [
                        {"name": "blocks Russia", "file": "deploy.yaml", "content": "region: ru-central", "should_match": True},
                        {"name": "allows approved region", "file": "deploy.yaml", "content": "region: westeurope", "should_match": False},
                    ],
                }
            ],
        }


class Ado:
    def fetch_diff(self, job):
        return PrDiff(
            pr_id=job.pr_id,
            repo_name=job.repo_name,
            source_branch=job.source_branch,
            target_branch=job.target_branch,
            iteration_id=4,
            changed_files=[ChangedFile("/deploy.yaml", "edit", "service: payments\nregion: ru-central\n")],
            raw_diff="diff --git a/deploy.yaml b/deploy.yaml",
        )


class Reporter:
    def __init__(self):
        self.result = None

    def publish(self, result):
        self.result = result


def test_natural_language_policy_to_cited_pr_finding_end_to_end():
    plane = ControlPlane(connection_string="")
    policy = plane.save_policy_document(
        {
            "title": "Sanctions and Geographic Restrictions",
            "version": "2026-01",
            "effective_date": "2026-01-01",
            "owner": "Security Engineering",
            "filename": "sanctions.txt",
            "input_type": "paste",
        },
        POLICY,
        actor="author@example.com",
    )
    job = plane.record_policy_job(policy["document_id"], policy["version"], actor="author@example.com")
    [proposed] = process_policy_job(job, plane, interpreter=Interpreter())
    assert proposed["state"] == "draft" and proposed["validation"]["passed"]
    plane.approve_control(proposed["control_id"], proposed["version"], actor="approver@example.com")
    plane.transition_control(proposed["control_id"], proposed["version"], "active", actor="activator@example.com")

    review_job = ReviewJob.from_dict(
        {
            "event_id": "event-e2e",
            "event_type": "git.pullrequest.created",
            "organization_url": "https://dev.azure.com/org",
            "project": "Platform",
            "repo_id": "repo-1",
            "repo_name": "payments",
            "pr_id": 99,
            "source_branch": "refs/heads/feature",
            "target_branch": "refs/heads/main",
        }
    )
    reporter = Reporter()

    def typed_scanner(files):
        active, _ = plane.active_controls()
        return run_typed_control_scan(files, active)

    result = process_review(
        review_job,
        ado=Ado(),
        scanner=typed_scanner,
        reporter=reporter,
        control_plane=plane,
        run_id="run-e2e",
    )
    assert reporter.result is result
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.control_id == "sanctions.russia-location"
    assert finding.control_version == "1.0"
    assert finding.policy_document == "Sanctions and Geographic Restrictions"
    assert finding.policy_version == "2026-01"
    assert finding.source_reference["excerpt"] == POLICY
    assert finding.file == "/deploy.yaml" and finding.line == 2
    stored = plane.get_review("run-e2e")
    assert stored["control_snapshot"][0]["detector_sha256"]
    assert stored["findings"][0]["source_reference"]["excerpt"] == POLICY
