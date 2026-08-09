"""Every review must declare what it could not check."""

from ado_client import ChangedFile, PrDiff
from models import ReviewJob
from orchestrator import process_review
from prsa_control import ControlPlane
from scanner import run_typed_control_scan


class _Reporter:
    def publish(self, result):
        self.result = result


def _plane():
    plane = ControlPlane(connection_string="")
    plane.save_policy_document(
        {"title": "Sanctions and Geographic Restrictions", "version": "2026-01", "filename": "sanctions.txt"},
        "Software must not set any deployment location to Russia or Russian territories.",
        actor="author@example.com",
    )
    return plane


def _activate(plane, control_id, control_type, detector=None, version="1.0"):
    control = plane.save_control(
        {
            "control_id": control_id,
            "version": version,
            "state": "draft",
            "title": control_id,
            "prohibited_condition": "Prohibited condition",
            "control_type": control_type,
            "severity": "ERROR",
            "policy_document_id": "sanctions-and-geographic-restrictions",
            "policy_version": "2026-01",
            "policy_title": "Sanctions and Geographic Restrictions",
            "source_reference": {"excerpt": "must not set any deployment location to Russia"},
            "detector": detector or {},
            "validation": {"passed": True, "tests": []},
        },
        actor="author@example.com",
    )
    plane.approve_control(control_id, version, actor="approver@example.com")
    plane.transition_control(control_id, version, "active", actor="activator@example.com")
    return control


def _job():
    return ReviewJob.from_dict(
        {
            "event_id": "event-gap",
            "event_type": "git.pullrequest.created",
            "organization_url": "https://dev.azure.com/org",
            "project": "Platform",
            "repo_id": "repo-1",
            "repo_name": "payments",
            "pr_id": 11,
            "source_branch": "refs/heads/feature",
            "target_branch": "refs/heads/main",
        }
    )


class _Ado:
    def __init__(self, changed_files):
        self.changed_files = changed_files

    def fetch_diff(self, job):
        return PrDiff(
            pr_id=job.pr_id,
            repo_name=job.repo_name,
            source_branch=job.source_branch,
            target_branch=job.target_branch,
            iteration_id=1,
            changed_files=self.changed_files,
            raw_diff="",
        )


def _review(plane, changed_files, *, semantic_scanner=None, ado=None, run_id="run-gap"):
    def typed_scanner(files):
        active, _ = plane.active_controls()
        return run_typed_control_scan(files, active)

    reporter = _Reporter()
    return process_review(
        _job(),
        ado=ado or _Ado(changed_files),
        scanner=typed_scanner,
        reporter=reporter,
        control_plane=plane,
        run_id=run_id,
        semantic_scanner=semantic_scanner,
    )


def test_disabled_scanner_flag_skips_the_control_and_is_declared_as_a_gap():
    plane = _plane()
    _activate(plane, "sanctions.russia-location", "config_iac", {"field_names": ["region"], "prohibited_values": ["ru-central"]})
    plane.update_settings({"scanner_config_iac_enabled": False}, actor="admin@example.com")

    result = _review(plane, [ChangedFile("/deploy.yaml", "edit", "region: ru-central\n")])

    # The control is dropped before scanning, so it is neither executed nor recorded as applied.
    assert result.policy_versions == []
    assert result.control_snapshot == []
    assert any("skipped by scanner feature flags" in gap and "sanctions.russia-location@1.0" in gap for gap in result.coverage_gaps)


def test_unsupported_dependency_manifest_is_declared_as_a_gap():
    plane = _plane()
    _activate(plane, "crypto.prohibited-dependencies", "dependency", {"packages": ["web3"]})

    result = _review(plane, [ChangedFile("/Cargo.toml", "edit", '[dependencies]\nweb3 = "0.19"\n')])

    assert result.findings == []
    assert any("Unsupported dependency manifests changed" in gap and "Cargo.toml" in gap for gap in result.coverage_gaps)


def test_supported_dependency_manifest_produces_no_gap():
    plane = _plane()
    _activate(plane, "crypto.prohibited-dependencies", "dependency", {"packages": ["web3"], "file_globs": ["*requirements*.txt"]})

    result = _review(plane, [ChangedFile("/requirements.txt", "edit", "web3==6.0.0\n")])

    assert len(result.findings) == 1
    assert not any("Unsupported dependency manifests" in gap for gap in result.coverage_gaps)


def test_semantic_control_without_a_configured_scanner_is_declared_as_a_gap():
    plane = _plane()
    _activate(plane, "crypto.terminology-review", "semantic_review")

    result = _review(plane, [ChangedFile("/wallet.py", "edit", "settle_on_chain()\n")])

    assert "Semantic policy controls were active but no semantic scanner was configured" in result.coverage_gaps


def test_semantic_scanner_failure_is_declared_as_a_gap_and_never_fails_the_review():
    plane = _plane()
    _activate(plane, "crypto.terminology-review", "semantic_review")

    class _Broken:
        def scan(self, files, controls):
            raise RuntimeError("model unavailable")

    result = _review(plane, [ChangedFile("/wallet.py", "edit", "settle_on_chain()\n")], semantic_scanner=_Broken())

    assert result.status.startswith("completed")
    assert any("Semantic policy review failed: model unavailable" in gap for gap in result.coverage_gaps)


def test_manual_review_control_always_raises_a_human_review_finding():
    plane = _plane()
    _activate(plane, "crypto.terminology-review", "manual_review")

    class _Silent:
        def scan(self, files, controls):
            return []

    result = _review(plane, [ChangedFile("/wallet.py", "edit", "settle_on_chain()\n")], semantic_scanner=_Silent())

    [finding] = result.findings
    assert finding.control_id == "crypto.terminology-review"
    assert finding.review_required is True


def test_manual_review_finding_is_not_pinned_to_an_arbitrary_changed_file():
    """It matched nothing, so it must not look like an accusation about one file."""
    plane = _plane()
    _activate(plane, "crypto.terminology-review", "manual_review")

    class _Silent:
        def scan(self, files, controls):
            return []

    result = _review(
        plane,
        [
            ChangedFile("/Dockerfile", "edit", "FROM ubuntu:latest\n"),
            ChangedFile("/wallet.py", "edit", "settle_on_chain()\n"),
        ],
        semantic_scanner=_Silent(),
    )

    [finding] = result.findings
    assert finding.file == ""
    assert finding.line == 0
    assert finding.matched_value == ""
    assert finding.inline_comment is False


def test_supplemental_file_fetch_failure_is_declared_as_a_gap():
    plane = _plane()
    _activate(plane, "crypto.prohibited-dependencies", "dependency", {"packages": ["web3"]})

    class _FailingAdo(_Ado):
        def fetch_relevant_policy_files(self, branch, known_paths, control_types):
            raise RuntimeError("branch not found")

    ado = _FailingAdo([ChangedFile("/app.py", "edit", "print('hello')\n")])
    result = _review(plane, [], ado=ado)

    assert any("Could not fetch relevant policy files: branch not found" in gap for gap in result.coverage_gaps)


def test_supplemental_gaps_reported_by_the_client_are_preserved():
    plane = _plane()
    _activate(plane, "crypto.prohibited-dependencies", "dependency", {"packages": ["web3"], "file_globs": ["*requirements*.txt"]})

    class _PartialAdo(_Ado):
        def fetch_relevant_policy_files(self, branch, known_paths, control_types):
            return {"/requirements.txt": "web3==6.0.0\n"}, ["Lock file was too large to fetch"]

    ado = _PartialAdo([ChangedFile("/app.py", "edit", "print('hello')\n")])
    result = _review(plane, [], ado=ado)

    assert "Lock file was too large to fetch" in result.coverage_gaps
    assert [finding.file for finding in result.findings] == ["/requirements.txt"]


def test_coverage_gaps_are_persisted_with_the_immutable_review_record():
    plane = _plane()
    _activate(plane, "crypto.terminology-review", "semantic_review")

    _review(plane, [ChangedFile("/wallet.py", "edit", "settle_on_chain()\n")], run_id="run-persisted")

    stored = plane.get_review("run-persisted")
    assert "Semantic policy controls were active but no semantic scanner was configured" in stored["coverage_gaps"]
