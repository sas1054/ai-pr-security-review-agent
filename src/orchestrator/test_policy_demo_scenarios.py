"""End-to-end demo scenarios for the two example policies in the requirement.

These prove that one natural-language paragraph produces the *kind* of control the
obligation actually needs: a sanctions location rule compiles to configuration and
literal-value analysis, while the cryptocurrency rule compiles to dependency, domain,
and human-review analysis. No regex or Semgrep syntax is authored by the user.
"""

import pytest

from ado_client import ChangedFile, PrDiff
from models import ReviewJob
from policy_engine import process_policy_job
from prsa_control import ControlPlane
from scanner import run_typed_control_scan


SANCTIONS_POLICY = (
    "Due to current sanctions, software must not set any location, region, country, "
    "deployment target, tenant, countrycode, deployment_region, or address to Russia, "
    "ru-central, Russian Federation, RU, or Russian territories."
)

CRYPTO_POLICY = (
    "The software must not integrate cryptocurrency payment services, crypto wallets, "
    "mining libraries, exchanges, or blockchain transaction services unless explicitly "
    "approved by Security Engineering. Governed examples are web3, bitcoinjs-lib, the "
    "coinbase- package family, api.binance.com, and api.coinbase.com."
)

SANCTIONS_EXCERPT = SANCTIONS_POLICY
CRYPTO_EXCERPT = CRYPTO_POLICY


def _sanctions_controls(clause):
    return [
        {
            "control_id": "sanctions.russia-location",
            "title": "Prohibited deployment location",
            "description": "Detects prohibited Russian deployment locations.",
            "prohibited_condition": "Deployment configuration must not target Russia or a Russian territory.",
            "control_type": "config_iac",
            "severity": "ERROR",
            "scope": {"file_globs": ["*.yaml", "*.yml", "*.json"]},
            "exclusions": ["Documentation describing the sanction", "Tests that assert rejection"],
            "clarification_questions": [],
            "source_reference": {**clause, "excerpt": SANCTIONS_EXCERPT},
            "confidence": 0.97,
            "fix_hint": "Use an approved deployment region or request a documented exception.",
            "match": {
                "field_names": ["region", "location", "countrycode", "deployment_region", "tenant"],
                "prohibited_values": ["russia", "ru-central", "russian federation", "ru"],
                "file_globs": ["*.yaml", "*.yml", "*.json"],
            },
            "tests": [
                {"name": "blocks a Russian region", "file": "deploy.yaml", "content": "region: ru-central", "should_match": True},
                {"name": "allows an approved region", "file": "deploy.yaml", "content": "region: westeurope", "should_match": False},
            ],
        },
        {
            "control_id": "sanctions.russia-literal",
            "title": "Prohibited sanctioned location value",
            "description": "Detects sanctioned location values in infrastructure code.",
            "prohibited_condition": "Infrastructure code must not assign a sanctioned location value.",
            "control_type": "literal_value",
            "severity": "ERROR",
            "scope": {"file_globs": ["*.tf", "*.bicep"]},
            "exclusions": ["Documentation describing the sanction"],
            "clarification_questions": [],
            "source_reference": {**clause, "excerpt": SANCTIONS_EXCERPT},
            "confidence": 0.93,
            "fix_hint": "Use an approved deployment region or request a documented exception.",
            "match": {
                "prohibited_values": ["ru-central", "Russian Federation"],
                "file_globs": ["*.tf", "*.bicep"],
            },
            "tests": [
                {"name": "blocks a sanctioned literal", "file": "main.tf", "content": 'deployment_region = "Russian Federation"', "should_match": True},
                {"name": "allows an approved literal", "file": "main.tf", "content": 'deployment_region = "westeurope"', "should_match": False},
            ],
        },
    ]


def _crypto_controls(clause):
    return [
        {
            "control_id": "crypto.prohibited-dependencies",
            "title": "Unapproved cryptocurrency dependency",
            "description": "Detects unapproved cryptocurrency and blockchain dependencies.",
            "prohibited_condition": "A dependency must not introduce crypto wallet, mining, or blockchain transaction functionality without approval.",
            "control_type": "dependency",
            "severity": "ERROR",
            "scope": {"file_globs": ["*requirements*.txt", "*package.json"]},
            "exclusions": ["Test-only integrations pending review"],
            "clarification_questions": [],
            "source_reference": {**clause, "excerpt": CRYPTO_EXCERPT},
            "confidence": 0.9,
            "fix_hint": "Remove the dependency or record an approval from Security Engineering.",
            "match": {
                "packages": ["web3", "bitcoinjs-lib"],
                "package_prefixes": ["coinbase-"],
                "file_globs": ["*requirements*.txt", "*package.json"],
            },
            "tests": [
                {"name": "blocks a blockchain library", "file": "requirements.txt", "content": "web3==6.0.0\n", "should_match": True},
                {"name": "allows an ordinary library", "file": "requirements.txt", "content": "requests==2.32.0\n", "should_match": False},
            ],
        },
        {
            "control_id": "crypto.exchange-endpoints",
            "title": "Cryptocurrency exchange endpoint",
            "description": "Detects calls to known cryptocurrency exchange and payment endpoints.",
            "prohibited_condition": "Code must not call a cryptocurrency exchange or crypto payment endpoint without approval.",
            "control_type": "url_domain",
            "severity": "ERROR",
            "scope": {},
            "exclusions": ["Documentation and comments"],
            "clarification_questions": [],
            "source_reference": {**clause, "excerpt": CRYPTO_EXCERPT},
            "confidence": 0.88,
            "fix_hint": "Use an approved payment provider or record an approved exception.",
            "match": {"domains": ["api.binance.com", "api.coinbase.com"]},
            "tests": [
                {"name": "blocks an exchange endpoint", "file": "payments.py", "content": 'URL = "https://api.binance.com/api/v3/order"', "should_match": True},
                {"name": "allows an approved provider", "file": "payments.py", "content": 'URL = "https://api.stripe.com/v1/charges"', "should_match": False},
            ],
        },
        {
            "control_id": "crypto.terminology-review",
            "title": "Cryptocurrency terminology requires review",
            "description": "Raises a human review when generic cryptocurrency terminology appears.",
            "prohibited_condition": "Generic blockchain terminology may indicate an unapproved integration.",
            "control_type": "manual_review",
            "severity": "WARNING",
            "scope": {},
            "exclusions": ["Security research code"],
            "clarification_questions": [
                "Does the prohibition include documentation and comments?",
                "Does it include test-only integrations and internal security tooling?",
                "Does it include transitive dependencies?",
            ],
            "source_reference": {**clause, "excerpt": CRYPTO_EXCERPT},
            "confidence": 0.4,
            "fix_hint": "Confirm with Security Engineering whether an approval is required.",
            "match": {},
            "tests": [
                {"name": "flags ambiguous terminology", "file": "wallet.py", "content": "# blockchain settlement helper", "should_match": True},
                {"name": "ignores unrelated code", "file": "wallet.py", "content": "# invoice helper", "should_match": False},
            ],
        },
    ]


class DemoInterpreter:
    """Stands in for Azure OpenAI so the scenario stays deterministic and offline."""

    def interpret(self, policy, text, clauses):
        clause = clauses[0]
        if "Sanctions" in policy["title"]:
            controls = _sanctions_controls(clause)
            obligations = [{
                "obligation_id": "restricted-location",
                "statement": "Do not set any deployment location to a restricted value",
                "detection_surfaces": ["configuration_iac", "source_literals"],
                "source_reference": {**clause, "excerpt": SANCTIONS_EXCERPT},
            }]
        else:
            controls = _crypto_controls(clause)
            obligations = [{
                "obligation_id": "restricted-integration",
                "statement": "Do not integrate governed services without approval",
                "detection_surfaces": ["dependencies", "service_endpoints", "manual_evidence"],
                "source_reference": {**clause, "excerpt": CRYPTO_EXCERPT},
            }]
        for control in controls:
            control["obligation_ids"] = [obligations[0]["obligation_id"]]
        return {
            "obligations": obligations,
            "exceptions": ["Explicit approval by Security Engineering"],
            "effective_dates": [policy.get("effective_date")],
            "defined_terms": {},
            "controls": controls,
        }


class DemoAdo:
    def fetch_diff(self, job):
        return PrDiff(
            pr_id=job.pr_id,
            repo_name=job.repo_name,
            source_branch=job.source_branch,
            target_branch=job.target_branch,
            iteration_id=1,
            changed_files=[
                ChangedFile("/deploy.yaml", "edit", "service: payments\nregion: ru-central\n"),
                ChangedFile("/infra/main.tf", "edit", 'deployment_region = "Russian Federation"\n'),
                ChangedFile("/requirements.txt", "edit", "requests==2.32.0\nweb3==6.0.0\n"),
                ChangedFile("/src/payments.py", "edit", 'PAYOUT = "https://api.binance.com/api/v3/order"\n'),
                ChangedFile("/docs/sanctions.md", "edit", "We must never deploy to ru-central (Russian Federation).\n"),
            ],
            raw_diff="diff --git a/deploy.yaml b/deploy.yaml",
        )


def _ingest(plane, title, version, text):
    policy = plane.save_policy_document(
        {
            "title": title,
            "version": version,
            "effective_date": "2026-01-01",
            "owner": "Security Engineering",
            "filename": f"{title.lower().replace(' ', '-')}.txt",
            "input_type": "paste",
        },
        text,
        actor="author@example.com",
    )
    job = plane.record_policy_job(policy["document_id"], policy["version"], actor="author@example.com")
    return policy, process_policy_job(job, plane, interpreter=DemoInterpreter())


def _review_job():
    return ReviewJob.from_dict(
        {
            "event_id": "event-demo",
            "event_type": "git.pullrequest.created",
            "organization_url": "https://dev.azure.com/org",
            "project": "Platform",
            "repo_id": "repo-1",
            "repo_name": "payments",
            "pr_id": 42,
            "source_branch": "refs/heads/feature",
            "target_branch": "refs/heads/main",
        }
    )


def test_two_policies_compile_to_different_control_types():
    plane = ControlPlane(connection_string="")
    _, sanctions = _ingest(plane, "Sanctions and Geographic Restrictions", "2026-01", SANCTIONS_POLICY)
    _, crypto = _ingest(plane, "Cryptocurrency Integration Restrictions", "2026-02", CRYPTO_POLICY)

    sanctions_types = {control["control_type"] for control in sanctions}
    crypto_types = {control["control_type"] for control in crypto}
    assert sanctions_types == {"config_iac", "literal_value"}
    assert crypto_types == {"dependency", "url_domain", "manual_review"}
    assert sanctions_types.isdisjoint(crypto_types)

    for control in [*sanctions, *crypto]:
        assert control["validation"]["passed"], control["control_id"]
        assert control["examples"]["positive"] and control["examples"]["negative"]
        assert control["exclusions"]
        assert control["severity"] in {"ERROR", "WARNING", "INFO"}
        assert control["source_reference"]["excerpt"]


def test_ambiguous_cryptocurrency_control_cannot_be_approved_until_clarified():
    plane = ControlPlane(connection_string="")
    _, crypto = _ingest(plane, "Cryptocurrency Integration Restrictions", "2026-02", CRYPTO_POLICY)
    ambiguous = next(item for item in crypto if item["control_id"] == "crypto.terminology-review")

    assert ambiguous["state"] == "needs_clarification"
    assert len(ambiguous["clarification_questions"]) == 3
    with pytest.raises(ValueError):
        plane.approve_control(ambiguous["control_id"], ambiguous["version"], actor="approver@example.com")
    with pytest.raises(ValueError):
        plane.transition_control(ambiguous["control_id"], ambiguous["version"], "active", actor="activator@example.com")
    assert plane.get_control(ambiguous["control_id"], ambiguous["version"])["state"] == "needs_clarification"


def test_activated_controls_from_both_policies_cite_their_own_policy_on_one_pr():
    from orchestrator import process_review

    plane = ControlPlane(connection_string="")
    _, sanctions = _ingest(plane, "Sanctions and Geographic Restrictions", "2026-01", SANCTIONS_POLICY)
    _, crypto = _ingest(plane, "Cryptocurrency Integration Restrictions", "2026-02", CRYPTO_POLICY)
    for control in [*sanctions, *crypto]:
        if control["state"] != "draft":
            continue
        plane.approve_control(control["control_id"], control["version"], actor="approver@example.com")
        plane.transition_control(control["control_id"], control["version"], "active", actor="activator@example.com")

    def typed_scanner(files):
        active, _ = plane.active_controls()
        return run_typed_control_scan(files, active)

    result = process_review(
        _review_job(),
        ado=DemoAdo(),
        scanner=typed_scanner,
        reporter=type("R", (), {"publish": lambda self, value: None})(),
        control_plane=plane,
        run_id="run-demo",
    )

    by_control = {finding.control_id: finding for finding in result.findings}
    assert set(by_control) == {
        "sanctions.russia-location",
        "sanctions.russia-literal",
        "crypto.prohibited-dependencies",
        "crypto.exchange-endpoints",
    }
    assert by_control["sanctions.russia-location"].file == "/deploy.yaml"
    assert by_control["sanctions.russia-location"].line == 2
    assert by_control["sanctions.russia-location"].policy_document == "Sanctions and Geographic Restrictions"
    assert by_control["sanctions.russia-location"].policy_version == "2026-01"
    assert by_control["crypto.prohibited-dependencies"].file == "/requirements.txt"
    assert by_control["crypto.prohibited-dependencies"].line == 2
    assert by_control["crypto.prohibited-dependencies"].policy_version == "2026-02"
    assert by_control["crypto.exchange-endpoints"].matched_value == "api.binance.com"
    for finding in result.findings:
        assert finding.source_reference["excerpt"] in (SANCTIONS_EXCERPT, CRYPTO_EXCERPT)

    # Documentation that merely describes the sanction must not be flagged.
    assert not any(finding.file == "/docs/sanctions.md" for finding in result.findings)

    stored = plane.get_review("run-demo")
    assert {item["policy_version"] for item in stored["control_snapshot"]} == {"2026-01", "2026-02"}
