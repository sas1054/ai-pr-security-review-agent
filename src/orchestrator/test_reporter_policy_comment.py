"""The developer-facing policy comment must be auditable and free of detector internals."""

from reporter import AdoReporter
from models import TriageItem
from scanner import Finding


def _finding(**overrides):
    values = {
        "tool": "policy-config_iac",
        "rule_id": "sanctions.russia-location",
        "file": "/deploy/config.yaml",
        "line": 12,
        "severity": "ERROR",
        "message": "Deployment location is set to a prohibited Russian region.",
        "fix_hint": "Use an approved deployment region or request a documented exception.",
        "control_id": "sanctions.russia-location",
        "control_version": "1.0",
        "reason": "The active sanctions policy prohibits Russian locations.",
        "policy_document": "Sanctions and Geographic Restrictions",
        "policy_version": "2026-01",
        "source_reference": {
            "page": 3,
            "section": "Geographic restrictions",
            "excerpt": "Software must not set any deployment location to Russia...",
        },
        "confidence": 0.97,
        "matched_value": "ru-central",
    }
    values.update(overrides)
    return Finding(**values)


def test_policy_comment_states_severity_policy_source_statement_and_action():
    body = AdoReporter._policy_body(_finding(), "<!-- marker -->", None)

    assert body.startswith("<!-- marker -->")
    assert "**ERROR — Deployment location is set to a prohibited Russian region.**" in body
    assert "Matched evidence: `ru-central`" in body
    assert "**Policy:** Sanctions and Geographic Restrictions, version 2026-01" in body
    assert "**Source:** page 3, section “Geographic restrictions”" in body
    assert "**Policy statement:** “Software must not set any deployment location to Russia...”" in body
    assert "**Reason:** The active sanctions policy prohibits Russian locations." in body
    assert "**Suggested action:** Use an approved deployment region or request a documented exception." in body
    assert "Control `sanctions.russia-location` version `1.0` · Confidence 0.97" in body


def test_policy_comment_never_leaks_detector_internals():
    body = AdoReporter._policy_body(_finding(), "", None).lower()

    for internal in ("regex", "semgrep", "pattern:", "prohibited_values", "detector"):
        assert internal not in body


def test_policy_comment_includes_paragraph_and_falls_back_when_the_clause_has_no_page():
    with_paragraph = AdoReporter._policy_body(
        _finding(source_reference={"paragraph": 4, "excerpt": "Text"}), "", None
    )
    assert "**Source:** paragraph 4" in with_paragraph

    without_location = AdoReporter._policy_body(_finding(source_reference={"excerpt": "Text"}), "", None)
    assert "**Source:** source clause recorded with the control" in without_location


def test_triage_fix_hint_is_preferred_but_never_removes_the_policy_citation():
    triage = TriageItem("fingerprint", "high", True, "Likely a false positive", "Move to an approved region")

    body = AdoReporter._policy_body(_finding(), "", triage)

    assert "**Suggested action:** Move to an approved region" in body
    assert "**Policy:** Sanctions and Geographic Restrictions, version 2026-01" in body
    assert "**Policy statement:**" in body


def test_policy_comment_escapes_untrusted_policy_and_code_text():
    body = AdoReporter._policy_body(
        _finding(
            matched_value="`; rm -rf /",
            message="<script>alert(1)</script>",
            source_reference={"section": "<b>bold</b>", "excerpt": "quote & <em>emphasis</em>"},
        ),
        "",
        None,
    )

    assert "<script>" not in body and "<b>" not in body and "<em>" not in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
    assert "&amp;" in body
    assert "\\`; rm -rf /" in body


def test_manual_review_comment_says_it_matched_nothing_instead_of_faking_evidence():
    body = AdoReporter._policy_body(_finding(matched_value="", confidence=0.0), "", None)

    assert "Matched evidence" not in body
    assert "cannot be checked automatically" in body
    assert "asks for a human decision" in body
    # The citation must still be intact so the developer knows which policy asked for the review.
    assert "**Policy:** Sanctions and Geographic Restrictions, version 2026-01" in body
    assert "**Policy statement:**" in body
