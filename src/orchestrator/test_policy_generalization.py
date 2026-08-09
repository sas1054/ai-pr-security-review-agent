"""Domain-neutral acceptance tests for obligation planning and fail-closed coverage."""

from policy_engine import process_policy_job
from prsa_control import ControlPlane


def _ingest(text, proposal, *, title="Business Security Policy"):
    plane = ControlPlane(connection_string="")
    policy = plane.save_policy_document(
        {"title": title, "version": "1.0", "filename": "policy.txt"}, text
    )
    job = plane.record_policy_job(policy["document_id"], policy["version"])

    class Interpreter:
        def interpret(self, policy, extracted, clauses):
            value = proposal(clauses[0])
            return {"exceptions": [], "defined_terms": {}, **value}

    controls = process_policy_job(job, plane, interpreter=Interpreter())
    return plane, policy, controls


def test_arbitrary_data_egress_policy_compiles_to_domain_control():
    text = "Customer records must not be sent to blocked.example.net from application code."

    def proposal(clause):
        source = {**clause, "excerpt": text}
        return {
            "obligations": [{
                "obligation_id": "customer-data-egress",
                "statement": "Do not send customer records to the blocked service.",
                "detection_surfaces": ["service_endpoints"],
                "source_reference": source,
            }],
            "controls": [{
                "obligation_ids": ["customer-data-egress"],
                "control_id": "data-egress.blocked-service",
                "title": "Blocked customer-data endpoint",
                "description": "Detects use of the prohibited endpoint.",
                "prohibited_condition": "Customer records must not be sent to blocked.example.net.",
                "control_type": "url_domain",
                "severity": "ERROR",
                "scope": {},
                "exclusions": ["Documentation", "Tests that verify rejection"],
                "clarification_questions": [],
                "source_reference": source,
                "confidence": 0.97,
                "match": {"domains": ["blocked.example.net"]},
                "tests": [
                    {"file": "client.py", "content": 'URL = "https://blocked.example.net/upload"', "should_match": True},
                    {"file": "client.py", "content": 'URL = "https://approved.example.net/upload"', "should_match": False},
                ],
            }],
        }

    plane, policy, [control] = _ingest(text, proposal)

    assert control["control_type"] == "url_domain"
    assert control["state"] == "draft"
    assert control["validation"]["passed"] is True
    assert plane.get_policy(policy["document_id"], policy["version"])["coverage_complete"] is True


def test_arbitrary_runtime_policy_compiles_to_structured_configuration_control():
    text = "Production configuration must not set the debug field to true."

    def proposal(clause):
        source = {**clause, "excerpt": text}
        return {
            "obligations": [{
                "obligation_id": "production-debug",
                "statement": "Debug mode is disabled in production.",
                "detection_surfaces": ["configuration_iac"],
                "source_reference": source,
            }],
            "controls": [{
                "obligation_ids": ["production-debug"],
                "control_id": "runtime.production-debug",
                "title": "Production debug mode",
                "description": "Detects debug=true in structured production configuration.",
                "prohibited_condition": "Production configuration must not enable debug mode.",
                "control_type": "config_iac",
                "severity": "ERROR",
                "scope": {"file_globs": ["*.json", "*.yaml", "*.yml"]},
                "exclusions": ["Test configuration"],
                "clarification_questions": [],
                "source_reference": source,
                "confidence": 0.98,
                "match": {"field_names": ["debug"], "prohibited_values": ["true"]},
                "tests": [
                    {"file": "production.json", "content": '{"debug": true}', "should_match": True},
                    {"file": "production.json", "content": '{"debug": false}', "should_match": False},
                ],
            }],
        }

    _, _, [control] = _ingest(text, proposal)

    assert control["control_type"] == "config_iac"
    assert control["state"] == "draft"
    assert control["validation"]["passed"] is True


def test_unimplemented_obligation_becomes_visible_non_activatable_placeholder():
    text = "Every repository must require two approving reviewers before merge."

    def proposal(clause):
        return {
            "obligations": [{
                "obligation_id": "two-reviewers",
                "statement": text,
                "detection_surfaces": ["repository_settings"],
                "source_reference": {**clause, "excerpt": text},
            }],
            "controls": [],
        }

    plane, policy, [control] = _ingest(text, proposal)

    assert control["generated_coverage_placeholder"] is True
    assert control["control_type"] == "manual_review"
    assert control["state"] == "needs_clarification"
    assert control["validation"]["passed"] is True
    import pytest
    plane.answer_control_clarifications(
        control["control_id"],
        control["version"],
        [{"question": question, "answer": "A repository-settings adapter is required."} for question in control["clarification_questions"]],
    )
    with pytest.raises(ValueError, match="coverage placeholders cannot be approved"):
        plane.approve_control(control["control_id"], control["version"], actor="approver@example.com")
    stored_policy = plane.get_policy(policy["document_id"], policy["version"])
    assert stored_policy["status"] == "partial_coverage"
    assert stored_policy["coverage_complete"] is False
    assert any("repository_settings" in question for question in stored_policy["coverage_questions"])


def test_model_invented_detector_vocabulary_requires_human_provenance():
    text = "Applications must not use unapproved external analytics services."

    def proposal(clause):
        source = {**clause, "excerpt": text}
        return {
            "obligations": [{
                "obligation_id": "analytics",
                "statement": text,
                "detection_surfaces": ["service_endpoints"],
                "source_reference": source,
            }],
            "controls": [{
                "obligation_ids": ["analytics"],
                "control_id": "analytics.vendor",
                "title": "Unapproved analytics endpoint",
                "description": "Proposed endpoint detector.",
                "prohibited_condition": text,
                "control_type": "url_domain",
                "severity": "ERROR",
                "scope": {},
                "exclusions": [],
                "clarification_questions": [],
                "source_reference": source,
                "confidence": 0.7,
                "match": {"domains": ["invented-vendor.example"]},
                "tests": [
                    {"file": "client.py", "content": 'URL="https://invented-vendor.example"', "should_match": True},
                    {"file": "client.py", "content": 'URL="https://internal.example"', "should_match": False},
                ],
            }],
        }

    _, _, [control] = _ingest(text, proposal)

    assert control["validation"]["passed"] is True
    assert control["state"] == "needs_clarification"
    assert any("invented-vendor.example" in question for question in control["clarification_questions"])
