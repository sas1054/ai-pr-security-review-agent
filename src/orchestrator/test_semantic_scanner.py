"""Guardrail tests for the bounded LLM semantic/manual-review scanner."""

import json

import pytest

from policy_engine import AzureOpenAISemanticControlScanner, PolicyEngineError


CONTROL = {
    "control_id": "crypto.terminology-review",
    "version": "1.0",
    "control_type": "semantic_review",
    "title": "Cryptocurrency terminology requires review",
    "prohibited_condition": "Generic blockchain terminology may indicate an unapproved integration.",
    "scope": {},
    "exclusions": ["Security research code"],
    "policy_title": "Cryptocurrency Integration Restrictions",
    "policy_version": "2026-02",
    "source_reference": {"excerpt": "must not integrate cryptocurrency payment services"},
}

FILES = {"/src/wallet.py": "import wallet_sdk\nsettle_on_chain()\n"}


class FakeClient:
    """Minimal stand-in for the OpenAI client surface the scanner touches."""

    def __init__(self, content):
        self.content = content
        self.request = None
        message = type("Message", (), {"content": content})()
        choice = type("Choice", (), {"message": message})()
        response = type("Response", (), {"choices": [choice]})()

        def create(**kwargs):
            self.request = kwargs
            return response

        self.chat = type("Chat", (), {"completions": type("Completions", (), {"create": staticmethod(create)})()})()


def _scanner(content):
    client = FakeClient(content)
    return AzureOpenAISemanticControlScanner(client=client, deployment="gpt-test"), client


def test_semantic_scanner_returns_review_evidence_with_policy_citation():
    scanner, _ = _scanner(
        json.dumps(
            {
                "findings": [
                    {
                        "control_id": "crypto.terminology-review",
                        "file": "/src/wallet.py",
                        "line": 2,
                        "matched_value": "settle_on_chain()",
                        "reason": "On-chain settlement suggests a blockchain transaction service.",
                        "confidence": 0.82,
                    }
                ]
            }
        )
    )

    [finding] = scanner.scan(FILES, [CONTROL])

    assert finding.tool == "policy-semantic-review"
    assert finding.review_required is True
    assert finding.severity == "WARNING"
    assert finding.control_id == "crypto.terminology-review"
    assert finding.control_version == "1.0"
    assert finding.policy_document == "Cryptocurrency Integration Restrictions"
    assert finding.policy_version == "2026-02"
    assert finding.source_reference["excerpt"] == "must not integrate cryptocurrency payment services"
    assert finding.confidence == 0.82
    assert finding.line == 2


@pytest.mark.parametrize(
    "raw",
    [
        {"control_id": "crypto.terminology-review", "file": "/src/wallet.py", "line": 1, "confidence": 0.49},
        {"control_id": "invented.control", "file": "/src/wallet.py", "line": 1, "confidence": 0.99},
        {"control_id": "crypto.terminology-review", "file": "/src/never-sent.py", "line": 1, "confidence": 0.99},
        {"control_id": "crypto.terminology-review", "file": "/src/wallet.py", "line": 99, "confidence": 0.99},
        {"control_id": "crypto.terminology-review", "file": "/src/wallet.py", "line": 0, "confidence": 0.99},
        {"control_id": "crypto.terminology-review", "file": "/src/wallet.py", "line": "two", "confidence": 0.99},
        "not-an-object",
    ],
)
def test_semantic_scanner_drops_low_confidence_and_ungrounded_output(raw):
    scanner, _ = _scanner(json.dumps({"findings": [raw]}))
    assert scanner.scan(FILES, [CONTROL]) == []


def test_semantic_scanner_rejects_invalid_json_instead_of_guessing():
    scanner, _ = _scanner("not json at all")
    with pytest.raises(PolicyEngineError):
        scanner.scan(FILES, [CONTROL])


def test_semantic_scanner_skips_deterministic_controls_and_empty_input():
    scanner, client = _scanner(json.dumps({"findings": []}))
    deterministic = {**CONTROL, "control_type": "literal_value"}

    assert scanner.scan(FILES, [deterministic]) == []
    assert scanner.scan({}, [CONTROL]) == []
    assert client.request is None, "the model must not be called when there is nothing to review"


def test_semantic_scanner_bounds_the_content_sent_to_the_model():
    scanner, client = _scanner(json.dumps({"findings": []}))
    oversized = {f"/src/file{index}.py": "x" * 150_000 for index in range(4)}

    scanner.scan(oversized, [CONTROL])

    sent = json.loads(client.request["messages"][1]["content"])["changed_files"]
    assert sum(len(value) for value in sent.values()) <= 300_000
    assert all(len(value) <= 100_000 for value in sent.values())
