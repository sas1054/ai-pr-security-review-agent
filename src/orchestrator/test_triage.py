import json

import pytest

from ado_client import PrDiff
from models import TriageResult
from scanner import Finding
from triage import AzureOpenAITriageClient, TriageError


class _Message:
    def __init__(self, content):
        self.content = content


class _Choice:
    def __init__(self, content):
        self.message = _Message(content)


class _Completions:
    def __init__(self, content):
        self.content = content
        self.last_call = None

    def create(self, **kwargs):
        self.last_call = kwargs
        return type("Response", (), {"choices": [_Choice(self.content)]})()


class _Client:
    def __init__(self, content):
        self.chat = type("Chat", (), {"completions": _Completions(content)})()


def _inputs():
    finding = Finding("secret-scan", "hardcoded-password", "/config.py", 1, "ERROR", "secret")
    diff = PrDiff(1, "repo", "feature", "main", iteration_id=2, raw_diff="diff")
    return diff, [finding]


def test_triage_parses_structured_response_and_ignores_unknown_findings():
    diff, findings = _inputs()
    payload = {
        "summary": "Review completed",
        "items": [
            {
                "fingerprint": findings[0].fingerprint,
                "priority": "high",
                "likely_false_positive": False,
                "explanation": "Use a secret store",
                "fix_hint": "Move it to Key Vault",
            },
            {"fingerprint": "unknown", "priority": "critical"},
        ],
    }
    client = _Client(json.dumps(payload))
    result = AzureOpenAITriageClient(client=client, deployment="model").triage(diff, findings)
    assert isinstance(result, TriageResult)
    assert result.summary == "Review completed"
    assert len(result.items) == 1
    assert client.chat.completions.last_call["max_completion_tokens"] == 8000
    assert client.chat.completions.last_call["reasoning_effort"] == "medium"
    assert client.chat.completions.last_call["messages"][0]["role"] == "developer"


def test_triage_rejects_invalid_json():
    diff, findings = _inputs()
    with pytest.raises(TriageError):
        AzureOpenAITriageClient(client=_Client("not-json"), deployment="model").triage(diff, findings)


def test_triage_keeps_item_level_priorities_when_the_model_omits_the_summary():
    """Observed in Azure: the model returned items but no summary string."""
    diff, findings = _inputs()
    payload = {
        "items": [
            {
                "fingerprint": findings[0].fingerprint,
                "priority": "high",
                "likely_false_positive": False,
                "explanation": "Use a secret store",
                "fix_hint": "Move it to Key Vault",
            }
        ]
    }

    result = AzureOpenAITriageClient(client=_Client(json.dumps(payload)), deployment="model").triage(diff, findings)

    assert len(result.items) == 1
    assert result.items[0].priority == "high"
    assert result.summary == "Prioritized 1 of 1 findings."


@pytest.mark.parametrize("payload", [{}, {"summary": "   "}, {"summary": None, "items": []}, {"items": [{"fingerprint": "unknown"}]}])
def test_triage_fails_when_nothing_usable_comes_back(payload):
    diff, findings = _inputs()
    with pytest.raises(TriageError):
        AzureOpenAITriageClient(client=_Client(json.dumps(payload)), deployment="model").triage(diff, findings)


def test_triage_rejects_a_non_object_payload():
    diff, findings = _inputs()
    with pytest.raises(TriageError):
        AzureOpenAITriageClient(client=_Client(json.dumps(["not", "an", "object"])), deployment="model").triage(diff, findings)


def test_triage_prioritizes_finding_files_and_respects_input_budget():
    finding = Finding("secret-scan", "hardcoded-password", "/important.py", 2, "ERROR", "secret")
    diff = PrDiff(
        1,
        "repo",
        "feature",
        "main",
        iteration_id=2,
        raw_diff=(
            "diff --git a/noise.py b/noise.py\n" + "x = 'noise'\n" * 2000
            + "diff --git a/important.py b/important.py\npassword = 'secret'\n" * 2000
        ),
    )
    client = _Client(json.dumps({"summary": "Review completed", "items": []}))
    AzureOpenAITriageClient(
        client=client,
        deployment="model",
        max_input_tokens=2000,
    ).triage(diff, [finding])

    request = json.loads(client.chat.completions.last_call["messages"][1]["content"])
    assert request["diff"].startswith("diff --git a/important.py b/important.py")
    assert len(request["diff"]) < len(diff.raw_diff)


def test_hackathon_mode_uses_api_key(monkeypatch):
    captured = {}

    class FakeOpenAI:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr("triage.OpenAI", FakeOpenAI)
    monkeypatch.setenv("HACKATHON_MODE", "true")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "hackathon-key")
    AzureOpenAITriageClient(endpoint="https://example.openai.azure.com", deployment="gpt-5.4-mini")
    assert captured["api_key"] == "hackathon-key"
