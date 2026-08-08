"""Unit tests for scanner.py — no Azure dependencies or Semgrep binary needed."""

import json
import subprocess

import pytest

from scanner import ScannerError, _owasp_for_rule, Finding, run_secret_scan, run_semgrep, run_typed_control_scan


def test_detects_hardcoded_password():
    files = {"config.py": 'db_password = "supersecret123"'}
    findings = run_secret_scan(files)
    assert any(f.rule_id == "hardcoded-password" for f in findings)


def test_detects_github_pat():
    files = {"deploy.py": 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'}
    findings = run_secret_scan(files)
    assert any(f.rule_id == "github-pat" for f in findings)


def test_skips_test_files():
    files = {"test_config.py": 'password = "testsecret123"'}
    findings = run_secret_scan(files)
    assert findings == []


def test_skips_markdown():
    files = {"README.md": 'password = "supersecret123"'}
    findings = run_secret_scan(files)
    assert findings == []


def test_clean_file_no_findings():
    files = {"app.py": "import os\npassword = os.environ['DB_PASSWORD']\n"}
    findings = run_secret_scan(files)
    assert findings == []


def test_finding_has_owasp():
    files = {"secrets.py": 'api_key = "mysecretkey1234"'}
    findings = run_secret_scan(files)
    assert findings
    assert findings[0].owasp != ""
    assert "Cryptographic" in findings[0].owasp


def test_owasp_mapping_secret():
    assert "Cryptographic" in _owasp_for_rule("hardcoded-secret")


def test_owasp_mapping_injection():
    assert "Injection" in _owasp_for_rule("sql-injection")


@pytest.mark.parametrize(
    ("rule_id", "expected_category"),
    [
        ("python.lang.security.audit.subprocess-shell-true.subprocess-shell-true", "Injection"),
        ("python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load", "Data Integrity"),
        ("python.jwt.security.unverified-jwt-decode.unverified-jwt-decode", "Authentication"),
        ("python.flask.security.audit.debug-enabled.debug-enabled", "Misconfiguration"),
        ("dockerfile.security.last-user-is-root.last-user-is-root", "Misconfiguration"),
        ("python.lang.security.insecure-hash-algorithms-md5.insecure-hash-algorithm-md5", "Cryptographic"),
    ],
)
def test_owasp_mapping_common_semgrep_rule_ids(rule_id, expected_category):
    assert expected_category in _owasp_for_rule(rule_id)


def test_owasp_mapping_unknown():
    result = _owasp_for_rule("some-unknown-rule")
    assert result == "A00:2021 - General Security"


def test_finding_severity_error():
    files = {"config.py": 'password = "hunter2"'}
    findings = run_secret_scan(files)
    assert all(f.severity == "ERROR" for f in findings)


def test_finding_has_stable_fingerprint():
    first = Finding("secret-scan", "hardcoded-password", "/config.py", 4, "ERROR", "secret")
    second = Finding("secret-scan", "hardcoded-password", "/config.py", 4, "ERROR", "different text")
    assert first.fingerprint == second.fingerprint


def test_semgrep_json_is_normalized():
    def runner(*args, **kwargs):
        payload = {
            "results": [
                {
                    "path": str(__import__("pathlib").Path(args[0][-1]) / "app.py"),
                    "check_id": "python.sql-injection",
                    "start": {"line": 4},
                    "end": {"line": 5},
                    "extra": {"severity": "ERROR", "message": "Unsafe query", "fix": "Use parameters"},
                }
            ]
        }
        return subprocess.CompletedProcess(args[0], 1, json.dumps(payload), "")

    findings = run_semgrep({"app.py": "query = user_input"}, runner=runner)
    assert findings[0].file == "/app.py"
    assert findings[0].line == 4
    assert findings[0].end_line == 5
    assert findings[0].owasp == "A03:2021 - Injection"


def test_semgrep_missing_binary_is_not_a_clean_result():
    def runner(*args, **kwargs):
        raise FileNotFoundError("semgrep")

    with pytest.raises(ScannerError):
        run_semgrep({"app.py": "print('x')"}, runner=runner)


def test_semgrep_rejects_unsafe_paths():
    with pytest.raises(ScannerError):
        run_semgrep({"../escape.py": "secret = 1"}, runner=lambda *args, **kwargs: None)


def _typed_control(kind, detector):
    return {
        "control_id": f"policy-{kind}",
        "version": "1.0",
        "control_type": kind,
        "severity": "ERROR",
        "description": "Policy matched",
        "prohibited_condition": "The integration is prohibited.",
        "policy_title": "Security policy",
        "policy_version": "2026-01",
        "source_reference": {"paragraph": 1, "excerpt": "This integration is prohibited."},
        "detector": detector,
    }


def test_literal_control_adds_policy_citation_and_skips_documentation():
    control = _typed_control("literal_value", {"prohibited_values": ["ru-central"]})
    findings = run_typed_control_scan({"deploy/config.yaml": 'region: "ru-central"', "docs/example.md": 'region: "ru-central"'}, [control])
    assert len(findings) == 1
    assert findings[0].control_id == "policy-literal_value"
    assert findings[0].source_reference["paragraph"] == 1


@pytest.mark.parametrize(
    ("path", "content", "package"),
    [
        ("package-lock.json", '{"packages":{"node_modules/crypto-wallet-sdk":{"version":"1.0"}}}', "crypto-wallet-sdk"),
        ("requirements.txt", "crypto-wallet-sdk==1.0\n", "crypto-wallet-sdk"),
        ("service.csproj", '<Project><ItemGroup><PackageReference Include="Crypto.Wallet.SDK" Version="1" /></ItemGroup></Project>', "Crypto.Wallet.SDK"),
        ("pom.xml", '<project><dependencies><dependency><groupId>crypto</groupId><artifactId>wallet-sdk</artifactId></dependency></dependencies></project>', "crypto:wallet-sdk"),
        ("go.mod", "module example\nrequire crypto.example/wallet v1.2.3\n", "crypto.example/wallet"),
    ],
)
def test_dependency_control_supports_common_five_ecosystems(path, content, package):
    control = _typed_control("dependency", {"packages": [package], "file_globs": ["*"]})
    findings = run_typed_control_scan({path: content}, [control])
    assert findings and findings[0].matched_value == package


def test_domain_control_matches_subdomains_but_not_lookalikes():
    control = _typed_control("url_domain", {"domains": ["crypto.example"]})
    findings = run_typed_control_scan(
        {"app.py": 'good="https://api.crypto.example/pay"\nbad="https://crypto.example.evil.test/pay"'}, [control]
    )
    assert len(findings) == 1
    assert findings[0].matched_value == "api.crypto.example"


def test_config_control_matches_only_scoped_structured_fields():
    control = _typed_control(
        "config_iac",
        {"prohibited_values": ["RU"], "field_names": ["countryCode"], "file_globs": ["*.yaml"]},
    )
    findings = run_typed_control_scan(
        {"deploy.yaml": "countryCode: RU\ndescription: RU\nregion: westeurope\n"}, [control]
    )
    assert len(findings) == 1
    assert findings[0].line == 1


def test_generated_pattern_rejects_nested_quantifier_redos_shape():
    control = _typed_control("pattern", {"patterns": ["(a+)+$"]})
    assert run_typed_control_scan({"app.py": "a" * 1000 + "!"}, [control]) == []
