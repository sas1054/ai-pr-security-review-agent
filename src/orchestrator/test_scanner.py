"""Unit tests for scanner.py — no Azure dependencies, no Semgrep binary needed."""

import pytest

from scanner import run_secret_scan, Finding, _owasp_for_rule


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


def test_owasp_mapping_secret():
    assert "Cryptographic" in _owasp_for_rule("hardcoded-secret")


def test_owasp_mapping_injection():
    assert "Injection" in _owasp_for_rule("sql-injection")


def test_owasp_mapping_unknown():
    result = _owasp_for_rule("some-unknown-rule")
    assert result == "A00:2021 – General Security"


def test_finding_severity_error():
    files = {"config.py": 'password = "hunter2"'}
    findings = run_secret_scan(files)
    assert all(f.severity == "ERROR" for f in findings)
