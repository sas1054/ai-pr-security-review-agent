"""
Security scanner — US-06

Runs Semgrep and a secret scan on the PR diff.
Each scanner runs in-process (Semgrep via its Python API) so no Docker-in-Docker
is needed; the container image just needs semgrep + detect-secrets installed.

Findings are normalised to a common schema and mapped to OWASP Top 10 categories.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# ── OWASP mapping ─────────────────────────────────────────────────────────────

OWASP_MAP: dict[str, str] = {
    # Semgrep rule category → OWASP Top 10 (2021)
    "injection":            "A03:2021 – Injection",
    "sql-injection":        "A03:2021 – Injection",
    "xss":                  "A03:2021 – Injection",
    "xxe":                  "A05:2021 – Security Misconfiguration",
    "ssrf":                 "A10:2021 – SSRF",
    "path-traversal":       "A01:2021 – Broken Access Control",
    "broken-access-control":"A01:2021 – Broken Access Control",
    "cryptography":         "A02:2021 – Cryptographic Failures",
    "hardcoded-secret":     "A02:2021 – Cryptographic Failures",
    "secret":               "A02:2021 – Cryptographic Failures",
    "insecure-deserialization": "A08:2021 – Software and Data Integrity Failures",
    "logging":              "A09:2021 – Security Logging and Monitoring Failures",
    "misconfiguration":     "A05:2021 – Security Misconfiguration",
}

DEFAULT_OWASP = "A00:2021 – General Security"


def _owasp_for_rule(rule_id: str) -> str:
    rule_lower = rule_id.lower()
    for keyword, owasp in OWASP_MAP.items():
        if keyword in rule_lower:
            return owasp
    return DEFAULT_OWASP


# ── Finding schema ────────────────────────────────────────────────────────────

@dataclass
class Finding:
    tool: str           # "semgrep" | "secret-scan"
    rule_id: str
    file: str
    line: int
    severity: str       # "ERROR" | "WARNING" | "INFO"
    message: str
    owasp: str = ""
    fix_hint: str = ""

    def __post_init__(self):
        if not self.owasp:
            self.owasp = _owasp_for_rule(self.rule_id)


# ── Semgrep ───────────────────────────────────────────────────────────────────

SEMGREP_RULESETS = [
    "p/owasp-top-ten",
    "p/secrets",
    "p/python",
]


def run_semgrep(files: dict[str, str]) -> list[Finding]:
    """
    Writes changed file content to a temp dir and runs Semgrep.
    `files` is a dict of {relative_path: file_content}.
    """
    if not files:
        return []

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        for rel_path, content in files.items():
            dest = tmp / rel_path.lstrip("/")
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8", errors="replace")

        ruleset_args = []
        for rs in SEMGREP_RULESETS:
            ruleset_args += ["--config", rs]

        cmd = [
            "semgrep",
            "--json",
            "--quiet",
            "--no-git-ignore",
            *ruleset_args,
            str(tmp),
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except FileNotFoundError:
            logger.error("semgrep not found — is it installed in this container?")
            return []
        except subprocess.TimeoutExpired:
            logger.error("semgrep timed out")
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            logger.error("semgrep produced non-JSON output: %s", result.stdout[:500])
            return []

    findings = []
    for r in data.get("results", []):
        rel = str(Path(r["path"]).relative_to(Path(tmpdir))) if tmpdir in r["path"] else r["path"]
        findings.append(Finding(
            tool="semgrep",
            rule_id=r.get("check_id", "unknown"),
            file="/" + rel.replace("\\", "/"),
            line=r.get("start", {}).get("line", 0),
            severity=r.get("extra", {}).get("severity", "WARNING").upper(),
            message=r.get("extra", {}).get("message", ""),
            fix_hint=r.get("extra", {}).get("fix", ""),
        ))
    logger.info("Semgrep: %d findings", len(findings))
    return findings


# ── Secret scan ───────────────────────────────────────────────────────────────

# Patterns that strongly suggest a hard-coded secret in source code
_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("hardcoded-password",    re.compile(r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']')),
    ("hardcoded-api-key",     re.compile(r'(?i)(api_?key|apikey|token)\s*=\s*["\'][^"\']{8,}["\']')),
    ("hardcoded-connection-string", re.compile(r'(?i)(connectionstring|connstr)\s*=\s*["\'][^"\']{8,}["\']')),
    ("aws-access-key",        re.compile(r'AKIA[0-9A-Z]{16}')),
    ("github-pat",            re.compile(r'ghp_[A-Za-z0-9]{36}')),
    ("azure-storage-key",     re.compile(r'AccountKey=[A-Za-z0-9+/]{88}==')),
]

# Files that legitimately contain secret-like strings
_EXCLUDE_PATHS = re.compile(r'\.(md|txt|lock|sum)$|test_|_test\.|spec\.')


def run_secret_scan(files: dict[str, str]) -> list[Finding]:
    """Simple regex-based secret scan — fast, no external process."""
    findings = []
    for file_path, content in files.items():
        if _EXCLUDE_PATHS.search(file_path):
            continue
        for lineno, line in enumerate(content.splitlines(), start=1):
            for rule_id, pattern in _SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        tool="secret-scan",
                        rule_id=rule_id,
                        file=file_path,
                        line=lineno,
                        severity="ERROR",
                        message=f"Possible hard-coded secret matched pattern '{rule_id}'",
                        fix_hint="Move this value to Key Vault / environment variable.",
                    ))
    logger.info("Secret scan: %d findings", len(findings))
    return findings


# ── Unified entry point ───────────────────────────────────────────────────────

def scan(files: dict[str, str]) -> list[Finding]:
    """
    Runs all scanners and returns a deduplicated, sorted list of findings.
    `files` — {file_path: file_content} for non-deleted changed files only.
    """
    all_findings = run_semgrep(files) + run_secret_scan(files)

    # Deduplicate: same tool + rule + file + line
    seen: set[tuple] = set()
    unique = []
    for f in all_findings:
        key = (f.tool, f.rule_id, f.file, f.line)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Sort: ERROR first, then by file + line
    severity_order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
    unique.sort(key=lambda f: (severity_order.get(f.severity, 9), f.file, f.line))
    return unique
