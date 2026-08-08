"""Deterministic security scanners and the normalized finding contract."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import subprocess
import tempfile
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path, PurePosixPath
from typing import Any, Callable

logger = logging.getLogger(__name__)

OWASP_MAP: dict[str, str] = {
    "sql-injection": "A03:2021 - Injection",
    "subprocess": "A03:2021 - Injection",
    "shell-true": "A03:2021 - Injection",
    "eval": "A03:2021 - Injection",
    "xss": "A03:2021 - Injection",
    "injection": "A03:2021 - Injection",
    "ssrf": "A10:2021 - SSRF",
    "path-traversal": "A01:2021 - Broken Access Control",
    "broken-access-control": "A01:2021 - Broken Access Control",
    "authorization": "A01:2021 - Broken Access Control",
    "access-control": "A01:2021 - Broken Access Control",
    "unverified-jwt": "A07:2021 - Identification and Authentication Failures",
    "jwt": "A07:2021 - Identification and Authentication Failures",
    "authentication": "A07:2021 - Identification and Authentication Failures",
    "insecure-deserialization": "A08:2021 - Software and Data Integrity Failures",
    "deserialization": "A08:2021 - Software and Data Integrity Failures",
    "pyyaml": "A08:2021 - Software and Data Integrity Failures",
    "yaml-load": "A08:2021 - Software and Data Integrity Failures",
    "pickle": "A08:2021 - Software and Data Integrity Failures",
    "logging": "A09:2021 - Security Logging and Monitoring Failures",
    "debug": "A05:2021 - Security Misconfiguration",
    "dockerfile": "A05:2021 - Security Misconfiguration",
    "last-user-is-root": "A05:2021 - Security Misconfiguration",
    "xxe": "A05:2021 - Security Misconfiguration",
    "misconfiguration": "A05:2021 - Security Misconfiguration",
    "insecure-hash": "A02:2021 - Cryptographic Failures",
    "md5": "A02:2021 - Cryptographic Failures",
    "cryptography": "A02:2021 - Cryptographic Failures",
    "hardcoded-secret": "A02:2021 - Cryptographic Failures",
    "hardcoded-password": "A02:2021 - Cryptographic Failures",
    "hardcoded-api-key": "A02:2021 - Cryptographic Failures",
    "secret": "A02:2021 - Cryptographic Failures",
}
DEFAULT_OWASP = "A00:2021 - General Security"


class ScannerError(RuntimeError):
    """Raised when a deterministic scanner cannot produce a trustworthy result."""


def _owasp_for_rule(rule_id: str) -> str:
    rule_lower = rule_id.lower()
    for keyword, owasp in OWASP_MAP.items():
        if keyword in rule_lower:
            return owasp
    return DEFAULT_OWASP


@dataclass
class Finding:
    tool: str
    rule_id: str
    file: str
    line: int
    severity: str
    message: str
    owasp: str = ""
    fix_hint: str = ""
    end_line: int | None = None
    fingerprint: str = ""
    control_id: str = ""
    control_version: str = ""
    reason: str = ""
    policy_document: str = ""
    policy_version: str = ""
    source_reference: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    matched_value: str = ""
    review_required: bool = False
    exception_id: str = ""
    inline_comment: bool = True

    def __post_init__(self) -> None:
        if not self.owasp:
            self.owasp = _owasp_for_rule(self.rule_id)
        self.severity = self.severity.upper()
        if self.end_line is None:
            self.end_line = self.line
        if not self.fingerprint:
            identity = f"{self.tool}|{self.rule_id}|{self.file}|{self.line}|{self.end_line}|{self.matched_value}"
            self.fingerprint = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]


SEMGREP_RULESETS = ["p/owasp-top-ten", "p/secrets", "p/python"]


def _safe_relative_path(rel_path: str) -> str | None:
    normalized = rel_path.replace("\\", "/").lstrip("/")
    path = PurePosixPath(normalized)
    if not normalized or any(part in ("", ".", "..") for part in path.parts):
        return None
    return str(path)


def run_semgrep(
    files: dict[str, str],
    *,
    runner: Callable[..., Any] = subprocess.run,
    timeout: int = 120,
    policy_rules: list[dict[str, Any]] | None = None,
) -> list[Finding]:
    """Run Semgrep against an isolated copy of changed files."""
    if not files:
        return []

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        for rel_path, content in files.items():
            safe_path = _safe_relative_path(rel_path)
            if safe_path is None:
                raise ScannerError(f"Unsafe repository path: {rel_path}")
            dest = tmp / safe_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8", errors="replace")

        ruleset_args: list[str] = []
        for ruleset in SEMGREP_RULESETS:
            ruleset_args += ["--config", ruleset]
        for index, policy_rule in enumerate(policy_rules or []):
            semgrep_yaml = str(policy_rule.get("semgrep_yaml") or "")
            if not semgrep_yaml:
                continue
            if len(semgrep_yaml) > 100_000:
                raise ScannerError(f"Custom Semgrep rule is too large: {policy_rule.get('rule_id', index)}")
            rule_id = re.sub(r"[^a-zA-Z0-9_.-]+", "-", str(policy_rule.get("rule_id") or index))
            rule_path = tmp / ".prsa-policy-rules" / f"{index:03d}-{rule_id}.yaml"
            rule_path.parent.mkdir(parents=True, exist_ok=True)
            rule_path.write_text(semgrep_yaml, encoding="utf-8")
            ruleset_args += ["--config", str(rule_path)]
        cmd = ["semgrep", "--json", "--quiet", "--no-git-ignore", *ruleset_args, str(tmp)]

        try:
            result = runner(cmd, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError as exc:
            raise ScannerError("semgrep is not installed") from exc
        except subprocess.TimeoutExpired as exc:
            raise ScannerError("semgrep timed out") from exc

        if not result.stdout:
            raise ScannerError(f"semgrep produced no JSON output: {result.stderr[:500]}")
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ScannerError(f"semgrep produced invalid JSON: {result.stdout[:500]}") from exc

        findings: list[Finding] = []
        for item in data.get("results", []):
            path = str(item.get("path", ""))
            try:
                relative = str(Path(path).relative_to(tmp))
            except ValueError:
                relative = path
            start_line = int(item.get("start", {}).get("line", 0))
            end_line = int(item.get("end", {}).get("line", start_line))
            extra = item.get("extra", {})
            findings.append(
                Finding(
                    tool="semgrep",
                    rule_id=item.get("check_id", "unknown"),
                    file="/" + relative.replace("\\", "/"),
                    line=start_line,
                    end_line=end_line,
                    severity=extra.get("severity", "WARNING"),
                    message=extra.get("message", ""),
                    fix_hint=extra.get("fix") or "",
                )
            )
        logger.info("Semgrep: %d findings", len(findings))
        return findings


_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("hardcoded-password", re.compile(r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']')),
    ("hardcoded-api-key", re.compile(r'(?i)(api_?key|apikey|token)\s*=\s*["\'][^"\']{8,}["\']')),
    ("hardcoded-connection-string", re.compile(r'(?i)(connectionstring|connstr)\s*=\s*["\'][^"\']{8,}["\']')),
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github-pat", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("azure-storage-key", re.compile(r"AccountKey=[A-Za-z0-9+/]{88}==")),
]
_EXCLUDE_PATHS = re.compile(r"\.(md|txt|lock|sum)$|test_|_test\.|spec\.")


def run_secret_scan(files: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    for file_path, content in files.items():
        if _EXCLUDE_PATHS.search(file_path):
            continue
        for lineno, line in enumerate(content.splitlines(), start=1):
            for rule_id, pattern in _SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        Finding(
                            tool="secret-scan",
                            rule_id=rule_id,
                            file=file_path,
                            line=lineno,
                            severity="ERROR",
                            message=f"Possible hard-coded secret matched pattern '{rule_id}'",
                            fix_hint="Move this value to Key Vault / environment variable.",
                        )
                    )
    logger.info("Secret scan: %d findings", len(findings))
    return findings


def run_policy_scan(files: dict[str, str], policy_rules: list[dict[str, Any]]) -> list[Finding]:
    """Run approved simple policy rules without giving the LLM enforcement power.

    A rule is intentionally small and reviewable: a regular expression, optional
    file glob, severity, message, policy reference, and fix hint. More complex
    rules use the ``semgrep_yaml`` field and run through Semgrep above.
    """
    findings: list[Finding] = []
    for raw_rule in policy_rules:
        pattern = str(raw_rule.get("pattern") or "")
        if not pattern:
            continue
        if len(pattern) > 512:
            logger.warning("Skipping policy rule with an overly long pattern: %s", raw_rule.get("rule_id"))
            continue
        try:
            matcher = re.compile(pattern)
        except re.error:
            logger.warning("Skipping policy rule with invalid pattern: %s", raw_rule.get("rule_id"))
            continue
        rule_id = str(raw_rule.get("rule_id") or "policy-rule")
        file_glob = str(raw_rule.get("file_glob") or "*")
        for file_path, content in files.items():
            if not fnmatch(file_path.lstrip("/"), file_glob):
                continue
            for line_number, line in enumerate(content.splitlines(), start=1):
                if matcher.search(line):
                    findings.append(
                        Finding(
                            tool="policy",
                            rule_id=rule_id,
                            file=file_path if file_path.startswith("/") else f"/{file_path}",
                            line=line_number,
                            severity=str(raw_rule.get("severity") or "WARNING"),
                            message=str(raw_rule.get("message") or "Approved policy rule matched this code."),
                            owasp=str(raw_rule.get("owasp") or ""),
                            fix_hint=str(raw_rule.get("fix_hint") or "Review the applicable engineering policy."),
                        )
                    )
    logger.info("Policy scan: %d findings", len(findings))
    return findings


def _policy_finding(
    control: dict[str, Any], file_path: str, line: int, matched: str, message: str | None = None
) -> Finding:
    return Finding(
        tool=f"policy-{control.get('control_type', 'control')}",
        rule_id=str(control.get("control_id") or "policy-control"),
        file=file_path if file_path.startswith("/") else f"/{file_path}",
        line=line,
        severity=str(control.get("severity") or "WARNING"),
        message=message or str(control.get("description") or control.get("prohibited_condition") or "Active policy control matched."),
        fix_hint=str(control.get("fix_hint") or "Use an approved value or request a documented exception."),
        control_id=str(control.get("control_id") or ""),
        control_version=str(control.get("version") or ""),
        reason=str(control.get("prohibited_condition") or control.get("description") or ""),
        policy_document=str(control.get("policy_title") or control.get("policy_document_id") or ""),
        policy_version=str(control.get("policy_version") or ""),
        source_reference=dict(control.get("source_reference") or {}),
        confidence=float(control.get("confidence") or 1.0),
        matched_value=matched,
        review_required=control.get("control_type") in {"semantic_review", "manual_review"},
    )


def _allowed_file(control: dict[str, Any], file_path: str) -> bool:
    detector = control.get("detector") or {}
    globs = detector.get("file_globs") or (control.get("scope") or {}).get("file_globs") or ["*"]
    normalized = file_path.lstrip("/")
    excludes = detector.get("exclude_globs") or [
        "*.md", "docs/**", "**/docs/**", "tests/**", "**/tests/**", "test_*", "**/test_*", "*_test.*", "**/*.spec.*"
    ]
    return any(fnmatch(normalized, str(pattern)) for pattern in globs) and not any(
        fnmatch(normalized, str(pattern)) for pattern in excludes
    )


def _line_matches(files: dict[str, str], control: dict[str, Any], patterns: list[re.Pattern[str]]) -> list[Finding]:
    findings: list[Finding] = []
    for file_path, content in files.items():
        if not _allowed_file(control, file_path):
            continue
        for line_number, line in enumerate(content.splitlines(), 1):
            for matcher in patterns:
                match = matcher.search(line)
                if match:
                    findings.append(_policy_finding(control, file_path, line_number, match.group(0)))
                    break
    return findings


def _walk_values(value: Any, path: tuple[str, ...] = ()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk_values(child, (*path, str(key)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_values(child, (*path, str(index)))
    else:
        yield path, value


def _config_control_scan(files: dict[str, str], control: dict[str, Any]) -> list[Finding]:
    detector = control.get("detector") or {}
    prohibited = {str(item).casefold() for item in [*detector.get("prohibited_values", []), *detector.get("aliases", [])]}
    fields = {str(item).casefold() for item in detector.get("field_names", [])}
    findings: list[Finding] = []
    for file_path, content in files.items():
        if not _allowed_file(control, file_path):
            continue
        parsed: Any = None
        try:
            if file_path.lower().endswith(".json"):
                parsed = json.loads(content)
            elif file_path.lower().endswith((".yaml", ".yml")):
                import yaml

                parsed = yaml.safe_load(content)
        except Exception:
            logger.warning("Could not parse structured configuration %s; using assignment analysis", file_path)
        if parsed is not None:
            for path, value in _walk_values(parsed):
                if fields and not any(part.casefold() in fields for part in path):
                    continue
                normalized = str(value).strip().casefold()
                if normalized not in prohibited:
                    continue
                line = next(
                    (number for number, text in enumerate(content.splitlines(), 1) if str(value).casefold() in text.casefold()),
                    1,
                )
                findings.append(_policy_finding(control, file_path, line, str(value)))
            continue
        assignment = re.compile(r"(?i)^\s*([\w.-]+)\s*(?:=|:)\s*['\"]?([^'\"\s,}]+)")
        for number, line in enumerate(content.splitlines(), 1):
            match = assignment.search(line)
            if not match:
                continue
            key, value = match.group(1), match.group(2)
            if (not fields or key.casefold() in fields) and value.casefold() in prohibited:
                findings.append(_policy_finding(control, file_path, number, value))
    return findings


def _normalize_package(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value.strip().lower())


def _safe_policy_pattern(value: str) -> bool:
    """Reject high-risk regex features before a generated pattern reaches Python's backtracking engine."""
    if not value or len(value) > 512 or re.search(r"\\[1-9]|\(\?<[=!]|\(\?P=", value):
        return False
    if re.search(r"\((?:[^()]|\\.)*[*+](?:[^()]|\\.)*\)\s*(?:[*+]|\{)", value):
        return False
    return True


def _packages_from_file(path: str, content: str) -> list[tuple[str, int]]:
    """Extract direct and lock-file dependencies for the supported five ecosystems."""
    name = PurePosixPath(path.lower()).name
    packages: list[tuple[str, int]] = []
    try:
        if name in {"package.json", "package-lock.json", "npm-shrinkwrap.json"}:
            data = json.loads(content)
            for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                for package in (data.get(section) or {}):
                    packages.append((str(package), 1))
            for package_path, item in (data.get("packages") or {}).items():
                package = str(package_path).split("node_modules/")[-1]
                if package and package_path:
                    packages.append((package, 1))
                if isinstance(item, dict) and item.get("name"):
                    packages.append((str(item["name"]), 1))
        elif name in {"pyproject.toml", "pdm.lock", "poetry.lock", "pipfile"}:
            data = tomllib.loads(content)
            project = data.get("project") or {}
            for requirement in project.get("dependencies") or []:
                packages.append((re.split(r"[<>=!~\[ ;]", str(requirement), 1)[0], 1))
            poetry = ((data.get("tool") or {}).get("poetry") or {})
            for section in ("dependencies", "dev-dependencies"):
                for package in (poetry.get(section) or {}):
                    if package.lower() != "python":
                        packages.append((str(package), 1))
            for item in data.get("package") or []:
                if isinstance(item, dict) and item.get("name"):
                    packages.append((str(item["name"]), 1))
        elif name.startswith("requirements") and name.endswith((".txt", ".in")):
            for number, line in enumerate(content.splitlines(), 1):
                value = line.split("#", 1)[0].strip()
                if value and not value.startswith(("-", "http://", "https://")):
                    packages.append((re.split(r"[<>=!~\[ ;]", value, 1)[0], number))
        elif name.endswith((".csproj", ".fsproj", ".vbproj")) or name == "packages.config":
            root = ET.fromstring(content)
            for element in root.iter():
                if element.tag.split("}")[-1] in {"PackageReference", "package"}:
                    package = element.attrib.get("Include") or element.attrib.get("Update") or element.attrib.get("id")
                    if package:
                        packages.append((package, 1))
        elif name == "packages.lock.json":
            data = json.loads(content)
            for framework in (data.get("dependencies") or {}).values():
                if isinstance(framework, dict):
                    packages.extend((str(package), 1) for package in framework)
        elif name == "pom.xml":
            root = ET.fromstring(content)
            for dependency in root.iter():
                if dependency.tag.split("}")[-1] != "dependency":
                    continue
                group = artifact = ""
                for child in dependency:
                    tag = child.tag.split("}")[-1]
                    if tag == "groupId":
                        group = child.text or ""
                    elif tag == "artifactId":
                        artifact = child.text or ""
                if artifact:
                    packages.append((f"{group}:{artifact}" if group else artifact, 1))
        elif name in {"build.gradle", "build.gradle.kts"}:
            for number, line in enumerate(content.splitlines(), 1):
                for match in re.finditer(r"['\"]([\w.-]+:[\w.-]+)(?::[^'\"]+)?['\"]", line):
                    packages.append((match.group(1), number))
        elif name in {"go.mod", "go.sum"}:
            for number, line in enumerate(content.splitlines(), 1):
                value = line.strip()
                match = re.match(r"(?:require\s+)?([\w./-]+)\s+v\d", value)
                if match:
                    packages.append((match.group(1), number))
    except (json.JSONDecodeError, tomllib.TOMLDecodeError, ET.ParseError, TypeError, AttributeError):
        logger.warning("Could not parse dependency manifest %s", path)
    return packages


def run_typed_control_scan(files: dict[str, str], controls: list[dict[str, Any]]) -> list[Finding]:
    """Execute validated control IR through deterministic, type-specific adapters."""
    findings: list[Finding] = []
    for control in controls:
        kind = str(control.get("control_type") or "manual_review")
        detector = control.get("detector") or {}
        if kind in {"manual_review", "semantic_review", "ast"}:
            # Semantic controls run in the bounded review path; AST controls run through Semgrep.
            continue
        if kind == "config_iac":
            findings.extend(_config_control_scan(files, control))
        elif kind == "literal_value":
            values = [str(item) for item in detector.get("prohibited_values", []) if str(item)]
            aliases = [str(item) for item in detector.get("aliases", []) if str(item)]
            patterns = [re.compile(rf"(?i)(?<![\w]){re.escape(value)}(?![\w])") for value in [*values, *aliases]]
            findings.extend(_line_matches(files, control, patterns))
        elif kind == "pattern":
            patterns: list[re.Pattern[str]] = []
            for raw in detector.get("patterns", []):
                if not isinstance(raw, str) or not _safe_policy_pattern(raw):
                    continue
                try:
                    patterns.append(re.compile(raw))
                except re.error:
                    logger.warning("Skipping invalid validated pattern for %s", control.get("control_id"))
            findings.extend(_line_matches(files, control, patterns))
        elif kind == "url_domain":
            domains = [str(item).lower().rstrip(".") for item in detector.get("domains", [])]
            if not domains:
                continue
            domain_pattern = re.compile(r"(?i)(?:https?://)?([a-z0-9.-]+\.[a-z]{2,})(?::\d+)?")
            for file_path, content in files.items():
                if not _allowed_file(control, file_path):
                    continue
                for number, line in enumerate(content.splitlines(), 1):
                    for match in domain_pattern.finditer(line):
                        host = match.group(1).lower().rstrip(".")
                        if any(host == domain or host.endswith("." + domain) for domain in domains):
                            findings.append(_policy_finding(control, file_path, number, host))
        elif kind == "dependency":
            prohibited = {_normalize_package(str(item)) for item in detector.get("packages", []) if str(item)}
            prefixes = [_normalize_package(str(item)) for item in detector.get("package_prefixes", []) if str(item)]
            for file_path, content in files.items():
                if not _allowed_file(control, file_path):
                    continue
                for package, number in _packages_from_file(file_path, content):
                    normalized = _normalize_package(package)
                    if normalized in prohibited or any(normalized.startswith(prefix) for prefix in prefixes):
                        findings.append(_policy_finding(control, file_path, number, package, f"Prohibited dependency '{package}' is present."))
    return findings


def scan(
    files: dict[str, str],
    *,
    semgrep_runner: Callable[..., Any] = subprocess.run,
    policy_rules: list[dict[str, Any]] | None = None,
    controls: list[dict[str, Any]] | None = None,
) -> list[Finding]:
    """Run all deterministic scanners and return deduplicated findings."""
    active_rules = policy_rules or []
    active_controls = controls or []
    ast_rules = [
        {"rule_id": control.get("control_id"), "semgrep_yaml": (control.get("detector") or {}).get("semgrep_yaml", "")}
        for control in active_controls
        if control.get("control_type") == "ast" and (control.get("detector") or {}).get("semgrep_yaml")
    ]
    semgrep_findings = run_semgrep(files, runner=semgrep_runner, policy_rules=[*active_rules, *ast_rules])
    for finding in semgrep_findings:
        for control in active_controls:
            control_id = str(control.get("control_id") or "")
            if control.get("control_type") == "ast" and control_id and control_id in finding.rule_id:
                finding.control_id = control_id
                finding.control_version = str(control.get("version") or "")
                finding.reason = str(control.get("prohibited_condition") or control.get("description") or "")
                finding.policy_document = str(control.get("policy_title") or control.get("policy_document_id") or "")
                finding.policy_version = str(control.get("policy_version") or "")
                finding.source_reference = dict(control.get("source_reference") or {})
                finding.confidence = float(control.get("confidence") or 1.0)
                break
    all_findings = (
        semgrep_findings
        + run_secret_scan(files)
        + run_policy_scan(files, active_rules)
        + run_typed_control_scan(files, active_controls)
    )
    unique: dict[str, Finding] = {}
    for finding in all_findings:
        unique.setdefault(finding.fingerprint, finding)

    severity_order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
    return sorted(
        unique.values(),
        key=lambda finding: (severity_order.get(finding.severity, 9), finding.file, finding.line),
    )
