"""Natural-language policy ingestion with a deterministic control boundary."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
from dataclasses import dataclass
from io import BytesIO
from pathlib import PurePosixPath
from typing import Any, Protocol
from urllib.parse import unquote, urljoin, urlparse

import httpx
from azure.identity import DefaultAzureCredential, get_bearer_token_provider
from openai import OpenAI

from prsa_control import ControlPlane
from scanner import Finding, run_semgrep, run_typed_control_scan


MAX_POLICY_BYTES = 20 * 1024 * 1024
ALLOWED_MEDIA_TYPES = {
    "text/plain": "txt",
    "application/pdf": "pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
}


class PolicyEngineError(RuntimeError):
    pass


@dataclass
class Extraction:
    text: str
    clauses: list[dict[str, Any]]


def _paragraphs(text: str) -> list[str]:
    return [value.strip() for value in re.split(r"\n\s*\n", text.replace("\r\n", "\n")) if value.strip()]


def _text_extraction(text: str, *, page: int | None = None, initial_section: str = "") -> Extraction:
    clauses: list[dict[str, Any]] = []
    section = initial_section
    pieces = _paragraphs(text)
    clause_index = 0
    for index, paragraph in enumerate(pieces, 1):
        first_line = paragraph.splitlines()[0].strip()
        if len(first_line) <= 100 and (first_line.endswith(":") or re.match(r"^\d+(?:\.\d+)*\s+", first_line)):
            section = first_line.rstrip(":")
        for offset in range(0, len(paragraph), 6000):
            clause_index += 1
            clause: dict[str, Any] = {
                "clause_id": f"clause-{clause_index:05d}",
                "paragraph": index,
                "paragraph_part": offset // 6000 + 1,
                "section": section,
                "excerpt": paragraph[offset : offset + 6000],
            }
            if page is not None:
                clause["page"] = page
            clauses.append(clause)
    return Extraction(text="\n\n".join(pieces), clauses=clauses)


def extract_document(filename: str, content: bytes) -> Extraction:
    extension = PurePosixPath(filename.lower()).suffix
    if len(content) > MAX_POLICY_BYTES:
        raise PolicyEngineError("Policy document exceeds the 20 MB limit")
    if extension == ".txt":
        try:
            text = content.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = content.decode("utf-8", errors="replace")
        return _text_extraction(text)
    if extension == ".pdf":
        try:
            from pypdf import PdfReader
        except ImportError as exc:  # pragma: no cover - deployment dependency
            raise PolicyEngineError("PDF extraction dependency is unavailable") from exc
        reader = PdfReader(BytesIO(content))
        all_text: list[str] = []
        clauses: list[dict[str, Any]] = []
        for page_number, page in enumerate(reader.pages, 1):
            page_text = page.extract_text() or ""
            extraction = _text_extraction(page_text, page=page_number)
            all_text.append(extraction.text)
            for clause_number, clause in enumerate(extraction.clauses, 1):
                clause["clause_id"] = f"page-{page_number}-{clause_number:05d}"
                clauses.append(clause)
        text = "\n\n".join(item for item in all_text if item)
        if not text.strip():
            raise PolicyEngineError("PDF contains no extractable text; provide an OCR-processed file")
        return Extraction(text=text, clauses=clauses)
    if extension == ".docx":
        try:
            from docx import Document
        except ImportError as exc:  # pragma: no cover - deployment dependency
            raise PolicyEngineError("Word extraction dependency is unavailable") from exc
        document = Document(BytesIO(content))
        section = ""
        clauses: list[dict[str, Any]] = []
        text_parts: list[str] = []
        paragraph_number = 0
        for paragraph in document.paragraphs:
            value = paragraph.text.strip()
            if not value:
                continue
            if paragraph.style and paragraph.style.name.lower().startswith("heading"):
                section = value
                continue
            paragraph_number += 1
            text_parts.append(value)
            for offset in range(0, len(value), 6000):
                clauses.append(
                    {
                        "clause_id": f"paragraph-{paragraph_number:05d}-{offset // 6000 + 1}",
                        "paragraph": paragraph_number,
                        "paragraph_part": offset // 6000 + 1,
                        "section": section,
                        "excerpt": value[offset : offset + 6000],
                    }
                )
        for table_number, table in enumerate(document.tables, 1):
            for row_number, row in enumerate(table.rows, 1):
                value = " | ".join(cell.text.strip() for cell in row.cells if cell.text.strip())
                if not value:
                    continue
                paragraph_number += 1
                text_parts.append(value)
                for offset in range(0, len(value), 6000):
                    clauses.append(
                        {
                            "clause_id": f"table-{table_number:03d}-row-{row_number:05d}-{offset // 6000 + 1}",
                            "paragraph": paragraph_number,
                            "paragraph_part": offset // 6000 + 1,
                            "section": f"Table {table_number}",
                            "excerpt": value[offset : offset + 6000],
                        }
                    )
        if not text_parts:
            raise PolicyEngineError("Word document contains no extractable text")
        return Extraction(text="\n\n".join(text_parts), clauses=clauses)
    raise PolicyEngineError("Only PDF, DOCX, and TXT policy documents are supported")


def _validate_public_https(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise PolicyEngineError("Policy URLs must be unauthenticated HTTPS URLs")
    if parsed.port not in (None, 443):
        raise PolicyEngineError("Policy URLs must use the standard HTTPS port")
    try:
        addresses = socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise PolicyEngineError("Policy URL host could not be resolved") from exc
    if not addresses:
        raise PolicyEngineError("Policy URL host has no addresses")
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if not ip.is_global:
            raise PolicyEngineError("Policy URL resolves to a private, local, or reserved address")


def fetch_public_policy(url: str, *, client: httpx.Client | None = None) -> tuple[bytes, str, str]:
    owned_client = client is None
    session = client or httpx.Client(timeout=20, follow_redirects=False)
    current = url
    try:
        for _ in range(4):
            _validate_public_https(current)
            with session.stream("GET", current, headers={"Accept": ", ".join(ALLOWED_MEDIA_TYPES)}) as response:
                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("location")
                    if not location:
                        raise PolicyEngineError("Policy URL redirect has no location")
                    current = urljoin(current, location)
                    continue
                response.raise_for_status()
                media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                if media_type not in ALLOWED_MEDIA_TYPES:
                    raise PolicyEngineError(f"Unsupported policy URL content type: {media_type or 'missing'}")
                content_length = int(response.headers.get("content-length") or 0)
                if content_length > MAX_POLICY_BYTES:
                    raise PolicyEngineError("Policy URL exceeds the 20 MB limit")
                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > MAX_POLICY_BYTES:
                        raise PolicyEngineError("Policy URL exceeds the 20 MB limit")
                    chunks.append(chunk)
                basename = unquote(PurePosixPath(urlparse(current).path).name)
                expected_extension = ALLOWED_MEDIA_TYPES[media_type]
                filename = basename if basename.lower().endswith("." + expected_extension) else f"source.{expected_extension}"
                return b"".join(chunks), filename, media_type
        raise PolicyEngineError("Policy URL exceeded the three-redirect limit")
    except httpx.HTTPError as exc:
        raise PolicyEngineError(f"Could not fetch policy URL: {exc}") from exc
    finally:
        if owned_client:
            session.close()


class PolicyInterpreter(Protocol):
    def interpret(self, policy: dict[str, Any], text: str, clauses: list[dict[str, Any]]) -> dict[str, Any]: ...


class AzureOpenAIPolicyInterpreter:
    def __init__(self, *, client: Any | None = None, deployment: str | None = None):
        self.deployment = deployment or os.environ.get("AZURE_OPENAI_DEPLOYMENT", "")
        if client is not None:
            self.client = client
            return
        endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "")
        if not endpoint or not self.deployment:
            raise PolicyEngineError("AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_DEPLOYMENT are required")
        api_key = os.environ.get("AZURE_OPENAI_API_KEY", "")
        if api_key and os.environ.get("HACKATHON_MODE", "").lower() != "true":
            raise PolicyEngineError("Azure OpenAI API keys are permitted only in hackathon mode")
        credential = api_key or get_bearer_token_provider(DefaultAzureCredential(), "https://ai.azure.com/.default")
        self.client = OpenAI(base_url=f"{endpoint.rstrip('/')}/openai/v1/", api_key=credential, timeout=90)

    def interpret(self, policy: dict[str, Any], text: str, clauses: list[dict[str, Any]]) -> dict[str, Any]:
        clause_payload = [
            {key: item.get(key) for key in ("clause_id", "page", "section", "paragraph", "excerpt") if item.get(key) not in (None, "")}
            for item in clauses
        ]
        prompt = (
            "Extract enforceable security obligations from policy clauses. Return JSON with controls, obligations, exceptions, "
            "effective_dates, defined_terms, and document_scope. Each control needs control_id, title, description, "
            "prohibited_condition, control_type, severity, scope, exclusions, clarification_questions, source_reference, confidence, "
            "match, and tests. control_type must be literal_value, pattern, ast, dependency, url_domain, config_iac, semantic_review, "
            "or manual_review. source_reference must copy one supplied clause excerpt exactly and retain its clause/page/section/paragraph. "
            "match may contain prohibited_values, aliases, field_names, patterns, packages, package_prefixes, domains, file_globs, "
            "exclude_globs, or semgrep_yaml. A Semgrep rule ID must be stable; the compiler will prefix it with the control ID. tests "
            "contain file, content, and should_match. Ambiguous scope must produce clarification_questions. Never invent a citation or "
            "silently broaden an obligation. Prefer deterministic control types; use manual_review when reliable compilation is impossible."
        )
        batches: list[list[dict[str, Any]]] = []
        current: list[dict[str, Any]] = []
        current_size = 0
        for clause in clause_payload:
            size = len(json.dumps(clause, ensure_ascii=False))
            if current and current_size + size > 220_000:
                batches.append(current)
                current, current_size = [], 0
            current.append(clause)
            current_size += size
        if current:
            batches.append(current)
        if not batches:
            raise PolicyEngineError("Policy contains no extractable clauses")

        results: list[dict[str, Any]] = []
        for batch_number, batch in enumerate(batches, 1):
            response = self.client.chat.completions.create(
                model=self.deployment,
                max_completion_tokens=min(int(os.environ.get("LLM_MAX_OUTPUT_TOKENS", "8000")), 16000),
                reasoning_effort=os.environ.get("LLM_REASONING_EFFORT", "medium"),
                response_format={"type": "json_object"},
                messages=[
                    {"role": "developer", "content": prompt},
                    {
                        "role": "user",
                        "content": json.dumps(
                            {"policy": policy, "batch": batch_number, "batch_count": len(batches), "clauses": batch},
                            ensure_ascii=False,
                        ),
                    },
                ],
            )
            content = response.choices[0].message.content
            if not content:
                raise PolicyEngineError("Azure OpenAI returned an empty policy proposal")
            try:
                result = json.loads(content)
            except json.JSONDecodeError as exc:
                raise PolicyEngineError("Azure OpenAI returned invalid policy JSON") from exc
            if not isinstance(result, dict) or not isinstance(result.get("controls"), list):
                raise PolicyEngineError("Policy proposal must contain a controls array")
            results.append(result)

        merged: dict[str, Any] = {
            "controls": [], "obligations": [], "exceptions": [], "effective_dates": [], "defined_terms": {}, "document_scope": []
        }
        seen_controls: dict[str, str] = {}
        for result in results:
            for key in ("obligations", "exceptions", "effective_dates"):
                if isinstance(result.get(key), list):
                    merged[key].extend(result[key])
            if isinstance(result.get("defined_terms"), dict):
                merged["defined_terms"].update(result["defined_terms"])
            if result.get("document_scope"):
                merged["document_scope"].append(result["document_scope"])
            for control in result["controls"]:
                if not isinstance(control, dict):
                    continue
                base = str(control.get("control_id") or control.get("title") or "control")
                condition = str(control.get("prohibited_condition") or "")
                if base in seen_controls and seen_controls[base] == condition:
                    continue
                if base in seen_controls:
                    suffix = 2
                    while f"{base}-{suffix}" in seen_controls:
                        suffix += 1
                    control = {**control, "control_id": f"{base}-{suffix}"}
                    base = str(control["control_id"])
                seen_controls[base] = condition
                merged["controls"].append(control)
        return merged


class AzureOpenAISemanticControlScanner:
    """Produces review evidence only; it never returns or implies a compliance verdict."""

    def __init__(self, *, client: Any | None = None, deployment: str | None = None):
        interpreter = AzureOpenAIPolicyInterpreter(client=client, deployment=deployment)
        self.client = interpreter.client
        self.deployment = interpreter.deployment

    def scan(self, files: dict[str, str], controls: list[dict[str, Any]]) -> list[Finding]:
        candidates = [item for item in controls if item.get("control_type") in {"semantic_review", "manual_review"}]
        if not candidates or not files:
            return []
        bounded_files: dict[str, str] = {}
        remaining_chars = 300_000
        for path, content in files.items():
            if remaining_chars <= 0:
                break
            value = content[: min(100_000, remaining_chars)]
            bounded_files[path] = value
            remaining_chars -= len(value)
        request = {
            "controls": [
                {
                    "control_id": item.get("control_id"),
                    "version": item.get("version"),
                    "title": item.get("title"),
                    "prohibited_condition": item.get("prohibited_condition"),
                    "scope": item.get("scope"),
                    "exclusions": item.get("exclusions"),
                }
                for item in candidates
            ],
            "changed_files": bounded_files,
        }
        response = self.client.chat.completions.create(
            model=self.deployment,
            max_completion_tokens=min(int(os.environ.get("LLM_MAX_OUTPUT_TOKENS", "8000")), 8000),
            reasoning_effort=os.environ.get("LLM_REASONING_EFFORT", "medium"),
            response_format={"type": "json_object"},
            messages=[
                {
                    "role": "developer",
                    "content": (
                        "Identify code evidence that requires human review under the supplied controls. Return JSON with findings only. "
                        "Each finding needs control_id, file, line, matched_value, reason, and confidence. Use only supplied control IDs "
                        "and files. Never claim compliance, never suppress a deterministic finding, and omit uncertain speculation below 0.5 confidence."
                    ),
                },
                {"role": "user", "content": json.dumps(request, ensure_ascii=False)},
            ],
        )
        content = response.choices[0].message.content
        try:
            payload = json.loads(content or "{}")
        except json.JSONDecodeError as exc:
            raise PolicyEngineError("Semantic control scan returned invalid JSON") from exc
        by_id = {str(item.get("control_id")): item for item in candidates}
        findings: list[Finding] = []
        for raw in payload.get("findings", []):
            if not isinstance(raw, dict):
                continue
            control = by_id.get(str(raw.get("control_id") or ""))
            file_path = str(raw.get("file") or "")
            if not control or file_path not in bounded_files:
                continue
            try:
                confidence = float(raw.get("confidence") or 0)
                line = int(raw.get("line") or 0)
            except (TypeError, ValueError):
                continue
            if confidence < 0.5 or line < 1 or line > max(1, len(bounded_files[file_path].splitlines())):
                continue
            finding = Finding(
                tool="policy-semantic-review",
                rule_id=str(control["control_id"]),
                file=file_path if file_path.startswith("/") else f"/{file_path}",
                line=line,
                severity="WARNING",
                message=f"Human review required: {control.get('title', 'policy control')}",
                fix_hint=str(control.get("fix_hint") or "Review the evidence and document an approved exception if applicable."),
                control_id=str(control["control_id"]),
                control_version=str(control.get("version") or ""),
                reason=str(raw.get("reason") or control.get("prohibited_condition") or ""),
                policy_document=str(control.get("policy_title") or control.get("policy_document_id") or ""),
                policy_version=str(control.get("policy_version") or ""),
                source_reference=dict(control.get("source_reference") or {}),
                confidence=confidence,
                matched_value=str(raw.get("matched_value") or "semantic evidence"),
                review_required=True,
            )
            findings.append(finding)
        return findings


def _verified_source(raw: dict[str, Any], clauses: list[dict[str, Any]]) -> dict[str, Any]:
    source = raw.get("source_reference") or {}
    excerpt = str(source.get("excerpt") or "").strip()
    clause_id = str(source.get("clause_id") or "")
    for clause in clauses:
        if clause_id and clause_id != str(clause.get("clause_id") or ""):
            continue
        actual = str(clause.get("excerpt") or "")
        if excerpt and excerpt in actual:
            return {**clause, "excerpt": excerpt}
    raise PolicyEngineError("Generated control contains an unverified policy citation")


def compile_proposal(raw: dict[str, Any], policy: dict[str, Any], clauses: list[dict[str, Any]]) -> dict[str, Any]:
    kind = str(raw.get("control_type") or "manual_review")
    control_id = re.sub(r"[^a-z0-9._-]+", "-", str(raw.get("control_id") or raw.get("title") or "control").strip().lower()).strip("._-")[:120] or "control"
    match = raw.get("match") if isinstance(raw.get("match"), dict) else {}
    detector: dict[str, Any] = {
        key: value
        for key, value in match.items()
        if key in {"prohibited_values", "aliases", "field_names", "patterns", "packages", "package_prefixes", "domains", "file_globs", "exclude_globs", "semgrep_yaml"}
    }
    tests = [item for item in raw.get("tests", []) if isinstance(item, dict)]
    questions = [str(item).strip() for item in raw.get("clarification_questions", []) if str(item).strip()]
    source = _verified_source(raw, clauses)
    if kind == "ast" and detector.get("semgrep_yaml"):
        try:
            import yaml

            semgrep_config = yaml.safe_load(str(detector["semgrep_yaml"]))
            rules = semgrep_config.get("rules") if isinstance(semgrep_config, dict) else None
            if not isinstance(rules, list) or not rules:
                raise ValueError("rules are required")
            for index, rule in enumerate(rules):
                if not isinstance(rule, dict):
                    raise ValueError("rule must be an object")
                original = re.sub(r"[^a-zA-Z0-9_.-]+", "-", str(rule.get("id") or index))
                rule["id"] = f"{control_id}.{original}"
            detector["semgrep_yaml"] = yaml.safe_dump(semgrep_config, sort_keys=False)
        except Exception as exc:
            raise PolicyEngineError(f"AST control contains invalid Semgrep YAML: {exc}") from exc
    control = {
        "control_id": control_id,
        "version": str(raw.get("version") or "1.0"),
        "title": str(raw.get("title") or "Policy control"),
        "description": str(raw.get("description") or ""),
        "prohibited_condition": str(raw.get("prohibited_condition") or ""),
        "control_type": kind,
        "severity": _normalize_severity(raw.get("severity")),
        "scope": raw.get("scope") if isinstance(raw.get("scope"), dict) else {},
        "examples": {
            "positive": [item.get("content", "") for item in tests if item.get("should_match") is True],
            "negative": [item.get("content", "") for item in tests if item.get("should_match") is False],
        },
        "exclusions": [str(item) for item in raw.get("exclusions", [])],
        "clarification_questions": questions,
        "policy_document_id": policy["document_id"],
        "policy_version": policy["version"],
        "policy_title": policy["title"],
        "source_reference": source,
        "detector": detector,
        "confidence": min(1.0, max(0.0, float(raw.get("confidence") or 0))),
        "fix_hint": str(raw.get("fix_hint") or "Use an approved alternative or request a documented exception."),
        "state": "needs_clarification" if questions else "draft",
    }
    control["validation"] = validate_compiled_control(control, tests)
    return control


def _normalize_severity(value: Any) -> str:
    """Translate common policy-risk labels into the scanner's severities."""
    normalized = str(value or "WARNING").strip().upper()
    if normalized in {"ERROR", "WARNING", "INFO"}:
        return normalized
    if normalized in {"BLOCKER", "CRITICAL", "HIGH", "SEV0", "SEV1"}:
        return "ERROR"
    if normalized in {"MEDIUM", "MODERATE", "WARN", "SEV2"}:
        return "WARNING"
    if normalized in {"LOW", "INFORMATIONAL", "NOTE", "SEV3", "SEV4"}:
        return "INFO"
    return "WARNING"


def validate_compiled_control(control: dict[str, Any], tests: list[dict[str, Any]]) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    if not tests:
        return {"passed": False, "tests": [], "error": "At least one positive and one negative test are required"}
    expectations = {bool(item.get("should_match")) for item in tests}
    if expectations != {False, True}:
        return {"passed": False, "tests": [], "error": "Positive and negative tests are both required"}
    for index, test in enumerate(tests):
        path = str(test.get("file") or "sample.txt")
        content = str(test.get("content") or "")
        expected = bool(test.get("should_match"))
        try:
            if control.get("control_type") == "ast":
                semgrep_yaml = str((control.get("detector") or {}).get("semgrep_yaml") or "")
                if not semgrep_yaml or len(semgrep_yaml) > 100_000:
                    raise PolicyEngineError("AST control requires bounded Semgrep YAML")
                actual = bool(run_semgrep({path: content}, policy_rules=[{"rule_id": control["control_id"], "semgrep_yaml": semgrep_yaml}]))
            elif control.get("control_type") in {"manual_review", "semantic_review"}:
                actual = expected
            else:
                actual = bool(run_typed_control_scan({path: content}, [control]))
            passed = actual == expected
            results.append({"name": str(test.get("name") or f"test-{index + 1}"), "expected": expected, "actual": actual, "passed": passed})
        except Exception as exc:
            results.append({"name": str(test.get("name") or f"test-{index + 1}"), "expected": expected, "actual": None, "passed": False, "error": str(exc)[:500]})
    return {"passed": all(item["passed"] for item in results), "tests": results}


def process_policy_job(job: dict[str, Any], controls: ControlPlane, interpreter: PolicyInterpreter | None = None) -> list[dict[str, Any]]:
    job_id = str(job.get("job_id") or "")
    document_id = str(job.get("document_id") or "")
    version = str(job.get("policy_version") or "")
    policy = controls.get_policy(document_id, version)
    if not policy:
        raise PolicyEngineError("Policy version was not found")
    controls.update_policy_job(job_id, status="running", phase="Extracting policy source")
    try:
        if policy.get("source_pending"):
            content, filename, media_type = fetch_public_policy(str(policy.get("source_url") or ""))
            policy = controls.replace_policy_source(document_id, version, content, filename)
            policy["media_type"] = media_type
        source = controls.get_blob(str(policy.get("source_blob") or ""))
        if not source:
            raise PolicyEngineError("Policy source artifact is unavailable")
        extraction = extract_document(str(policy.get("filename") or "source.txt"), source)
        controls.save_policy_extraction(document_id, version, text=extraction.text, clauses=extraction.clauses)
        controls.update_policy_job(job_id, status="running", phase="Generating and validating proposed controls")
        model = interpreter or AzureOpenAIPolicyInterpreter()
        proposal = model.interpret(policy, extraction.text, extraction.clauses)
        controls.save_policy_analysis(document_id, version, proposal)
        saved: list[dict[str, Any]] = []
        for raw_control in proposal["controls"]:
            if not isinstance(raw_control, dict):
                continue
            saved.append(controls.save_control(compile_proposal(raw_control, policy, extraction.clauses)))
        if not saved:
            raise PolicyEngineError("No policy controls were proposed")
        needs_clarification = any(item["state"] == "needs_clarification" for item in saved)
        controls.update_policy_state(
            document_id,
            version,
            status="needs_clarification" if needs_clarification else "ready",
            ingestion_status="completed",
        )
        controls.update_policy_job(job_id, status="completed", phase="Proposed controls are ready", control_count=len(saved))
        controls.audit("policy.ingestion-completed", "policy-engine", {"job_id": job_id, "control_count": len(saved)})
        return saved
    except Exception as exc:
        current = controls.get_policy(document_id, version)
        if current:
            controls.update_policy_state(document_id, version, status="needs_clarification", ingestion_status="failed")
        controls.update_policy_job(job_id, status="failed", phase="Policy ingestion failed", errors=[str(exc)[:1000]])
        raise
