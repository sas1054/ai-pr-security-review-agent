"""Identity-aware admin control plane for the policy portal.

The route is deliberately separate from the webhook business handler. Hosted
deployments use Microsoft Entra authentication and role claims; a shared-key
fallback remains available for local development only.
"""

from __future__ import annotations

import json
import logging
import base64
import os
import uuid
from pathlib import Path
from typing import Any

import azure.functions as func

from app import queue_policy_job, queue_review_job
from prsa_control import get_control_plane
from scanner import run_typed_control_scan

logger = logging.getLogger(__name__)
PORTAL_FILE = Path(__file__).with_name("admin_portal.html")
PORTAL_ROLES = {
    "Policy.Admin",
    "Policy.Author",
    "Policy.Approver",
    "Policy.Activator",
    "Exception.Approver",
}


def _actor(req: func.HttpRequest) -> str:
    """Use platform identity headers when present; the hackathon fallback is auditable."""
    identity = req.headers.get("X-MS-CLIENT-PRINCIPAL-NAME", "").strip()
    if not identity and req.headers.get("X-MS-CLIENT-PRINCIPAL"):
        try:
            encoded = req.headers["X-MS-CLIENT-PRINCIPAL"]
            principal = json.loads(base64.b64decode(encoded + "=" * (-len(encoded) % 4)))
            identity = str(principal.get("user_details") or principal.get("userDetails") or "").strip()
        except (ValueError, json.JSONDecodeError):
            identity = ""
    if os.environ.get("ADMIN_REQUIRE_ENTRA", "false").lower() == "true" and not identity:
        raise PermissionError("Microsoft Entra authentication is required")
    return identity or "function-key-admin"


def _roles(req: func.HttpRequest) -> set[str]:
    encoded = req.headers.get("X-MS-CLIENT-PRINCIPAL", "")
    if not encoded:
        return set()
    try:
        payload = json.loads(base64.b64decode(encoded + "=" * (-len(encoded) % 4)))
    except (ValueError, json.JSONDecodeError):
        return set()
    roles: set[str] = set()
    for claim in payload.get("claims", []):
        if not isinstance(claim, dict):
            continue
        claim_type = str(claim.get("typ") or claim.get("type") or "")
        if claim_type in {"roles", "role", "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"}:
            roles.add(str(claim.get("val") or claim.get("value") or ""))
    return roles


def _authorize(req: func.HttpRequest, required_role: str) -> str:
    actor = _actor(req)
    if os.environ.get("ADMIN_REQUIRE_ENTRA", "false").lower() != "true":
        return actor
    roles = _roles(req)
    if required_role not in roles and "Policy.Admin" not in roles:
        raise PermissionError(f"The {required_role} role is required")
    return actor


def authorize_portal(req: func.HttpRequest) -> str:
    """Require a portal role when Entra is enabled, without affecting local key mode."""
    actor = _actor(req)
    if os.environ.get("ADMIN_REQUIRE_ENTRA", "false").lower() == "true" and not (_roles(req) & PORTAL_ROLES):
        raise PermissionError("A PR Security Control portal role is required")
    return actor


def _json_response(value: dict[str, Any], status: int = 200) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps(value, ensure_ascii=False, default=str),
        status_code=status,
        mimetype="application/json",
        headers={"Cache-Control": "no-store"},
    )


def _body(req: func.HttpRequest) -> dict[str, Any]:
    try:
        value = req.get_json()
    except ValueError as exc:
        raise ValueError("A JSON request body is required") from exc
    if not isinstance(value, dict):
        raise ValueError("The JSON body must be an object")
    return value


def portal(req: func.HttpRequest) -> func.HttpResponse:
    authorize_portal(req)
    return func.HttpResponse(
        PORTAL_FILE.read_text(encoding="utf-8"),
        status_code=200,
        mimetype="text/html",
        headers={"Cache-Control": "no-store"},
    )


def dashboard(req: func.HttpRequest) -> func.HttpResponse:
    actor = authorize_portal(req)
    value = get_control_plane().dashboard()
    value["identity"] = {"name": actor, "roles": sorted(_roles(req))}
    return _json_response(value)


def settings(req: func.HttpRequest) -> func.HttpResponse:
    controls = get_control_plane()
    if req.method == "GET":
        return _json_response({"settings": controls.get_settings()})
    try:
        return _json_response({"settings": controls.update_settings(_body(req), actor=_actor(req))})
    except (TypeError, ValueError) as exc:
        return _json_response({"error": str(exc)}, 400)


def repository(req: func.HttpRequest) -> func.HttpResponse:
    try:
        return _json_response({"repository": get_control_plane().save_repository(_body(req), actor=_actor(req))})
    except (TypeError, ValueError) as exc:
        return _json_response({"error": str(exc)}, 400)


def rule_pack(req: func.HttpRequest) -> func.HttpResponse:
    try:
        return _json_response({"rule_pack": get_control_plane().save_rule_pack(_body(req), actor=_actor(req))})
    except (TypeError, ValueError) as exc:
        return _json_response({"error": str(exc)}, 400)


def regulation(req: func.HttpRequest) -> func.HttpResponse:
    try:
        return _json_response({"regulation": get_control_plane().save_regulation(_body(req), actor=_actor(req))})
    except (TypeError, ValueError) as exc:
        return _json_response({"error": str(exc)}, 400)


def regulation_search(req: func.HttpRequest) -> func.HttpResponse:
    query = str(req.params.get("q") or "")
    return _json_response({"results": get_control_plane().search_regulations(query)})


def rerun(req: func.HttpRequest) -> func.HttpResponse:
    try:
        run_id = str(_body(req).get("run_id") or "")
        review = get_control_plane().get_review(run_id)
        if not review or not isinstance(review.get("job"), dict):
            return _json_response({"error": "Review run was not found or cannot be replayed."}, 404)
        job = dict(review["job"])
        job["event_id"] = f"manual-rerun:{run_id}:{uuid.uuid4()}"
        job["event_type"] = "git.pullrequest.manual-rerun"
        queued = queue_review_job(job)
        get_control_plane().audit("review.rerun-requested", _actor(req), {"run_id": run_id})
        return _json_response({"status": queued["status"], "run_id": queued["run_id"], "source_run_id": run_id}, 202)
    except (TypeError, ValueError) as exc:
        return _json_response({"error": str(exc)}, 400)
    except Exception as exc:
        logger.exception("Could not enqueue manual review rerun")
        return _json_response({"error": f"Could not queue rerun: {exc}"}, 503)


def policies(req: func.HttpRequest) -> func.HttpResponse:
    controls = get_control_plane()
    if req.method == "GET":
        document_id = str(req.params.get("id") or "")
        version = str(req.params.get("version") or "")
        if document_id and version:
            policy = controls.get_policy(document_id, version)
            if not policy:
                return _json_response({"error": "Policy version was not found"}, 404)
            related = [
                item for item in controls.list_controls()
                if item.get("policy_document_id") == policy["document_id"] and item.get("policy_version") == version
            ]
            return _json_response(
                {
                    "policy": policy,
                    "clauses": controls.list_policy_clauses(document_id, version),
                    "analysis": controls.get_policy_analysis(document_id, version),
                    "controls": related,
                }
            )
        return _json_response({"policies": controls.list_policies()})
    try:
        if not controls.get_settings().get("policy_ingestion_enabled", True):
            return _json_response({"error": "Policy ingestion is disabled by an administrator"}, 503)
        raw = _body(req)
        mode = str(raw.get("input_type") or "paste")
        actor = _authorize(req, "Policy.Author")
        if mode == "url":
            policy = controls.save_policy_reference(raw, actor=actor)
        elif mode == "paste":
            value = dict(raw)
            value.setdefault("filename", "policy.txt")
            value.setdefault("media_type", "text/plain")
            policy = controls.save_policy_document(value, str(raw.get("content") or ""), actor=actor)
        elif mode == "upload":
            encoded = str(raw.get("content_base64") or "")
            try:
                content = base64.b64decode(encoded, validate=True)
            except ValueError as exc:
                raise ValueError("content_base64 is invalid") from exc
            policy = controls.save_policy_document(raw, content, actor=actor)
        else:
            raise ValueError("input_type must be paste, upload, or url")
        job = queue_policy_job(policy["document_id"], policy["version"], actor=actor, controls=controls)
        return _json_response({"policy": policy, "job": job}, 202)
    except PermissionError as exc:
        return _json_response({"error": str(exc)}, 401)
    except (TypeError, ValueError) as exc:
        return _json_response({"error": str(exc)}, 400)
    except Exception as exc:
        logger.exception("Could not queue policy ingestion")
        return _json_response({"error": f"Could not queue policy ingestion: {exc}"}, 503)


def policy_job(req: func.HttpRequest) -> func.HttpResponse:
    if req.method == "POST":
        try:
            raw = _body(req)
            document_id = str(raw.get("document_id") or "")
            version = str(raw.get("version") or raw.get("policy_version") or "")
            actor = _authorize(req, "Policy.Author")
            plane = get_control_plane()
            policy = plane.get_policy(document_id, version)
            if not policy:
                return _json_response({"error": "Policy version was not found"}, 404)
            existing_controls = [
                item
                for item in plane.list_controls()
                if item.get("policy_document_id") == policy["document_id"] and item.get("policy_version") == version
            ]
            if existing_controls:
                return _json_response(
                    {"error": "Policy already has generated controls; create a new immutable policy version to regenerate them"},
                    409,
                )
            value = queue_policy_job(policy["document_id"], version, actor=actor, controls=plane)
            return _json_response({"job": value}, 202)
        except PermissionError as exc:
            return _json_response({"error": str(exc)}, 401)
        except (TypeError, ValueError) as exc:
            return _json_response({"error": str(exc)}, 400)
    job_id = str(req.params.get("id") or "")
    value = get_control_plane().get_policy_job(job_id)
    return _json_response({"job": value}, 200 if value else 404)


def _author_deterministic_control(raw: dict[str, Any], *, actor: str) -> dict[str, Any]:
    """Create an immutable deterministic control only after executing its tests."""
    plane = get_control_plane()
    for field in ("control_id", "version", "title", "prohibited_condition"):
        if not str(raw.get(field) or "").strip():
            raise ValueError(f"{field} is required")
    if not isinstance(raw.get("detector"), dict):
        raise ValueError("detector must be an object")
    if raw.get("scope") is not None and not isinstance(raw.get("scope"), dict):
        raise ValueError("scope must be an object")
    document_id = str(raw.get("policy_document_id") or "")
    policy_version = str(raw.get("policy_version") or "")
    policy = plane.get_policy(document_id, policy_version)
    if not policy:
        raise ValueError("policy version was not found")
    control_type = str(raw.get("control_type") or "")
    supported = {"literal_value", "config_iac", "url_domain", "dependency"}
    if control_type not in supported:
        raise ValueError("authored controls must use a deterministic supported control type")
    source = raw.get("source_reference") if isinstance(raw.get("source_reference"), dict) else {}
    clause_id = str(source.get("clause_id") or "")
    excerpt = str(source.get("excerpt") or "").strip()
    clause = next(
        (item for item in plane.list_policy_clauses(document_id, policy_version) if item.get("clause_id") == clause_id),
        None,
    )
    if not clause or not excerpt or excerpt not in str(clause.get("excerpt") or ""):
        raise ValueError("source_reference must quote an exact excerpt from the stored policy clause")
    analysis = plane.get_policy_analysis(document_id, policy_version)
    obligation_ids = {
        str(item.get("obligation_id") or "")
        for item in analysis.get("obligations", [])
        if isinstance(item, dict) and item.get("obligation_id")
    }
    linked_obligations = [str(item) for item in raw.get("obligation_ids", []) if str(item) in obligation_ids]
    if not linked_obligations and len(obligation_ids) == 1:
        linked_obligations = list(obligation_ids)
    if obligation_ids and not linked_obligations:
        raise ValueError("obligation_ids must link the control to a stored policy obligation")
    surface_by_type = {
        "literal_value": ["source_literals"],
        "config_iac": ["configuration_iac"],
        "url_domain": ["service_endpoints"],
        "dependency": ["dependencies"],
    }
    tests = [item for item in raw.get("tests", []) if isinstance(item, dict)]
    if len(tests) > 50 or sum(len(str(item.get("content") or "")) for item in tests) > 2 * 1024 * 1024:
        raise ValueError("control tests exceed the bounded validation budget")
    expectations = {bool(item.get("should_match")) for item in tests}
    if expectations != {False, True}:
        raise ValueError("at least one positive and one negative test are required")
    candidate = {
        **raw,
        "policy_document_id": policy["document_id"],
        "policy_version": policy["version"],
        "policy_title": policy["title"],
        "source_reference": {**clause, "excerpt": excerpt},
        "obligation_ids": linked_obligations,
        "detection_surfaces": surface_by_type[control_type],
        "state": "draft",
    }
    results: list[dict[str, Any]] = []
    for index, test in enumerate(tests):
        filename = str(test.get("file") or f"control-test-{index + 1}.txt")
        content = str(test.get("content") or "")
        expected = bool(test.get("should_match"))
        actual = bool(run_typed_control_scan({filename: content}, [candidate]))
        results.append(
            {
                "name": str(test.get("name") or f"test-{index + 1}"),
                "expected": expected,
                "actual": actual,
                "passed": actual == expected,
            }
        )
    if not all(item["passed"] for item in results):
        raise ValueError(f"control validation failed: {json.dumps(results)}")
    candidate["validation"] = {"passed": True, "tests": results}
    candidate["examples"] = {
        "positive": [str(item.get("content") or "") for item in tests if item.get("should_match") is True],
        "negative": [str(item.get("content") or "") for item in tests if item.get("should_match") is False],
    }
    saved = plane.save_control(candidate, actor=actor)
    plane.reconcile_policy_coverage(policy["document_id"], policy["version"], actor=actor)
    return saved


def controls(req: func.HttpRequest) -> func.HttpResponse:
    if req.method == "GET":
        return _json_response({"controls": get_control_plane().list_controls()})
    try:
        value = _author_deterministic_control(_body(req), actor=_authorize(req, "Policy.Author"))
        return _json_response({"control": value}, 201)
    except PermissionError as exc:
        return _json_response({"error": str(exc)}, 401)
    except (TypeError, ValueError) as exc:
        return _json_response({"error": str(exc)}, 400)


def control_action(req: func.HttpRequest) -> func.HttpResponse:
    try:
        raw = _body(req)
        action = str(raw.get("action") or "")
        control_id = str(raw.get("control_id") or "")
        version = str(raw.get("version") or "")
        role = "Policy.Approver" if action == "approve" else "Policy.Activator" if action in {"activate", "suspend", "retire"} else "Policy.Author"
        actor = _authorize(req, role)
        plane = get_control_plane()
        if action == "approve":
            approval = plane.approve_control(control_id, version, actor=actor, notes=str(raw.get("notes") or ""))
            return _json_response({"approval": approval, "control": plane.get_control(control_id, version)})
        if action == "clarify":
            value = plane.answer_control_clarifications(control_id, version, raw.get("answers") or [], actor=actor)
            return _json_response({"control": value})
        if action == "revise":
            value = plane.revise_control(control_id, version, raw, actor=actor)
            return _json_response({"control": value}, 201)
        if action in {"activate", "suspend", "retire"}:
            target = {"activate": "active", "suspend": "suspended", "retire": "retired"}[action]
            value = plane.transition_control(
                control_id,
                version,
                target,
                actor=actor,
                expected_revision=int(raw["expected_revision"]) if raw.get("expected_revision") is not None else None,
            )
            return _json_response({"control": value})
        raise ValueError("action must be clarify, revise, approve, activate, suspend, or retire")
    except PermissionError as exc:
        return _json_response({"error": str(exc)}, 401)
    except (TypeError, ValueError) as exc:
        return _json_response({"error": str(exc)}, 400)


def exceptions(req: func.HttpRequest) -> func.HttpResponse:
    plane = get_control_plane()
    if req.method == "GET":
        return _json_response({"exceptions": plane.list_exceptions()})
    try:
        value = plane.save_exception(_body(req), actor=_authorize(req, "Exception.Approver"))
        return _json_response({"exception": value}, 201)
    except PermissionError as exc:
        return _json_response({"error": str(exc)}, 401)
    except (TypeError, ValueError) as exc:
        return _json_response({"error": str(exc)}, 400)


def exception_action(req: func.HttpRequest) -> func.HttpResponse:
    try:
        raw = _body(req)
        if raw.get("action") != "revoke":
            raise ValueError("action must be revoke")
        value = get_control_plane().revoke_exception(str(raw.get("exception_id") or ""), actor=_authorize(req, "Exception.Approver"))
        return _json_response({"exception": value})
    except PermissionError as exc:
        return _json_response({"error": str(exc)}, 401)
    except (TypeError, ValueError) as exc:
        return _json_response({"error": str(exc)}, 400)


def audit_events(req: func.HttpRequest) -> func.HttpResponse:
    try:
        limit = int(req.params.get("limit") or 100)
    except ValueError:
        return _json_response({"error": "limit must be an integer"}, 400)
    return _json_response({"events": get_control_plane().list_audit_events(limit)})
