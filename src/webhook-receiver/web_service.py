"""Scale-to-zero HTTP gateway for the webhook and admin control portal.

This reuses the Function-oriented business handlers so the hosted control plane
remains compatible with the local Functions project.  It exists as a reliable
fallback for the hackathon's Linux Consumption Functions deployment issue.
"""

from __future__ import annotations

import os
import secrets
from typing import Callable

import azure.functions as func
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response

from admin import (
    audit_events,
    control_action,
    controls,
    dashboard,
    exception_action,
    exceptions,
    policies,
    policy_job,
    portal,
    regulation,
    regulation_search,
    repository,
    rerun,
    rule_pack,
    settings,
)
from app import handler

api = FastAPI(title="PR Security Control", docs_url=None, redoc_url=None, openapi_url=None)


def _require_access(request: Request) -> None:
    expected = os.environ.get("ADMIN_ACCESS_KEY", "")
    provided = request.query_params.get("code", "")
    if not expected:
        raise HTTPException(status_code=503, detail="Gateway access key is not configured.")
    if not provided or not secrets.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Unauthorized")


async def _function_request(request: Request) -> func.HttpRequest:
    body = await request.body()
    return func.HttpRequest(
        method=request.method,
        url=str(request.url),
        headers=dict(request.headers),
        params=dict(request.query_params),
        route_params={},
        body=body,
    )


def _response(value: func.HttpResponse) -> Response:
    headers = dict(value.headers)
    return Response(
        content=value.get_body(),
        status_code=value.status_code,
        media_type=value.mimetype,
        headers=headers,
    )


@api.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@api.post("/api/webhook")
async def webhook(request: Request) -> Response:
    _require_access(request)
    result = handler(await request.body())
    return Response(content=result["body"], status_code=result["status"], media_type="text/plain")


@api.get("/api/admin")
@api.get("/api/admin/")
async def admin_portal(request: Request) -> Response:
    _require_access(request)
    return _response(portal(await _function_request(request)))


_ADMIN_ENDPOINTS: dict[str, Callable[[func.HttpRequest], func.HttpResponse]] = {
    "audit": audit_events,
    "dashboard": dashboard,
    "settings": settings,
    "repository": repository,
    "rule-pack": rule_pack,
    "regulation": regulation,
    "regulation-search": regulation_search,
    "rerun": rerun,
    "policies": policies,
    "policy-job": policy_job,
    "controls": controls,
    "control-action": control_action,
    "exceptions": exceptions,
    "exception-action": exception_action,
}


@api.api_route("/api/admin/api/{endpoint}", methods=["GET", "POST"])
async def admin_api(endpoint: str, request: Request) -> Response:
    _require_access(request)
    handler_fn = _ADMIN_ENDPOINTS.get(endpoint)
    if handler_fn is None:
        raise HTTPException(status_code=404, detail="Not Found")
    return _response(handler_fn(await _function_request(request)))
