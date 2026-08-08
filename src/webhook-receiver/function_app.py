"""
Azure Functions v2 app — HTTP trigger for Azure DevOps PR webhooks.
The Functions host rejects requests without a valid Function key before it
calls app.handler(), so Azure DevOps does not need unsupported HMAC signing.
"""

import logging

import azure.functions as func

# Azure Functions' Python v2 worker discovers this conventional module-level
# name in the deployed runtime.  Keep the conventional name even though the
# business HTTP application has its own ``app.py`` module.
app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)
logger = logging.getLogger(__name__)
_load_error = ""

try:
    from admin import (
        audit_events as admin_audit_events,
        control_action as admin_control_action,
        controls as admin_controls,
        dashboard as admin_dashboard,
        exception_action as admin_exception_action,
        exceptions as admin_exceptions,
        policies as admin_policies,
        policy_job as admin_policy_job,
        portal as admin_portal,
        regulation as admin_regulation,
        regulation_search as admin_regulation_search,
        repository as admin_repository,
        rerun as admin_rerun,
        rule_pack as admin_rule_pack,
        settings as admin_settings,
    )
    from app import handler
except Exception as exc:  # pragma: no cover - allows the host to surface a useful diagnostic
    _load_error = f"{type(exc).__name__}: {exc}"
    logger.exception("Function modules could not be loaded")


def _unavailable() -> func.HttpResponse:
    return func.HttpResponse(
        body="Function dependencies are not ready. Check /api/health with a Function key.",
        status_code=503,
        mimetype="text/plain",
    )


@app.route(route="health", methods=["GET"])
def health(_: func.HttpRequest) -> func.HttpResponse:
    if _load_error:
        return func.HttpResponse(body=_load_error, status_code=503, mimetype="text/plain")
    return func.HttpResponse(body="ok", status_code=200, mimetype="text/plain")


@app.route(route="webhook", methods=["POST"])
def webhook(req: func.HttpRequest) -> func.HttpResponse:
    if _load_error:
        return _unavailable()
    result = handler(
        request_body=req.get_body(),
    )
    return func.HttpResponse(
        body=result["body"],
        status_code=result["status"],
        mimetype="text/plain",
    )


@app.route(route="admin", methods=["GET"])
def admin(req: func.HttpRequest) -> func.HttpResponse:
    if _load_error:
        return _unavailable()
    return admin_portal(req)


@app.route(route="admin/api/dashboard", methods=["GET"])
def admin_dashboard_route(req: func.HttpRequest) -> func.HttpResponse:
    if _load_error:
        return _unavailable()
    return admin_dashboard(req)


@app.route(route="admin/api/settings", methods=["GET", "POST"])
def admin_settings_route(req: func.HttpRequest) -> func.HttpResponse:
    if _load_error:
        return _unavailable()
    return admin_settings(req)


@app.route(route="admin/api/repository", methods=["POST"])
def admin_repository_route(req: func.HttpRequest) -> func.HttpResponse:
    if _load_error:
        return _unavailable()
    return admin_repository(req)


@app.route(route="admin/api/rule-pack", methods=["POST"])
def admin_rule_pack_route(req: func.HttpRequest) -> func.HttpResponse:
    if _load_error:
        return _unavailable()
    return admin_rule_pack(req)


@app.route(route="admin/api/regulation", methods=["POST"])
def admin_regulation_route(req: func.HttpRequest) -> func.HttpResponse:
    if _load_error:
        return _unavailable()
    return admin_regulation(req)


@app.route(route="admin/api/regulation-search", methods=["GET"])
def admin_regulation_search_route(req: func.HttpRequest) -> func.HttpResponse:
    if _load_error:
        return _unavailable()
    return admin_regulation_search(req)


@app.route(route="admin/api/rerun", methods=["POST"])
def admin_rerun_route(req: func.HttpRequest) -> func.HttpResponse:
    if _load_error:
        return _unavailable()
    return admin_rerun(req)


@app.route(route="admin/api/policies", methods=["GET", "POST"])
def admin_policies_route(req: func.HttpRequest) -> func.HttpResponse:
    return _unavailable() if _load_error else admin_policies(req)


@app.route(route="admin/api/policy-job", methods=["GET", "POST"])
def admin_policy_job_route(req: func.HttpRequest) -> func.HttpResponse:
    return _unavailable() if _load_error else admin_policy_job(req)


@app.route(route="admin/api/controls", methods=["GET"])
def admin_controls_route(req: func.HttpRequest) -> func.HttpResponse:
    return _unavailable() if _load_error else admin_controls(req)


@app.route(route="admin/api/control-action", methods=["POST"])
def admin_control_action_route(req: func.HttpRequest) -> func.HttpResponse:
    return _unavailable() if _load_error else admin_control_action(req)


@app.route(route="admin/api/exceptions", methods=["GET", "POST"])
def admin_exceptions_route(req: func.HttpRequest) -> func.HttpResponse:
    return _unavailable() if _load_error else admin_exceptions(req)


@app.route(route="admin/api/exception-action", methods=["POST"])
def admin_exception_action_route(req: func.HttpRequest) -> func.HttpResponse:
    return _unavailable() if _load_error else admin_exception_action(req)


@app.route(route="admin/api/audit", methods=["GET"])
def admin_audit_route(req: func.HttpRequest) -> func.HttpResponse:
    return _unavailable() if _load_error else admin_audit_events(req)
