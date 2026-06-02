"""
Azure Functions v2 app — HTTP trigger for Azure DevOps PR webhooks.
Wraps app.handler() so the business logic stays independently testable.
"""

import logging

import azure.functions as func

from app import handler

web_app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)
logger = logging.getLogger(__name__)


@web_app.route(route="webhook", methods=["POST"])
def webhook(req: func.HttpRequest) -> func.HttpResponse:
    result = handler(
        request_body=req.get_body(),
        headers=dict(req.headers),
    )
    return func.HttpResponse(
        body=result["body"],
        status_code=result["status"],
        mimetype="text/plain",
    )
