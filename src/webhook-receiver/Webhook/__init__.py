"""Static-metadata HTTP entry point for the Azure DevOps webhook.

The logic stays in app.py so this compatibility binding is intentionally thin.
"""

import azure.functions as func

from app import handler


def main(req: func.HttpRequest) -> func.HttpResponse:
    result = handler(req.get_body())
    return func.HttpResponse(
        body=result["body"],
        status_code=result["status"],
        mimetype="text/plain",
    )
