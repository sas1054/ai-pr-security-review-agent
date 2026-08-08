"""Static-metadata gateway for the small admin control portal."""

import azure.functions as func

from admin import (
    dashboard,
    portal,
    regulation,
    regulation_search,
    repository,
    rerun,
    rule_pack,
    settings,
)


_ROUTES = {
    "api/dashboard": dashboard,
    "api/settings": settings,
    "api/repository": repository,
    "api/rule-pack": rule_pack,
    "api/regulation": regulation,
    "api/regulation-search": regulation_search,
    "api/rerun": rerun,
}


def main(req: func.HttpRequest) -> func.HttpResponse:
    path = str(req.route_params.get("path") or "").strip("/")
    if not path:
        return portal(req)
    endpoint = _ROUTES.get(path)
    if endpoint is None:
        return func.HttpResponse("Not Found", status_code=404, mimetype="text/plain")
    return endpoint(req)
