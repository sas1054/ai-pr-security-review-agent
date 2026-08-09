"""Authentication boundary tests for the combined webhook and admin gateway."""

import base64
import json

from fastapi.testclient import TestClient

import web_service


client = TestClient(web_service.api)


def _principal(role: str) -> dict[str, str]:
    encoded = base64.b64encode(
        json.dumps({"user_details": "admin@example.com", "claims": [{"typ": "roles", "val": role}]}).encode()
    ).decode()
    return {"X-MS-CLIENT-PRINCIPAL-NAME": "admin@example.com", "X-MS-CLIENT-PRINCIPAL": encoded}


def test_webhook_keeps_secret_authentication_when_entra_is_enabled(monkeypatch):
    monkeypatch.setenv("ADMIN_REQUIRE_ENTRA", "true")
    monkeypatch.setenv("ADMIN_ACCESS_KEY", "webhook-secret")
    response = client.post(
        "/api/webhook",
        headers={"X-MS-CLIENT-PRINCIPAL-NAME": "admin@example.com"},
        content=b"{}",
    )
    assert response.status_code == 401


def test_admin_rejects_query_key_when_entra_is_enabled(monkeypatch):
    monkeypatch.setenv("ADMIN_REQUIRE_ENTRA", "true")
    monkeypatch.setenv("ADMIN_ACCESS_KEY", "legacy-secret")
    response = client.get("/api/admin?code=legacy-secret", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == "/.auth/login/aad?post_login_redirect_uri=/api/admin"


def test_admin_api_rejects_query_key_when_entra_is_enabled(monkeypatch):
    monkeypatch.setenv("ADMIN_REQUIRE_ENTRA", "true")
    monkeypatch.setenv("ADMIN_ACCESS_KEY", "legacy-secret")
    response = client.get("/api/admin/api/dashboard?code=legacy-secret")
    assert response.status_code == 401
    assert response.json()["detail"] == "Microsoft Entra authentication is required"


def test_admin_accepts_platform_identity_when_entra_is_enabled(monkeypatch):
    monkeypatch.setenv("ADMIN_REQUIRE_ENTRA", "true")
    monkeypatch.setenv("ADMIN_ACCESS_KEY", "legacy-secret")
    response = client.get("/api/admin", headers=_principal("Policy.Admin"))
    assert response.status_code == 200
    assert "PR Security Control" in response.text


def test_admin_rejects_authenticated_user_without_portal_role(monkeypatch):
    monkeypatch.setenv("ADMIN_REQUIRE_ENTRA", "true")
    response = client.get("/api/admin", headers={"X-MS-CLIENT-PRINCIPAL-NAME": "user@example.com"})
    assert response.status_code == 403
    assert "portal role" in response.json()["detail"]


def test_local_admin_fallback_still_uses_query_key(monkeypatch):
    monkeypatch.setenv("ADMIN_REQUIRE_ENTRA", "false")
    monkeypatch.setenv("ADMIN_ACCESS_KEY", "local-secret")
    assert client.get("/api/admin").status_code == 401
    assert client.get("/api/admin?code=local-secret").status_code == 200
