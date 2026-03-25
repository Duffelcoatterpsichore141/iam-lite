"""
Testes de autenticação — login, refresh, introspect e revoke.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from tests.conftest import _make_role, _make_user


class TestLogin:
    def test_login_success(self, client: TestClient, admin_user, db: Session):
        resp = client.post(
            "/auth/token",
            json={"grant_type": "password", "username": "admin@test.com", "password": "Test@1234!"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "Bearer"
        assert data["expires_in"] > 0

    def test_login_with_openid_scope_returns_id_token(self, client: TestClient, admin_user, db: Session):
        resp = client.post(
            "/auth/token",
            json={
                "grant_type": "password",
                "username": "admin@test.com",
                "password": "Test@1234!",
                "scope": "openid profile email",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("id_token") is not None

    def test_login_wrong_password(self, client: TestClient, admin_user, db: Session):
        resp = client.post(
            "/auth/token",
            json={"grant_type": "password", "username": "admin@test.com", "password": "wrongpass"},
        )
        assert resp.status_code == 401

    def test_login_unknown_user(self, client: TestClient, db: Session):
        resp = client.post(
            "/auth/token",
            json={"grant_type": "password", "username": "ghost@test.com", "password": "any"},
        )
        assert resp.status_code == 401

    def test_login_inactive_user(self, client: TestClient, db: Session):
        role = _make_role(db, "viewer-inactive")
        user = _make_user(db, "inactive@test.com", [role])
        user.is_active = False
        db.flush()
        resp = client.post(
            "/auth/token",
            json={"grant_type": "password", "username": "inactive@test.com", "password": "Test@1234!"},
        )
        assert resp.status_code == 401

    def test_unsupported_grant_type(self, client: TestClient):
        resp = client.post(
            "/auth/token",
            json={"grant_type": "implicit"},
        )
        assert resp.status_code == 400


class TestTokenRefresh:
    def _get_tokens(self, client: TestClient, admin_user):
        resp = client.post(
            "/auth/token",
            json={"grant_type": "password", "username": "admin@test.com", "password": "Test@1234!"},
        )
        return resp.json()

    def test_refresh_token_success(self, client: TestClient, admin_user, db: Session):
        tokens = self._get_tokens(client, admin_user)
        resp = client.post(
            "/auth/refresh",
            json={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data

    def test_refresh_without_token_fails(self, client: TestClient):
        resp = client.post(
            "/auth/refresh",
            json={"grant_type": "refresh_token"},
        )
        assert resp.status_code == 400

    def test_refresh_with_invalid_token_fails(self, client: TestClient):
        resp = client.post(
            "/auth/refresh",
            json={"grant_type": "refresh_token", "refresh_token": "not.a.token"},
        )
        assert resp.status_code == 401


class TestIntrospect:
    def test_introspect_valid_token(self, client: TestClient, admin_user, db: Session):
        tokens = client.post(
            "/auth/token",
            json={"grant_type": "password", "username": "admin@test.com", "password": "Test@1234!"},
        ).json()
        resp = client.post("/auth/introspect", json={"token": tokens["access_token"]})
        assert resp.status_code == 200
        data = resp.json()
        assert data["active"] is True
        assert data["roles"] == ["admin"]

    def test_introspect_invalid_token(self, client: TestClient):
        resp = client.post("/auth/introspect", json={"token": "garbage.token.here"})
        assert resp.status_code == 200
        assert resp.json()["active"] is False


class TestRevoke:
    def test_revoke_token(self, client: TestClient, admin_user, db: Session):
        tokens = client.post(
            "/auth/token",
            json={"grant_type": "password", "username": "admin@test.com", "password": "Test@1234!"},
        ).json()
        resp = client.post("/auth/revoke", json={"token": tokens["access_token"]})
        assert resp.status_code == 204
