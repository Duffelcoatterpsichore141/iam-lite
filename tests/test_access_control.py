"""
Testes de controle de acesso — RBAC, ABAC e fluxo de aprovação.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from tests.conftest import _make_role, _make_system, _make_user


def _auth_header(client: TestClient, email: str, password: str = "Test@1234!") -> dict:
    tokens = client.post(
        "/auth/token",
        json={"grant_type": "password", "username": email, "password": password},
    ).json()
    return {"Authorization": f"Bearer {tokens['access_token']}"}


class TestRBAC:
    def test_admin_can_list_users(self, client: TestClient, admin_user, db: Session):
        headers = _auth_header(client, "admin@test.com")
        resp = client.get("/users", headers=headers)
        assert resp.status_code == 200

    def test_viewer_cannot_create_user(self, client: TestClient, viewer_user, db: Session):
        headers = _auth_header(client, "viewer@test.com")
        resp = client.post(
            "/users",
            json={"email": "new@test.com", "full_name": "Novo", "password": "Pass@1234!"},
            headers=headers,
        )
        assert resp.status_code == 403

    def test_unauthenticated_cannot_access_users(self, client: TestClient):
        resp = client.get("/users")
        assert resp.status_code in (401, 403)

    def test_admin_can_create_role(self, client: TestClient, admin_user, db: Session):
        headers = _auth_header(client, "admin@test.com")
        resp = client.post(
            "/roles",
            json={"name": "auditor", "description": "Role de auditoria"},
            headers=headers,
        )
        assert resp.status_code == 201
        assert resp.json()["name"] == "auditor"

    def test_viewer_cannot_create_role(self, client: TestClient, viewer_user, db: Session):
        headers = _auth_header(client, "viewer@test.com")
        resp = client.post(
            "/roles",
            json={"name": "test-role"},
            headers=headers,
        )
        assert resp.status_code == 403

    def test_manager_can_list_roles(self, client: TestClient, manager_user, db: Session):
        headers = _auth_header(client, "manager@test.com")
        resp = client.get("/roles", headers=headers)
        assert resp.status_code == 200


class TestAccessRequestWorkflow:
    def test_viewer_requests_access_to_critical_system(
        self, client: TestClient, viewer_user, critical_system, db: Session
    ):
        headers = _auth_header(client, "viewer@test.com")
        resp = client.post(
            "/access-requests",
            json={
                "system_id": str(critical_system.id),
                "justification": "Preciso de acesso para relatório Q1.",
            },
            headers=headers,
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "pending"
        assert data["system"]["classification"] == "critical"

    def test_duplicate_pending_request_rejected(
        self, client: TestClient, viewer_user, critical_system, db: Session
    ):
        headers = _auth_header(client, "viewer@test.com")
        payload = {
            "system_id": str(critical_system.id),
            "justification": "Primeira solicitação.",
        }
        client.post("/access-requests", json=payload, headers=headers)
        resp = client.post("/access-requests", json=payload, headers=headers)
        assert resp.status_code == 409

    def test_manager_approves_access_request(
        self,
        client: TestClient,
        viewer_user,
        manager_user,
        critical_system,
        db: Session,
    ):
        viewer_headers = _auth_header(client, "viewer@test.com")
        ar_resp = client.post(
            "/access-requests",
            json={"system_id": str(critical_system.id), "justification": "Necessário para auditoria."},
            headers=viewer_headers,
        ).json()

        manager_headers = _auth_header(client, "manager@test.com")
        approve_resp = client.patch(
            f"/access-requests/{ar_resp['id']}/approve",
            json={"comment": "Aprovado conforme política interna."},
            headers=manager_headers,
        )
        assert approve_resp.status_code == 200
        assert approve_resp.json()["status"] == "approved"

    def test_manager_rejects_access_request(
        self,
        client: TestClient,
        viewer_user,
        manager_user,
        critical_system,
        db: Session,
    ):
        viewer_headers = _auth_header(client, "viewer@test.com")
        ar_resp = client.post(
            "/access-requests",
            json={"system_id": str(critical_system.id), "justification": "Teste rejeição."},
            headers=viewer_headers,
        ).json()

        manager_headers = _auth_header(client, "manager@test.com")
        reject_resp = client.patch(
            f"/access-requests/{ar_resp['id']}/reject",
            json={"comment": "Não justificado adequadamente."},
            headers=manager_headers,
        )
        assert reject_resp.status_code == 200
        assert reject_resp.json()["status"] == "rejected"

    def test_viewer_cannot_approve_request(
        self, client: TestClient, viewer_user, admin_user, critical_system, db: Session
    ):
        admin_headers = _auth_header(client, "admin@test.com")
        ar_resp = client.post(
            "/access-requests",
            json={"system_id": str(critical_system.id), "justification": "Teste."},
            headers=admin_headers,
        ).json()

        viewer_headers = _auth_header(client, "viewer@test.com")
        resp = client.patch(
            f"/access-requests/{ar_resp['id']}/approve",
            json={"comment": "tentativa ilegal"},
            headers=viewer_headers,
        )
        assert resp.status_code == 403

    def test_admin_auto_approved_on_non_critical(
        self, client: TestClient, admin_user, internal_system, db: Session
    ):
        headers = _auth_header(client, "admin@test.com")
        resp = client.post(
            "/access-requests",
            json={"system_id": str(internal_system.id), "justification": "Acesso rápido."},
            headers=headers,
        )
        assert resp.status_code == 201
        assert resp.json()["status"] == "approved"


class TestPolicies:
    def test_admin_can_create_policy(self, client: TestClient, admin_user, db: Session):
        headers = _auth_header(client, "admin@test.com")
        resp = client.post(
            "/policies",
            json={
                "name": "test-policy-rbac",
                "effect": "allow",
                "subject_attributes": {"department": "TI"},
                "resource_attributes": {"classification": "internal"},
                "actions": ["read"],
            },
            headers=headers,
        )
        assert resp.status_code == 201
        assert resp.json()["name"] == "test-policy-rbac"

    def test_viewer_cannot_create_policy(self, client: TestClient, viewer_user, db: Session):
        headers = _auth_header(client, "viewer@test.com")
        resp = client.post(
            "/policies",
            json={"name": "bad-policy", "actions": ["read"]},
            headers=headers,
        )
        assert resp.status_code == 403
