"""
Testes da trilha de auditoria — imutabilidade e filtragem.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.domain.models.audit_log import AuditLog
from app.services.audit_service import audit_service


def _auth_header(client: TestClient, email: str, password: str = "Test@1234!") -> dict:
    tokens = client.post(
        "/auth/token",
        json={"grant_type": "password", "username": email, "password": password},
    ).json()
    return {"Authorization": f"Bearer {tokens['access_token']}"}


class TestAuditImmutability:
    def test_audit_logs_not_deletable_via_api(self, client: TestClient, admin_user, db: Session):
        headers = _auth_header(client, "admin@test.com")
        resp = client.delete("/audit/logs", headers=headers)
        assert resp.status_code == 405

    def test_audit_logs_not_editable_via_api(self, client: TestClient, admin_user, db: Session):
        headers = _auth_header(client, "admin@test.com")
        resp = client.put("/audit/logs", headers=headers)
        assert resp.status_code == 405

    def test_audit_log_created_on_login(self, client: TestClient, admin_user, db: Session):
        client.post(
            "/auth/token",
            json={"grant_type": "password", "username": "admin@test.com", "password": "Test@1234!"},
        )
        logs = db.query(AuditLog).filter(AuditLog.action == "auth.login.success").all()
        assert len(logs) >= 1

    def test_audit_log_created_on_failed_login(self, client: TestClient, db: Session):
        client.post(
            "/auth/token",
            json={"grant_type": "password", "username": "ghost@test.com", "password": "wrong"},
        )
        logs = db.query(AuditLog).filter(AuditLog.action == "auth.login.failed").all()
        assert len(logs) >= 1
        assert logs[0].status == "failure"


class TestAuditQuery:
    def test_admin_can_query_logs(self, client: TestClient, admin_user, db: Session):
        client.post(
            "/auth/token",
            json={"grant_type": "password", "username": "admin@test.com", "password": "Test@1234!"},
        )
        headers = _auth_header(client, "admin@test.com")
        resp = client.get("/audit/logs", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "items" in data
        assert isinstance(data["items"], list)

    def test_viewer_cannot_query_logs(self, client: TestClient, viewer_user, db: Session):
        headers = _auth_header(client, "viewer@test.com")
        resp = client.get("/audit/logs", headers=headers)
        assert resp.status_code == 403

    def test_filter_by_action(self, client: TestClient, admin_user, db: Session):
        client.post(
            "/auth/token",
            json={"grant_type": "password", "username": "admin@test.com", "password": "Test@1234!"},
        )
        headers = _auth_header(client, "admin@test.com")
        resp = client.get("/audit/logs?action=auth.login", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        for item in data["items"]:
            assert "auth.login" in item["action"]

    def test_filter_by_status(self, client: TestClient, admin_user, db: Session):
        headers = _auth_header(client, "admin@test.com")
        resp = client.get("/audit/logs?status=success", headers=headers)
        assert resp.status_code == 200
        for item in resp.json()["items"]:
            assert item["status"] == "success"


class TestAuditService:
    def test_log_entry_is_persisted(self, db: Session, admin_user):
        audit_service.log(
            db,
            action="test.action",
            actor_id=admin_user.id,
            actor_email=admin_user.email,
            resource_type="unit_test",
            detail={"key": "value"},
        )
        db.flush()
        entry = db.query(AuditLog).filter(AuditLog.action == "test.action").first()
        assert entry is not None
        assert entry.actor_email == admin_user.email
        assert entry.detail["key"] == "value"

    def test_query_returns_correct_count(self, db: Session, admin_user):
        for i in range(3):
            audit_service.log(
                db,
                action=f"bulk.test.{i}",
                actor_email=admin_user.email,
            )
        db.flush()
        items, total = audit_service.query_logs(db, action="bulk.test")
        assert total >= 3
