"""
Script de seed — popula o banco com dados iniciais de exemplo.
Execute com: python seed.py
"""
import sys
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import hash_password
from app.domain.models import (
    AccessRequest,
    AuditLog,
    Permission,
    Policy,
    Role,
    System,
    User,
    role_permissions,
    user_roles,
)
from app.infra.database.session import SessionLocal, engine
from app.infra.database.session import Base

settings = get_settings()


def seed() -> None:
    Base.metadata.create_all(bind=engine)
    db: Session = SessionLocal()

    try:
        if db.query(User).first():
            print("[seed] Banco já possui dados. Seed ignorado.")
            return

        print("[seed] Criando roles...")
        role_admin = Role(name="admin", description="Administrador do sistema com acesso total.")
        role_manager = Role(name="manager", description="Gestor com permissão de aprovar solicitações.")
        role_viewer = Role(name="viewer", description="Visualizador — acesso somente leitura.")
        db.add_all([role_admin, role_manager, role_viewer])
        db.flush()

        print("[seed] Criando permissões...")
        perms = [
            Permission(name="users:read", resource="users", action="read", description="Listar e visualizar usuários"),
            Permission(name="users:write", resource="users", action="write", description="Criar e atualizar usuários"),
            Permission(name="users:delete", resource="users", action="delete", description="Desativar usuários"),
            Permission(name="roles:read", resource="roles", action="read"),
            Permission(name="roles:write", resource="roles", action="write"),
            Permission(name="policies:read", resource="policies", action="read"),
            Permission(name="policies:write", resource="policies", action="write"),
            Permission(name="systems:read", resource="systems", action="read"),
            Permission(name="systems:write", resource="systems", action="write"),
            Permission(name="access_requests:read", resource="access_requests", action="read"),
            Permission(name="access_requests:approve", resource="access_requests", action="approve"),
            Permission(name="audit:read", resource="audit", action="read"),
        ]
        db.add_all(perms)
        db.flush()

        role_admin.permissions = perms
        role_manager.permissions = [p for p in perms if p.name not in ("users:delete", "roles:write", "policies:write", "systems:write")]
        role_viewer.permissions = [p for p in perms if p.action == "read"]
        db.flush()

        print("[seed] Criando usuários...")
        admin = User(
            email=settings.FIRST_ADMIN_EMAIL,
            full_name="Administrador IAM",
            hashed_password=hash_password(settings.FIRST_ADMIN_PASSWORD),
            department="TI",
            location="São Paulo",
            is_active=True,
        )
        admin.roles = [role_admin]
        db.add(admin)
        db.flush()

        manager = User(
            email="gestor@empresa.com",
            full_name="Maria Gestora",
            hashed_password=hash_password("Gestor@2025!"),
            department="Financeiro",
            location="Rio de Janeiro",
            manager_id=admin.id,
            is_active=True,
        )
        manager.roles = [role_manager]
        db.add(manager)
        db.flush()

        viewer = User(
            email="colaborador@empresa.com",
            full_name="Carlos Colaborador",
            hashed_password=hash_password("Viewer@2025!"),
            department="Comercial",
            location="São Paulo",
            manager_id=manager.id,
            is_active=True,
        )
        viewer.roles = [role_viewer]
        db.add(viewer)
        db.flush()

        print("[seed] Criando sistemas fictícios...")
        erp = System(
            name="ERP Corporativo",
            slug="erp",
            description="Sistema de Planejamento de Recursos Empresariais — SAP-like.",
            classification="critical",
            owner_department="Financeiro",
            requires_approval=True,
        )
        crm = System(
            name="CRM Comercial",
            slug="crm",
            description="Gestão de Relacionamento com Clientes.",
            classification="confidential",
            owner_department="Comercial",
            requires_approval=False,
        )
        rh = System(
            name="Portal RH",
            slug="rh",
            description="Sistema de Recursos Humanos — ponto, férias e contratos.",
            classification="confidential",
            owner_department="RH",
            requires_approval=True,
        )
        intranet = System(
            name="Intranet",
            slug="intranet",
            description="Portal interno de comunicação corporativa.",
            classification="internal",
            owner_department="TI",
            requires_approval=False,
        )
        db.add_all([erp, crm, rh, intranet])
        db.flush()

        print("[seed] Criando políticas ABAC...")
        policy_ti_erp = Policy(
            name="allow-ti-erp-read",
            description="Usuários do departamento TI podem acessar o ERP em modo leitura.",
            effect="allow",
            subject_attributes={"department": "TI"},
            resource_attributes={"slug": "erp"},
            actions=["read", "access"],
            conditions={},
            created_by_id=admin.id,
        )
        policy_fin_erp = Policy(
            name="allow-financeiro-erp-full",
            description="Usuários do Financeiro têm acesso completo ao ERP.",
            effect="allow",
            subject_attributes={"department": "Financeiro"},
            resource_attributes={"classification": "critical"},
            actions=["read", "write", "access"],
            conditions={},
            created_by_id=admin.id,
        )
        policy_sp_crm = Policy(
            name="allow-sp-crm",
            description="Usuários localizados em São Paulo acessam o CRM.",
            effect="allow",
            subject_attributes={"location": "São Paulo"},
            resource_attributes={"slug": "crm"},
            actions=["read", "write", "access"],
            conditions={},
            created_by_id=admin.id,
        )
        db.add_all([policy_ti_erp, policy_fin_erp, policy_sp_crm])
        db.flush()

        print("[seed] Criando solicitação de acesso de exemplo...")
        ar = AccessRequest(
            requester_id=viewer.id,
            system_id=erp.id,
            justification="Preciso acessar o ERP para extrair o relatório trimestral de vendas.",
            status="pending",
        )
        db.add(ar)
        db.flush()

        print("[seed] Registrando log de auditoria inicial...")
        log = AuditLog(
            actor_id=admin.id,
            actor_email=admin.email,
            action="seed.completed",
            resource_type="system",
            status="success",
            detail={"message": "Seed inicial executado com sucesso."},
            ip_address="127.0.0.1",
        )
        db.add(log)

        db.commit()
        print("[seed] Concluído com sucesso!")
        print(f"\n  Admin:    {settings.FIRST_ADMIN_EMAIL} / {settings.FIRST_ADMIN_PASSWORD}")
        print("  Manager:  gestor@empresa.com / Gestor@2025!")
        print("  Viewer:   colaborador@empresa.com / Viewer@2025!")

    except Exception as exc:
        db.rollback()
        print(f"[seed] Erro: {exc}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed()
