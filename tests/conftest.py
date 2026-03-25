"""
Fixtures compartilhadas para todos os testes.
Usa banco SQLite em memória e fakeredis para isolamento total — sem dependências externas.
"""
import uuid
from typing import Generator
from unittest.mock import patch

import fakeredis
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.security import hash_password
from app.domain.models import Role, System, User
from app.infra.database.session import Base, get_db
import app.infra.redis.client as _redis_module
from main import app

TEST_DB_URL = "sqlite:///:memory:"

engine_test = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(bind=engine_test)


@pytest.fixture(scope="session", autouse=True)
def fake_redis_session():
    """Substitui o Redis real por fakeredis em toda a sessão de testes."""
    fake = fakeredis.FakeRedis(decode_responses=True)
    with patch.object(_redis_module.token_store, "_r", fake):
        yield fake


@pytest.fixture(scope="session", autouse=True)
def create_tables():
    Base.metadata.create_all(bind=engine_test)
    yield
    Base.metadata.drop_all(bind=engine_test)


@pytest.fixture()
def db() -> Generator[Session, None, None]:
    connection = engine_test.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


@pytest.fixture()
def client(db: Session) -> Generator[TestClient, None, None]:
    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def _make_role(db: Session, name: str) -> Role:
    role = Role(name=name, description=f"Role {name}")
    db.add(role)
    db.flush()
    return role


def _make_user(
    db: Session,
    email: str,
    roles: list[Role],
    department: str = "TI",
    password: str = "Test@1234!",
) -> User:
    user = User(
        email=email,
        full_name=f"Test {email}",
        hashed_password=hash_password(password),
        department=department,
        location="São Paulo",
        is_active=True,
    )
    user.roles = roles
    db.add(user)
    db.flush()
    return user


def _make_system(
    db: Session,
    slug: str,
    classification: str = "internal",
    requires_approval: bool = False,
) -> System:
    system = System(
        name=f"Sistema {slug.upper()}",
        slug=slug,
        classification=classification,
        requires_approval=requires_approval,
    )
    db.add(system)
    db.flush()
    return system


@pytest.fixture()
def admin_role(db: Session) -> Role:
    return _make_role(db, "admin")


@pytest.fixture()
def manager_role(db: Session) -> Role:
    return _make_role(db, "manager")


@pytest.fixture()
def viewer_role(db: Session) -> Role:
    return _make_role(db, "viewer")


@pytest.fixture()
def admin_user(db: Session, admin_role: Role) -> User:
    return _make_user(db, "admin@test.com", [admin_role])


@pytest.fixture()
def manager_user(db: Session, manager_role: Role) -> User:
    return _make_user(db, "manager@test.com", [manager_role], department="Financeiro")


@pytest.fixture()
def viewer_user(db: Session, viewer_role: Role) -> User:
    return _make_user(db, "viewer@test.com", [viewer_role], department="Comercial")


@pytest.fixture()
def critical_system(db: Session) -> System:
    return _make_system(db, "erp-test", classification="critical", requires_approval=True)


@pytest.fixture()
def internal_system(db: Session) -> System:
    return _make_system(db, "intranet-test", classification="internal", requires_approval=False)
