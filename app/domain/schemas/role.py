import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class PermissionCreate(BaseModel):
    name: str = Field(..., examples=["users:read"])
    description: str | None = Field(None, examples=["Permite listar e visualizar usuários"])
    resource: str = Field(..., examples=["users"])
    action: str = Field(..., examples=["read"])


class PermissionResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    resource: str
    action: str
    created_at: datetime

    model_config = {"from_attributes": True}


class RoleCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100, examples=["manager"])
    description: str | None = Field(None, examples=["Gestor de equipe com permissão de aprovação"])


class RoleResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    permissions: list[PermissionResponse]
    created_at: datetime

    model_config = {"from_attributes": True}


class RoleListResponse(BaseModel):
    total: int
    items: list[RoleResponse]


class AddPermissionRequest(BaseModel):
    permission_id: uuid.UUID | None = None
    permission: PermissionCreate | None = None
