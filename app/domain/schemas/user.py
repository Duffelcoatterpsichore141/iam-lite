import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class UserCreate(BaseModel):
    email: EmailStr = Field(..., examples=["joao.silva@empresa.com"])
    full_name: str = Field(..., min_length=2, max_length=255, examples=["João Silva"])
    password: str = Field(..., min_length=8, examples=["S3cur3P@ss!"])
    department: str | None = Field(None, examples=["TI"])
    location: str | None = Field(None, examples=["São Paulo"])
    manager_id: uuid.UUID | None = None
    role_ids: list[uuid.UUID] = Field(default_factory=list)


class UserUpdate(BaseModel):
    full_name: str | None = Field(None, min_length=2, max_length=255)
    department: str | None = None
    location: str | None = None
    manager_id: uuid.UUID | None = None
    is_active: bool | None = None
    role_ids: list[uuid.UUID] | None = None


class RoleShort(BaseModel):
    id: uuid.UUID
    name: str

    model_config = {"from_attributes": True}


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str
    is_active: bool
    department: str | None
    location: str | None
    manager_id: uuid.UUID | None
    roles: list[RoleShort]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class UserListResponse(BaseModel):
    total: int
    items: list[UserResponse]
