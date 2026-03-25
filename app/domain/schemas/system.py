import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class SystemCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=200, examples=["ERP Corporativo"])
    slug: str = Field(..., min_length=2, max_length=100, pattern="^[a-z0-9-]+$", examples=["erp"])
    description: str | None = Field(None, examples=["Sistema de Planejamento de Recursos Empresariais"])
    classification: str = Field(
        "internal",
        pattern="^(public|internal|confidential|critical)$",
        examples=["critical"],
    )
    owner_department: str | None = Field(None, examples=["Financeiro"])
    requires_approval: bool = Field(False, examples=[True])


class SystemResponse(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    description: str | None
    classification: str
    owner_department: str | None
    is_active: bool
    requires_approval: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class SystemListResponse(BaseModel):
    total: int
    items: list[SystemResponse]
