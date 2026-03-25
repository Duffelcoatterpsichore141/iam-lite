import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class AccessRequestCreate(BaseModel):
    system_id: uuid.UUID
    requested_role_id: uuid.UUID | None = None
    justification: str | None = Field(
        None,
        max_length=1000,
        examples=["Preciso acessar o ERP para gerar relatórios financeiros do trimestre."],
    )


class ReviewRequest(BaseModel):
    comment: str | None = Field(None, max_length=1000)


class SystemShort(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    classification: str

    model_config = {"from_attributes": True}


class RoleShort(BaseModel):
    id: uuid.UUID
    name: str

    model_config = {"from_attributes": True}


class UserShort(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str

    model_config = {"from_attributes": True}


class AccessRequestResponse(BaseModel):
    id: uuid.UUID
    requester: UserShort
    system: SystemShort
    requested_role: RoleShort | None
    status: str
    justification: str | None
    reviewer: UserShort | None
    reviewer_comment: str | None
    reviewed_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AccessRequestListResponse(BaseModel):
    total: int
    items: list[AccessRequestResponse]
