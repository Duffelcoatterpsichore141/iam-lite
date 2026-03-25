import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class PolicyCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=200, examples=["allow-ti-erp-read"])
    description: str | None = None
    effect: str = Field("allow", pattern="^(allow|deny)$", examples=["allow"])
    subject_attributes: dict = Field(
        default_factory=dict,
        examples=[{"department": "TI", "location": "São Paulo"}],
    )
    resource_attributes: dict = Field(
        default_factory=dict,
        examples=[{"classification": "internal", "owner_department": "TI"}],
    )
    actions: list[str] = Field(
        default_factory=list,
        examples=[["read", "write"]],
    )
    conditions: dict = Field(default_factory=dict, examples=[{}])


class PolicyResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    effect: str
    subject_attributes: dict
    resource_attributes: dict
    actions: list[str]
    conditions: dict
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class PolicyListResponse(BaseModel):
    total: int
    items: list[PolicyResponse]
