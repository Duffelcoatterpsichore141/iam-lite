import uuid
from typing import Optional

from sqlalchemy.orm import Session

from app.domain.models.policy import Policy
from app.domain.models.user import User
from app.domain.schemas.policy import PolicyCreate


class PolicyService:
    def create(self, db: Session, payload: PolicyCreate, created_by_id: uuid.UUID) -> Policy:
        if db.query(Policy).filter(Policy.name == payload.name).first():
            raise ValueError(f"Política '{payload.name}' já existe.")
        policy = Policy(
            name=payload.name,
            description=payload.description,
            effect=payload.effect,
            subject_attributes=payload.subject_attributes,
            resource_attributes=payload.resource_attributes,
            actions=payload.actions,
            conditions=payload.conditions,
            created_by_id=created_by_id,
        )
        db.add(policy)
        db.flush()
        return policy

    def get_by_id(self, db: Session, policy_id: uuid.UUID) -> Optional[Policy]:
        return db.query(Policy).filter(Policy.id == policy_id).first()

    def list_policies(
        self, db: Session, *, skip: int = 0, limit: int = 50, is_active: Optional[bool] = None
    ) -> tuple[list[Policy], int]:
        q = db.query(Policy)
        if is_active is not None:
            q = q.filter(Policy.is_active == is_active)
        total = q.count()
        items = q.order_by(Policy.name).offset(skip).limit(limit).all()
        return items, total

    def delete(self, db: Session, policy: Policy) -> None:
        policy.is_active = False
        db.flush()

    def evaluate(self, user: User, resource_attributes: dict, action: str, policies: list[Policy]) -> bool:
        user_attrs = {
            "department": user.department,
            "location": user.location,
        }
        for policy in policies:
            if not policy.is_active:
                continue
            if action not in policy.actions and "*" not in policy.actions:
                continue
            if not self._match_attributes(user_attrs, policy.subject_attributes):
                continue
            if not self._match_attributes(resource_attributes, policy.resource_attributes):
                continue
            return policy.effect == "allow"
        return False

    def _match_attributes(self, subject: dict, required: dict) -> bool:
        for key, value in required.items():
            if subject.get(key) != value:
                return False
        return True


policy_service = PolicyService()
