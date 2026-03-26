"""Service layer for ABAC policy management and evaluation."""

import uuid
from typing import Optional

from sqlalchemy.orm import Session

from app.domain.models.policy import Policy
from app.domain.models.user import User
from app.domain.schemas.policy import PolicyCreate


class PolicyService:
    """Manages ABAC policies and evaluates access decisions against them."""

    def create(self, db: Session, payload: PolicyCreate, created_by_id: uuid.UUID) -> Policy:
        """Create a new ABAC policy.

        Args:
            db: Active SQLAlchemy session.
            payload: Validated policy creation schema.
            created_by_id: UUID of the admin user creating the policy.

        Returns:
            The newly created Policy instance (not yet committed).

        Raises:
            ValueError: If a policy with the same name already exists.
        """
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
        """Retrieve a policy by its UUID.

        Args:
            db: Active SQLAlchemy session.
            policy_id: The policy's UUID.

        Returns:
            The Policy instance, or None if not found.
        """
        return db.query(Policy).filter(Policy.id == policy_id).first()

    def list_policies(
        self,
        db: Session,
        *,
        skip: int = 0,
        limit: int = 50,
        is_active: Optional[bool] = None,
    ) -> tuple[list[Policy], int]:
        """Return a paginated list of policies with an optional active-status filter.

        Args:
            db: Active SQLAlchemy session.
            skip: Number of records to skip (offset).
            limit: Maximum number of records to return.
            is_active: Filter by active status when provided.

        Returns:
            A tuple of (list of Policy instances, total count before pagination).
        """
        q = db.query(Policy)
        if is_active is not None:
            q = q.filter(Policy.is_active == is_active)
        total = q.count()
        items = q.order_by(Policy.name).offset(skip).limit(limit).all()
        return items, total

    def delete(self, db: Session, policy: Policy) -> None:
        """Soft-delete a policy by setting is_active to False.

        Args:
            db: Active SQLAlchemy session.
            policy: The Policy instance to deactivate.
        """
        policy.is_active = False
        db.flush()

    def evaluate(
        self,
        user: User,
        resource_attributes: dict,
        action: str,
        policies: list[Policy],
    ) -> bool:
        """Evaluate whether a user may perform an action given a set of policies.

        Policies are evaluated in order; the first matching policy determines the
        outcome.  Returns False when no policy matches (implicit deny).

        Args:
            user: The User whose attributes are used as the subject.
            resource_attributes: Attributes describing the target resource.
            action: The action being requested (e.g. ``"read"``).
            policies: Ordered list of Policy objects to evaluate.

        Returns:
            True if access is allowed, False otherwise.
        """
        user_attrs: dict[str, Optional[str]] = {
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
        """Check that all required key/value pairs are present in subject.

        Args:
            subject: Attribute dictionary of the entity being evaluated.
            required: Expected attribute key/value pairs from the policy.

        Returns:
            True when all required attributes match, False otherwise.
        """
        for key, value in required.items():
            if subject.get(key) != value:
                return False
        return True


policy_service = PolicyService()
