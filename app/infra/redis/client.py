from typing import Optional

import redis as _redis

from app.core.config import get_settings

settings = get_settings()

_pool = _redis.ConnectionPool.from_url(
    settings.REDIS_URL,
    decode_responses=True,
    max_connections=50,
)


def get_redis() -> _redis.Redis:
    return _redis.Redis(connection_pool=_pool)


class TokenStore:
    REVOKED_PREFIX = "revoked:"
    REFRESH_PREFIX = "refresh:"
    PERMISSION_CACHE_PREFIX = "perms:"

    def __init__(self) -> None:
        self._r = get_redis()

    def revoke_token(self, jti: str, ttl_seconds: int) -> None:
        self._r.setex(f"{self.REVOKED_PREFIX}{jti}", ttl_seconds, "1")

    def is_revoked(self, jti: str) -> bool:
        return self._r.exists(f"{self.REVOKED_PREFIX}{jti}") == 1

    def store_refresh_token(self, user_id: str, token: str, ttl_seconds: int) -> None:
        self._r.setex(f"{self.REFRESH_PREFIX}{user_id}", ttl_seconds, token)

    def get_refresh_token(self, user_id: str) -> Optional[str]:
        return self._r.get(f"{self.REFRESH_PREFIX}{user_id}")

    def delete_refresh_token(self, user_id: str) -> None:
        self._r.delete(f"{self.REFRESH_PREFIX}{user_id}")

    def cache_permissions(
        self, user_id: str, permissions: list[str], ttl_seconds: int = 300
    ) -> None:
        key = f"{self.PERMISSION_CACHE_PREFIX}{user_id}"
        pipe = self._r.pipeline()
        pipe.delete(key)
        if permissions:
            pipe.sadd(key, *permissions)
        pipe.expire(key, ttl_seconds)
        pipe.execute()

    def get_cached_permissions(self, user_id: str) -> Optional[set[str]]:
        key = f"{self.PERMISSION_CACHE_PREFIX}{user_id}"
        members = self._r.smembers(key)
        return set(members) if members else None

    def invalidate_permission_cache(self, user_id: str) -> None:
        self._r.delete(f"{self.PERMISSION_CACHE_PREFIX}{user_id}")


token_store = TokenStore()
