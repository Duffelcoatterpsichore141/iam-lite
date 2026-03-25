from pydantic import BaseModel, Field


class TokenRequest(BaseModel):
    grant_type: str = Field(..., examples=["password", "client_credentials", "refresh_token"])
    username: str | None = Field(None, examples=["user@example.com"])
    password: str | None = Field(None, examples=["S3cur3P@ss!"])
    refresh_token: str | None = None
    scope: str | None = Field(None, examples=["openid profile email"])
    client_id: str | None = None
    client_secret: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: str | None = None
    id_token: str | None = None
    scope: str | None = None


class IntrospectRequest(BaseModel):
    token: str


class IntrospectResponse(BaseModel):
    active: bool
    sub: str | None = None
    email: str | None = None
    roles: list[str] | None = None
    exp: int | None = None
    iat: int | None = None
    iss: str | None = None
    aud: str | None = None
    token_type: str | None = None


class RevokeRequest(BaseModel):
    token: str
