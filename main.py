from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import auth, users, roles, policies, systems, access_requests, audit
from app.core.config import get_settings

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(
    title="IAM Lite — Identity & Access Management",
    description=(
        "Sistema centralizado de gerenciamento de identidades e permissões com "
        "RBAC, ABAC, OAuth2/OpenID Connect, fluxo de aprovação e trilha de auditoria "
        "em conformidade com a LGPD.\n\n"
        "## Autenticação\n"
        "Use o endpoint **POST /auth/token** com `grant_type=password` para obter um `access_token`.\n"
        "Clique em **Authorize** e cole o token no campo `Bearer`.\n\n"
        "## Modelos de Controle de Acesso\n"
        "- **RBAC** — cada usuário possui roles (`admin`, `manager`, `viewer`) com permissões pré-definidas.\n"
        "- **ABAC** — políticas baseadas em atributos do sujeito (departamento, localização) "
        "e do recurso (classificação, dono).\n\n"
        "## Conformidade LGPD\n"
        "Todos os logs de auditoria são imutáveis — nenhum endpoint permite edição ou exclusão."
    ),
    version="1.0.0",
    contact={"name": "Equipe IAM Lite", "email": "iam@empresa.com"},
    license_info={"name": "MIT"},
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(roles.router)
app.include_router(policies.router)
app.include_router(systems.router)
app.include_router(access_requests.router)
app.include_router(audit.router)


@app.get("/health", tags=["Health"], summary="Health check")
def health():
    return {"status": "ok", "service": settings.APP_NAME, "version": "1.0.0"}


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"detail": str(exc)})
