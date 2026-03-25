# IAM Lite — Identity & Access Management

Sistema centralizado de gerenciamento de identidades e permissões de usuários em múltiplos sistemas corporativos fictícios, com fluxos de aprovação, controle de acesso granular e trilha de auditoria em conformidade com a **LGPD**.

---

## Sumário

1. [Visão Geral](#visão-geral)
2. [Stack Técnica](#stack-técnica)
3. [Arquitetura](#arquitetura)
4. [Controle de Acesso: RBAC](#controle-de-acesso-rbac)
5. [Controle de Acesso: ABAC](#controle-de-acesso-abac)
6. [OAuth2 e OpenID Connect](#oauth2-e-openid-connect)
7. [Fluxo de Aprovação](#fluxo-de-aprovação)
8. [Trilha de Auditoria (LGPD)](#trilha-de-auditoria-lgpd)
9. [Sistemas Fictícios Cadastrados](#sistemas-fictícios-cadastrados)
10. [Configuração e Execução](#configuração-e-execução)
11. [Endpoints da API](#endpoints-da-api)
12. [Testes](#testes)

---

## Visão Geral

O IAM Lite resolve o problema de governança de acessos em ambientes corporativos onde múltiplos sistemas precisam de controle centralizado. Ele combina dois modelos de controle de acesso complementares (RBAC e ABAC), emite tokens JWT compatíveis com OAuth2/OIDC e mantém um histórico imutável de auditoria.

---

## Stack Técnica

| Componente | Tecnologia |
|---|---|
| Framework Web | FastAPI 0.111 |
| Banco de Dados | PostgreSQL 16 + SQLAlchemy 2 |
| Migrations | Alembic |
| Autenticação | python-jose (JWT), bcrypt |
| Cache / Sessões | Redis 7 |
| Validação | Pydantic v2 |
| Containerização | Docker + Docker Compose |
| Testes | pytest + httpx |

---

## Arquitetura

O projeto segue os princípios da **Clean Architecture**, separando responsabilidades em camadas bem definidas:

```
iam-lite/
├── app/
│   ├── api/routes/        # Camada de apresentação — routers FastAPI
│   ├── core/              # Núcleo: configuração, segurança, permissões
│   ├── domain/
│   │   ├── models/        # Entidades ORM (SQLAlchemy)
│   │   └── schemas/       # DTOs de entrada/saída (Pydantic)
│   ├── infra/
│   │   ├── database/      # Sessão e engine do PostgreSQL
│   │   └── redis/         # Client Redis e TokenStore
│   └── services/          # Casos de uso (regras de negócio)
├── migrations/            # Alembic — versionamento do schema
└── tests/                 # Testes automatizados
```

---

## Controle de Acesso: RBAC

**Role-Based Access Control** — cada usuário recebe uma ou mais *roles*. Cada role agrupa um conjunto de permissões sobre recursos.

### Roles disponíveis

| Role | Descrição |
|---|---|
| `admin` | Acesso total ao sistema |
| `manager` | Pode aprovar/reprovar solicitações e gerenciar usuários |
| `viewer` | Acesso somente leitura |

### Como funciona

```
Usuário → tem Roles → cada Role tem Permissões (resource:action)
```

**Exemplo prático:**

```json
{
  "user": "joao@empresa.com",
  "roles": ["manager"],
  "permissions": [
    "users:read",
    "users:write",
    "access_requests:approve",
    "audit:read"
  ]
}
```

O RBAC é verificado em todos os endpoints pela dependência `require_roles()`, que inspeciona as roles extraídas do JWT do usuário autenticado.

---

## Controle de Acesso: ABAC

**Attribute-Based Access Control** — as decisões de acesso levam em conta atributos do **sujeito** (usuário) e do **recurso** (sistema), não apenas a role.

### Atributos suportados

| Sujeito (usuário) | Recurso (sistema) |
|---|---|
| `department` | `classification` |
| `location` | `owner_department` |
|  | `slug` |

### Exemplo de política ABAC

```json
{
  "name": "allow-ti-erp-read",
  "effect": "allow",
  "subject_attributes": { "department": "TI" },
  "resource_attributes": { "slug": "erp" },
  "actions": ["read", "access"]
}
```

Esta política permite que qualquer usuário do departamento **TI** acesse o sistema **ERP** com as ações `read` e `access`, independentemente de qual role ele possua.

### Fluxo de avaliação ABAC

```
1. Coletar atributos do usuário autenticado
2. Coletar atributos do recurso alvo
3. Para cada política ativa:
   a. Verificar se a ação está na lista de ações da política
   b. Verificar se os atributos do sujeito batem
   c. Verificar se os atributos do recurso batem
   d. Se tudo bate → retornar o efeito (allow / deny)
4. Se nenhuma política aplicar → negar por padrão
```

### RBAC + ABAC combinados

O IAM Lite usa os dois modelos em conjunto:

- **RBAC** para controle estrutural (quem pode fazer o quê globalmente)
- **ABAC** para decisões contextuais em solicitações de acesso a sistemas

---

## OAuth2 e OpenID Connect

O IAM Lite implementa os fluxos OAuth2 com extensão OpenID Connect:

### Tokens emitidos

| Token | Formato | Conteúdo |
|---|---|---|
| `access_token` | JWT assinado HS256 | sub, roles, iss, aud, exp |
| `refresh_token` | JWT assinado HS256 | sub, token_type=refresh |
| `id_token` | JWT assinado HS256 | sub, email, name, department |

### Fluxo Authorization Code (Password Grant — simplificado)

```
POST /auth/token
{
  "grant_type": "password",
  "username": "joao@empresa.com",
  "password": "Senha@2025!",
  "scope": "openid profile email"
}
```

Retorna `access_token`, `refresh_token` e `id_token`.

### Renovação de token

```
POST /auth/refresh
{ "grant_type": "refresh_token", "refresh_token": "<token>" }
```

### Validação (Introspection — RFC 7662)

```
POST /auth/introspect
{ "token": "<access_token>" }
```

Resposta quando válido:
```json
{ "active": true, "sub": "uuid", "roles": ["manager"], "exp": 1234567890 }
```

### Revogação

Ao revogar um token, ele é marcado no Redis imediatamente — qualquer requisição com esse token é rejeitada antes mesmo de consultar o banco de dados.

---

## Fluxo de Aprovação

Sistemas classificados como `critical` ou com `requires_approval=true` exigem revisão humana antes de liberar acesso.

### Diagrama do fluxo

```
Usuário solicita acesso (POST /access-requests)
        │
        ▼
O sistema verifica:
├─ É crítico e requer aprovação?
│   └─ SIM → status = "pending" → aguarda revisor
│
└─ Não requer aprovação E (RBAC ou ABAC permite)?
    └─ SIM → status = "approved" automaticamente
        │
        ▼
Gestor/Admin consulta solicitações pendentes
(GET /access-requests?status=pending)
        │
        ├─ PATCH /access-requests/{id}/approve
        │   └─ status = "approved", role atribuída ao usuário
        │
        └─ PATCH /access-requests/{id}/reject
            └─ status = "rejected", comentário registrado
```

### Exemplo prático

```bash
# 1. Colaborador solicita acesso ao ERP (crítico)
curl -X POST /access-requests \
  -H "Authorization: Bearer <token_colaborador>" \
  -d '{"system_id": "uuid-erp", "justification": "Relatório Q1"}'
# → { "status": "pending" }

# 2. Gestor lista solicitações pendentes
curl /access-requests?status=pending \
  -H "Authorization: Bearer <token_gestor>"

# 3. Gestor aprova
curl -X PATCH /access-requests/{id}/approve \
  -H "Authorization: Bearer <token_gestor>" \
  -d '{"comment": "Aprovado para relatório trimestral"}'
# → { "status": "approved" }
```

---

## Trilha de Auditoria (LGPD)

Todas as ações do sistema geram automaticamente um log de auditoria **imutável**:

- Nenhum endpoint permite edição ou exclusão de logs
- Cada entrada registra: **quem** (actor), **o quê** (action), **quando** (created_at), **de onde** (ip_address)
- Logs são indexados por `action`, `resource_type` e `created_at` para consultas eficientes

### Campos do log

| Campo | Descrição |
|---|---|
| `actor_email` | E-mail de quem executou a ação |
| `action` | Ação realizada (ex: `users.create`, `auth.login.failed`) |
| `resource_type` | Tipo do recurso afetado (ex: `user`, `role`) |
| `resource_id` | ID do recurso afetado |
| `system_id` | Sistema relacionado (quando aplicável) |
| `status` | `success` ou `failure` |
| `ip_address` | IP de origem da requisição |
| `detail` | Detalhes adicionais em JSON |

---

## Sistemas Fictícios Cadastrados

O seed popula o banco com os seguintes sistemas corporativos:

| Sistema | Slug | Classificação | Requer Aprovação |
|---|---|---|---|
| ERP Corporativo | `erp` | critical | Sim |
| CRM Comercial | `crm` | confidential | Não |
| Portal RH | `rh` | confidential | Sim |
| Intranet | `intranet` | internal | Não |

---

## Configuração e Execução

### Pré-requisitos

- Docker e Docker Compose
- Python 3.12+ (para desenvolvimento local)

### Execução com Docker

```bash
# 1. Clonar o repositório
git clone https://github.com/jmello04/iam-lite.git
cd iam-lite

# 2. Configurar variáveis de ambiente
cp .env.example .env
# Edite .env com seu SECRET_KEY

# 3. Subir os serviços
docker compose up -d

# 4. Executar migrations
docker compose exec api alembic upgrade head

# 5. Popular banco com dados iniciais
docker compose exec api python seed.py
```

### Execução local (desenvolvimento)

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
# Configure DATABASE_URL e REDIS_URL apontando para instâncias locais

alembic upgrade head
python seed.py
uvicorn main:app --reload
```

### Acessar a documentação

- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

### Credenciais do seed

| Usuário | E-mail | Senha | Role |
|---|---|---|---|
| Administrador | admin@iam-lite.local | Admin@2025! | admin |
| Gestora | gestor@empresa.com | Gestor@2025! | manager |
| Colaborador | colaborador@empresa.com | Viewer@2025! | viewer |

---

## Endpoints da API

### Autenticação

| Método | Endpoint | Descrição |
|---|---|---|
| POST | `/auth/token` | Login OAuth2 (password / client_credentials) |
| POST | `/auth/refresh` | Renovar access token via refresh token |
| POST | `/auth/introspect` | Validar token (RFC 7662) |
| POST | `/auth/revoke` | Revogar token |

### Usuários

| Método | Endpoint | Role Mínima |
|---|---|---|
| POST | `/users` | admin |
| GET | `/users` | manager |
| GET | `/users/{id}` | próprio usuário / manager |
| PATCH | `/users/{id}` | admin |
| DELETE | `/users/{id}` | admin |

### Roles & Permissões

| Método | Endpoint | Role Mínima |
|---|---|---|
| POST | `/roles` | admin |
| GET | `/roles` | manager |
| POST | `/roles/{id}/permissions` | admin |
| DELETE | `/roles/{id}/permissions/{perm_id}` | admin |

### Políticas ABAC

| Método | Endpoint | Role Mínima |
|---|---|---|
| POST | `/policies` | admin |
| GET | `/policies` | manager |
| DELETE | `/policies/{id}` | admin |

### Solicitações de Acesso

| Método | Endpoint | Role Mínima |
|---|---|---|
| POST | `/access-requests` | qualquer autenticado |
| GET | `/access-requests` | próprio / manager |
| PATCH | `/access-requests/{id}/approve` | manager |
| PATCH | `/access-requests/{id}/reject` | manager |

### Auditoria

| Método | Endpoint | Role Mínima |
|---|---|---|
| GET | `/audit/logs` | manager |

### Sistemas

| Método | Endpoint | Role Mínima |
|---|---|---|
| POST | `/systems` | admin |
| GET | `/systems` | qualquer autenticado |

---

## Testes

```bash
# Rodar todos os testes com cobertura
pytest tests/ -v --cov=app --cov-report=term-missing

# Rodar apenas testes de autenticação
pytest tests/test_auth.py -v

# Rodar apenas testes de controle de acesso
pytest tests/test_access_control.py -v

# Rodar apenas testes de auditoria
pytest tests/test_audit.py -v
```

Os testes utilizam banco SQLite em memória para máximo isolamento — sem necessidade de infraestrutura externa.

---

## Licença

MIT — livre para uso, modificação e distribuição.
