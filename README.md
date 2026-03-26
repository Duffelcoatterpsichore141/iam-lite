# IAM Lite

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green?logo=fastapi)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue?logo=postgresql)
![Redis](https://img.shields.io/badge/Redis-7-red?logo=redis)
![Docker](https://img.shields.io/badge/Docker-ready-blue?logo=docker)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

Plataforma centralizada de **Gerenciamento de Identidades e Acessos** com RBAC, ABAC, OAuth2/OIDC, fluxo de aprovação e trilha de auditoria em conformidade com a LGPD.
Projetada para ser simples de operar e fácil de estender em ambientes corporativos.

---

## Visao geral

Organizacoes que gerenciam multiplos sistemas internos enfrentam o desafio de controlar quem pode acessar o que, de onde e sob quais condicoes. O IAM Lite resolve esse problema oferecendo um ponto unico de controle de identidades, com suporte a politicas baseadas em atributos (ABAC), papeis hierarquicos (RBAC), emissao de tokens padrao OAuth2/OpenID Connect e um log de auditoria imutavel compativel com os requisitos de rastreabilidade da LGPD.

---

## Funcionalidades

- Autenticacao via **OAuth2 Password Flow** com emissao de `access_token`, `refresh_token` e `id_token`
- **RBAC** — tres perfis predefinidos (`admin`, `manager`, `viewer`) com permissoes granulares
- **ABAC** — politicas configuráveis baseadas em atributos do usuario (departamento, localizacao) e do recurso
- **Fluxo de aprovacao** — solicitacoes de acesso a sistemas com status `pending → approved/rejected`
- **Revogacao de tokens** com blocklist em Redis (RFC 7009)
- **Introspeccao de tokens** (RFC 7662)
- **Trilha de auditoria imutavel** — todos os eventos sao registrados; nenhum endpoint permite edicao ou exclusao
- Seed automatico com dados de exemplo prontos para desenvolvimento

---

## Arquitetura

O projeto segue uma arquitetura em camadas com responsabilidades bem delimitadas:

```
HTTP Request
    │
    ▼
┌─────────────────────────────────┐
│  Routes  (app/api/routes/)      │  Validacao de entrada, autorizacao, resposta HTTP
└─────────────────┬───────────────┘
                  │
                  ▼
┌─────────────────────────────────┐
│  Services  (app/services/)      │  Regras de negocio, orquestracao, cache
└─────────────────┬───────────────┘
                  │
                  ▼
┌─────────────────────────────────┐
│  Domain Models (app/domain/)    │  Entidades SQLAlchemy + esquemas Pydantic
└─────────────────┬───────────────┘
                  │
                  ▼
┌─────────────────────────────────┐
│  Infra  (app/infra/)            │  Sessao PostgreSQL + cliente Redis
└─────────────────────────────────┘
```

- **Routes** delegam toda logica de negocio para os services; nunca acessam o banco diretamente.
- **Services** sao instancias singleton sem estado, injetadas via modulo.
- **Domain/models** usa SQLAlchemy 2 com `Mapped` e `mapped_column` para tipagem completa.
- **Domain/schemas** usa Pydantic v2 para validacao de entrada e serializacao de saida.

---

## Stack

| Componente | Tecnologia | Motivo |
|---|---|---|
| API framework | FastAPI 0.111 | Suporte nativo a OpenAPI, tipagem, async |
| ORM | SQLAlchemy 2 | Suporte a `Mapped`, sessao gerenciada, migrações via Alembic |
| Banco de dados | PostgreSQL 16 | ACID, JSON nativo, maturidade |
| Cache / blocklist | Redis 7 | Sub-millisecond para verificacao de tokens revogados |
| Tokens | `python-jose` + `bcrypt` | JWT padrao com hashing seguro de senhas |
| Validacao | Pydantic v2 | Desempenho, integração nativa com FastAPI |
| Migrações | Alembic | Controle de versao do schema desacoplado do ORM |
| Servidor ASGI | Uvicorn | Baixa latencia, suporte a HTTP/2 |

---

## Como rodar localmente

### Com Docker (recomendado)

```bash
# 1. Clone o repositorio
git clone https://github.com/jmello04/iam-lite.git
cd iam-lite

# 2. Crie o arquivo de variaveis de ambiente
cp .env.example .env
# Edite .env e defina SECRET_KEY, FIRST_ADMIN_EMAIL, FIRST_ADMIN_PASSWORD

# 3. Suba os servicos
docker compose up -d --build

# 4. Execute o seed (opcional — popula dados de exemplo)
docker compose exec api python seed.py

# 5. Acesse a documentacao interativa
open http://localhost:8000/docs
```

### Sem Docker

**Pre-requisitos:** Python 3.12+, PostgreSQL 16, Redis 7.

```bash
# 1. Crie e ative o ambiente virtual
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 2. Instale as dependencias
pip install -r requirements.txt

# 3. Configure as variaveis de ambiente
cp .env.example .env
# Edite .env com as suas credenciais locais

# 4. Execute as migracoes
alembic upgrade head

# 5. Opcional: execute o seed
python seed.py

# 6. Inicie o servidor
uvicorn main:app --reload
```

---

## Variaveis de ambiente

Copie `.env.example` para `.env` e preencha os valores. Nenhum arquivo `.env` deve ser
versionado.

| Variavel | Descricao | Exemplo |
|---|---|---|
| `APP_NAME` | Nome exibido na documentacao da API | `IAM Lite` |
| `APP_ENV` | Ambiente de execucao (`development`, `production`) | `development` |
| `DEBUG` | Ativa logs SQL do SQLAlchemy | `false` |
| `SECRET_KEY` | Chave HMAC para assinatura de JWTs — gere com `openssl rand -hex 32` | — |
| `ALGORITHM` | Algoritmo JWT | `HS256` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Validade do access token em minutos | `30` |
| `REFRESH_TOKEN_EXPIRE_DAYS` | Validade do refresh token em dias | `7` |
| `ID_TOKEN_EXPIRE_MINUTES` | Validade do id token em minutos | `60` |
| `DATABASE_URL` | DSN completo do PostgreSQL | `postgresql://user:pass@localhost:5432/iam_lite` |
| `POSTGRES_USER` | Usuario do PostgreSQL (usado pelo Docker Compose) | `iam_user` |
| `POSTGRES_PASSWORD` | Senha do PostgreSQL (usada pelo Docker Compose) | — |
| `POSTGRES_DB` | Nome do banco (usado pelo Docker Compose) | `iam_lite` |
| `REDIS_URL` | DSN do Redis | `redis://localhost:6379/0` |
| `REDIS_PASSWORD` | Senha do Redis (opcional) | — |
| `OAUTH2_ISSUER` | URL base do emissor de tokens | `http://localhost:8000` |
| `OAUTH2_AUDIENCE` | Audience do JWT | `iam-lite-api` |
| `FIRST_ADMIN_EMAIL` | E-mail do admin criado pelo seed — **obrigatorio** | `admin@example.com` |
| `FIRST_ADMIN_PASSWORD` | Senha do admin criado pelo seed — **obrigatorio** | — |

---

## Como rodar os testes

```bash
# Com ambiente virtual ativo e dependencias instaladas
pytest tests/ -v

# Com relatorio de cobertura
pytest tests/ -v --cov=app --cov-report=term-missing
```

Os testes usam `fakeredis` para simular o Redis e um banco SQLite em memoria — nenhuma
infraestrutura externa e necessaria.

---

## Estrutura de pastas

```
iam-lite/
├── app/
│   ├── api/
│   │   └── routes/          # Endpoints FastAPI (um arquivo por dominio)
│   │       ├── auth.py      # /auth — token, refresh, introspect, revoke
│   │       ├── users.py     # /users — CRUD de usuarios
│   │       ├── roles.py     # /roles — CRUD de roles e permissoes
│   │       ├── policies.py  # /policies — ABAC policies
│   │       ├── systems.py   # /systems — sistemas gerenciados
│   │       ├── access_requests.py  # /access-requests — fluxo de aprovacao
│   │       ├── audit.py     # /audit — consulta de logs
│   │       └── deps.py      # Dependencias compartilhadas (auth, RBAC)
│   ├── core/
│   │   ├── config.py        # Configuracoes carregadas do .env via Pydantic Settings
│   │   ├── security.py      # Hashing, geracao e decodificacao de JWTs
│   │   └── permissions.py   # Mapa estatico de permissoes por role
│   ├── domain/
│   │   ├── models/          # Entidades SQLAlchemy
│   │   └── schemas/         # Esquemas Pydantic (request/response)
│   ├── infra/
│   │   ├── database/        # Engine, sessao e Base declarativa
│   │   └── redis/           # Pool de conexao e TokenStore
│   └── services/            # Camada de servico (logica de negocio)
│       ├── user_service.py
│       ├── role_service.py
│       ├── policy_service.py
│       └── audit_service.py
├── migrations/              # Scripts Alembic
│   └── versions/
├── tests/                   # Suite de testes
├── main.py                  # Ponto de entrada FastAPI (app instance, middlewares, routers)
├── seed.py                  # Script de populacao inicial do banco
├── Dockerfile               # Build multi-stage (builder + runner)
├── docker-compose.yml       # Orquestracao local (api + postgres + redis)
├── .env.example             # Modelo de variaveis de ambiente
└── requirements.txt         # Dependencias Python fixadas
```

---

## Licenca

Distribuido sob a licenca **MIT**. Consulte o arquivo `LICENSE` para os termos completos.
