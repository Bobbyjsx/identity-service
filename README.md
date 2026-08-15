# Identity Service

A multi-tenant identity provider. You register an application, users belong
to that application, and this service issues Ed25519-signed JWTs that your
APIs verify locally from a JWKS endpoint.

It is the identity provider — not a wrapper around one. The hosted login UI
collects credentials; this service stores users, runs OAuth, and signs tokens.

## Docs

The README is setup. The docs are how the system works.

| Document | Contents |
| --- | --- |
| [Docs index](docs/README.md) | Where to start |
| [How it works](docs/how-it-works.md) | Parties, tenancy, how data moves |
| [Create an application](docs/create-an-app.md) | Register an app and sign a user in |
| [OAuth lifecycle](docs/oauth-lifecycle.md) | Redirect flow between your app, this service, and the login UI |
| [Tokens](docs/tokens.md) | Access, refresh, ID, and service tokens |
| [Reference](docs/reference.md) | Endpoints, environment, errors, collections |

## What you get

- **Application isolation.** Users, roles, and tokens are scoped to the
  application you register. The same email on two applications is two users.
- **Two login paths.** Direct email/password against `/api/v1/auth/*`, or
  OAuth 2.0 authorization code with PKCE and optional OpenID Connect.
- **Stateless verification.** Downstream services cache
  `/.well-known/jwks.json` and check `Authorization: Bearer` locally.
- **Machine-to-machine.** Client credentials grant for service tokens.
- **Local emulator.** Firestore via Docker Compose.

## Prerequisites

- Python 3.10+
- Docker and Docker Compose (Firestore emulator)

## Getting started

### 1. Environment

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` in the repo root:

```ini
ENVIRONMENT=development
FIRESTORE_DATABASE=identity-service
GOOGLE_APPLICATION_CREDENTIALS=firebase-credentials.json
ADMIN_SECRET=changeme-in-prod
JWT_EXPIRATION_MINUTES=15

# PEM-encoded Ed25519 private key. If omitted in development, the process
# generates one and prints the line to paste back here.
PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n..."

IDENTITY_UI_BASE_URL=http://localhost:3000
PUBLIC_BASE_URL=http://localhost:8002
OIDC_ISSUER=http://localhost:8002
```

The full list of settings is in [Reference](docs/reference.md#environment).

### 2. Firestore emulator

```bash
docker compose up -d firestore
```

### 3. Run the service

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8002 --reload
```

- API: `http://localhost:8002`
- OpenAPI UI: `http://localhost:8002/docs`
- Health: `http://localhost:8002/health`

### 4. Create an application

```bash
curl -s http://localhost:8002/api/v1/applications \
  -H "X-Admin-Token: $ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"name":"Storefront"}'
```

That returns a `client_id` and a one-time `client_secret`. From there,
[Create an application](docs/create-an-app.md) covers configuration, user
login, OAuth, and machine-to-machine tokens.

## Testing

Tests run against the Firestore emulator.

```bash
docker compose up -d firestore
PYTHONPATH=. pytest tests/ -v
```

Or `make test`.

## Project structure

```
app/
  core/           configuration, Firestore, hashing, errors
  routers/        HTTP surface
  services/       application, auth, oauth, rbac, keys
  repositories/   Firestore access
  schemas/        request and document shapes
  dependencies.py admin token, application header, current user
  main.py         startup and middleware
docs/             how the system works
tests/            pytest against the emulator
```
