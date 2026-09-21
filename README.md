# Identity Service

A multi-tenant identity provider. You register an application, users belong
to that application, and this service issues Ed25519-signed JWTs that your
APIs verify locally from a JWKS endpoint.

It is the identity provider — not a wrapper around one. The hosted login UI
collects credentials; this service stores users, runs OAuth, and signs tokens.

## Docs

The README is setup and deployment. The docs explain how the system works.

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

- Python 3.12+
- [uv](https://github.com/astral-sh/uv) (fast Python package and environment manager)
- Docker and Docker Compose (for local Firestore emulator and container runs)

## Getting started

### 1. Environment & Dependencies

Install dependencies using `uv`:

```bash
uv sync
```

Create a `.env` in the repo root:

```ini
ENVIRONMENT=development
FIRESTORE_DATABASE=identity-service
GOOGLE_APPLICATION_CREDENTIALS=firebase-credentials.json
ADMIN_SECRET=changeme-in-prod
IDENTITY_ISSUER=http://localhost:8002
JWT_EXPIRATION_MINUTES=15

# PEM-encoded Ed25519 private key. If omitted in development, the process
# generates one and prints the line to paste back here.
PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n..."

IDENTITY_UI_BASE_URL=http://localhost:3000
PUBLIC_BASE_URL=http://localhost:8002
```

The full list of settings is in [Reference](docs/reference.md#environment).

### 2. Firestore emulator

```bash
docker compose up -d firestore
```

### 3. Run the service

```bash
uv run uvicorn app.main:app --host 0.0.0.0 --port 8002 --reload
```

- API: `http://localhost:8002`
- OpenAPI UI: `http://localhost:8002/docs`
- Health: `http://localhost:8002/health`

### 4. Create an application

```bash
curl -s http://localhost:8002/api/v1/admin/applications \
  -H "X-Admin-Token: $ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"name":"Storefront"}'
```

That returns a `client_id` and a one-time `client_secret`. From there,
[Create an application](docs/create-an-app.md) covers configuration, user
login, OAuth, and machine-to-machine tokens.

## Testing & Linting

Tests run against the Firestore emulator using `uv`:

```bash
make lint   # runs: uv run ruff check .
make test   # automatically manages the Firestore emulator container and runs pytest
```

---

## Deployment to VM (CI/CD Workflow)

This service is deployed to an internal GCP Compute Engine VM instance (`bobs-vm`) running Docker Compose behind **Cloudflare Zero Trust Tunnels**.

### Architecture Overview

```
[Developer Pull Request]
       │
       ▼
[GitHub Actions CI]  ────────► Runs `make lint` & `make test` via `uv` (conserves CircleCI credits)
       │
       ▼ (PR Merged to `main`)
[CircleCI Pipeline]
       ├─► 1. `test`: Runs `make test` on an Ubuntu machine runner
       ├─► 2. `build-and-push`: Builds Docker image via `uv` and pushes to GCR
       │      (`gcr.io/$GCP_PROJECT_ID/identity-service:latest` & `:SHA`)
       └─► 3. `trigger-deploy`: Dispatches signed webhook POST request to VM
              │
              ▼
[Cloudflare Tunnel] (deploy.bobslab.xyz)
       │
       ▼
[VM Webhook Container] (Port 9001 on internal `webnet` network)
       ├─► Validates per-container secret (`X-Webhook-Secret`)
       ├─► Obtains ephemeral GCR access token from GCP VM Metadata Server
       ├─► Authenticates Docker daemon with GCR
       └─► Executes `docker compose pull identity-service && docker compose up -d identity-service`
```

### Key Security & Design Principles

1. **Zero Secret Exposure in Repositories**:
   - The application repository `.circleci/config.yml` contains no VM IP addresses, no SSH private keys, and no production credentials.
   - All GCR credentials, webhook tokens, and target URLs are injected securely via CircleCI Context (`identity-service`).

2. **Per-Container Secret Verification**:
   - The deployment receiver enforces strict HMAC comparison of `X-Webhook-Secret`. Any invalid or unauthenticated request returns `401 Unauthorized` without executing any system actions.

3. **Instance Metadata GCR Authentication**:
   - The VM deployment receiver uses the Compute Engine internal metadata endpoint (`http://metadata.google.internal`) to fetch short-lived OAuth tokens for Docker registry authentication. No static GCP service account keys are stored on disk on the VM.

4. **Public Ingress & DNS**:
   - Public API Hostname: `https://vm-id.bobslab.xyz` &rarr; routed securely over Cloudflare Tunnel directly to the `identity-service:8001` container.
   - Webhook Hostname: `https://deploy.bobslab.xyz` &rarr; routed securely over Cloudflare Tunnel to the `deploy-webhook:9001` receiver.
   - Hosted Web UI: `https://id.bobslab.xyz`.

---

## Project structure

```
.circleci/        CircleCI deployment pipeline config
.github/          GitHub Actions PR CI workflows
app/
  core/           configuration, Firestore, hashing, errors
  routers/        HTTP surface (Auth, OAuth 2.0 PKCE, Admin, RBAC)
  services/       application, auth, oauth, rbac, keys
  repositories/   Firestore access
  schemas/        request and document shapes
  dependencies.py admin token, application header, current user
  main.py         startup and middleware
docs/             how the system works
tests/            pytest against the emulator
Dockerfile        production multi-stage uv container definition
Makefile          standardized developer tooling (uv sync, lint, test)
pyproject.toml    project dependencies and tools configuration
uv.lock           deterministic lockfile generated by uv
```
