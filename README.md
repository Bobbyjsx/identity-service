# Identity Service

A generic, centralized Identity and Authentication service built with FastAPI and Google Cloud Firestore. 

The Identity Service acts as the central authority for user identities, application/client isolation, authentication, and authorization. It issues secure JSON Web Tokens (JWTs) signed with Ed25519 asymmetric keys, allowing downstream microservices to verify authentication statelessly using a public JWKS endpoint.

## Features

- **Application & Tenant Isolation**: Securely isolates users, roles, and permissions across different registered applications using a strict multi-tenant data model.
- **Asymmetric JWT Issuance**: Issues short-lived access tokens and long-lived refresh tokens signed with highly secure Ed25519 cryptographic keys.
- **Stateless Verification**: Target services do not need to round-trip to the Identity Service for every request. They simply verify JWTs locally by fetching the public keys from `/.well-known/jwks.json`.
- **Role-Based Access Control (RBAC)**: Fine-grained roles and permissions management tied directly to users and applications.
- **Service-to-Service Auth**: Supports application credential issuance (Client ID and Client Secret) for secure machine-to-machine OAuth workflows.
- **Local Emulator Support**: Fully integrated with the Google Cloud Firestore Emulator via Docker for reliable local development and testing.

## Prerequisites

- Python 3.10+
- Docker & Docker Compose (for the local Firestore emulator)

## Getting Started

### 1. Environment Setup

1. Clone the repository and navigate into it.
2. Create and activate a Python virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```
3. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### 2. Configuration (`.env`)

The service relies on a `.env` file for configuration. Create a `.env` in the root directory:

```ini
ENVIRONMENT=development
FIRESTORE_DATABASE=identity-service
GOOGLE_APPLICATION_CREDENTIALS=firebase-credentials.json
JWT_EXPIRATION_MINUTES=15
REFRESH_TOKEN_EXPIRATION_DAYS=30

# The private key must be a PEM-encoded Ed25519 private key.
# If omitted in development, the service will generate one in memory and print it out.
PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n..."
```

*(Note: When you run the application in development without a `PRIVATE_KEY` defined, it will automatically generate a secure one and print the exact configuration string you need to paste into your `.env`.)*

### 3. Start the Firestore Emulator

Local development relies on the Google Cloud Firestore emulator via Docker Compose:

```bash
docker compose up -d firestore
```

### 4. Run the Service

Start the FastAPI application using Uvicorn:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8002 --reload
```

The service will be available at `http://localhost:8002`.
Interactive Swagger UI documentation is automatically generated at `http://localhost:8002/docs`.

---

## Testing

The test suite runs directly against the Firestore Emulator to guarantee high fidelity.

1. Ensure the emulator is running (`docker compose up -d firestore`).
2. Run pytest:
   ```bash
   PYTHONPATH=. pytest tests/ -v
   ```

---

## Architecture & Integration

### JWKS (JSON Web Key Set)
Downstream services authenticate requests by validating the JWT access token without directly calling the Identity Service. 
1. The target service retrieves the public keys from: `GET /api/v1/auth/.well-known/jwks.json`
2. It caches the public keys.
3. For incoming API requests, it locally verifies the `Authorization: Bearer <token>` signature using the cached public keys, ensuring the `exp` (expiration) and `aud` (audience) claims are valid.

### Core API Endpoints

- **Applications**: `POST /api/v1/applications` to register a new tenant application.
- **Auth**: `POST /api/v1/auth/signup` and `POST /api/v1/auth/login` to authenticate users.
- **RBAC**: `POST /api/v1/rbac/roles` and `POST /api/v1/rbac/permissions` to build authorization rules (restricted to admin users).
- **OAuth2**: `POST /api/v1/auth/oauth/token` OAuth2 Client Credentials grant for M2M service authentication
- **Refresh**: `POST /api/v1/auth/refresh` Refresh access tokens
- **Profile**: `GET /api/v1/auth/me` Retrieve authenticated user profile


*(For detailed endpoint schemas, run the service and navigate to `/docs`.)*

## Project Structure

```
├── app/
│   ├── core/           # Configuration, security, hashing, and exception handling
│   ├── dependencies.py # Dependency injection for routers (auth, db, services)
│   ├── main.py         # FastAPI application entrypoint
│   ├── repositories/   # Firestore data access layer (Role, User, App, Permission)
│   ├── routers/        # API route definitions (v1)
│   ├── schemas/        # Pydantic models for validation and responses
│   └── services/       # Core business logic and key management
├── tests/              # Pytest suite
├── docker-compose.yml  # Local Firestore emulator and service config
└── requirements.txt    # Python dependencies
```
