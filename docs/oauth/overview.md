# OAuth 2.0 Overview

The Identity Service provides a standards-aligned **OAuth 2.0 authorization
code flow** (RFC 6749) with **PKCE** (RFC 7636) and **OpenID Connect** (OIDC)
support. This document is the entry point for the OAuth documentation set.

## What Is Provided

- **Authorization endpoint** (`GET /api/v1/oauth/authorize`) — validates the
  client, redirect URI, response type, scopes and PKCE challenge, then
  redirects the browser to the hosted Identity UI.
- **Hosted transaction API** (`/api/v1/oauth/transactions/*`) — lets the
  Identity UI drive login, signup, password reset and email verification
  against a transaction-bound application context.
- **Token endpoint** (`POST /api/v1/oauth/token`) — exchanges authorization
  codes for access, refresh and ID tokens; also serves the existing
  client-credentials grant.
- **OIDC discovery** (`/.well-known/openid-configuration`) and a shared
  **JWKS** endpoint (`/.well-known/jwks.json`).

## Design Principles

1. **No tokens in redirects.** The callback URL contains only `code` and
   `state`. Authorization codes are short-lived (5 minutes) and single-use.
2. **Nothing sensitive at rest.** Raw authorization codes, password-reset
   tokens and email-verification tokens are **never persisted** — only their
   SHA-256 hashes.
3. **Atomic single-use.** Authorization codes are marked consumed inside a
   Firestore transaction, so double redemption is impossible (verified by
   concurrency tests).
4. **Exact redirect-URI matching.** No wildcards, no prefix matching, no
   schemes that can execute code.
5. **PKCE required** for the authorization code grant (`S256` only).
6. **Reuses existing infrastructure.** Same users, applications, Argon2id
   password hashing, Ed25519 signing keys and refresh-token rotation as the
   rest of the service.
7. **No implicit flow.** `response_type=token` and `response_type=id_token`
   are rejected.

## Flow At A Glance

```
Browser                Identity UI               Identity Service            Your App
  |  1. /oauth/authorize?client_id=&redirect_uri=     |                          |
  |--------------------------------------------------->|   validate + create      |
  |                                                    |   transaction            |
  |  2. 302 -> {identity_ui_base_url}/authorize?tx_..  |                          |
  |<---------------------------------------------------|                          |
  |--------------------------------------------------->|   GET /transactions/{id} |
  |                                                    |   (safe UI context)      |
  |  3. login / signup / reset / verify-email          |                          |
  |--------------------------------------------------->|   ...                    |
  |  4. 302 -> callback?code=&state=                   |                          |
  |--------------------------------------------------->|---------------------------> code captured
  |                                                    |  5. POST /oauth/token    |
  |                                                    |<--------------------------| code+verifier
  |                                                    | 6. access+refresh+id     |
  |                                                    |-------------------------->|
```

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/v1/oauth/authorize` | Authorization request entrypoint (browser redirect) |
| POST | `/api/v1/oauth/transactions` | Admin-only: create a transaction directly |
| GET | `/api/v1/oauth/transactions/{tx}` | Load safe transaction context for the UI |
| POST | `/api/v1/oauth/transactions/{tx}/login` | Transaction-bound login |
| POST | `/api/v1/oauth/transactions/{tx}/signup` | Transaction-bound signup |
| POST | `/api/v1/oauth/transactions/{tx}/forgot-password` | Initiate password reset (enumeration-safe) |
| POST | `/api/v1/oauth/transactions/{tx}/reset-password` | Complete password reset |
| POST | `/api/v1/oauth/transactions/{tx}/verify-email` | Verify email, continue toward code issuance |
| POST | `/api/v1/oauth/transactions/{tx}/cancel` | Cancel the transaction |
| POST | `/api/v1/oauth/token` | Token endpoint (`authorization_code`, `client_credentials`) |
| GET | `/api/v1/oauth/applications/{client_id}/configuration` | Public branding/auth config for the UI |
| POST | `/api/v1/oauth/password/reset` | Standalone password reset (outside a transaction) |
| GET | `/.well-known/openid-configuration` | OIDC discovery document |
| GET | `/.well-known/jwks.json` | Public signing keys (shared with existing JWTs) |

## Documentation Index

| Document | Content |
| --- | --- |
| [`authorization-flow.md`](authorization-flow.md) | Step-by-step end-to-end walkthrough |
| [`transactions.md`](transactions.md) | Transaction model, states and lifecycle |
| [`authorization-code.md`](authorization-code.md) | Code issuance, hashing, single-use redemption |
| [`pkce.md`](pkce.md) | PKCE requirements and implementation |
| [`token-exchange.md`](token-exchange.md) | Token endpoint, validation order, token model |
| [`scopes.md`](scopes.md) | Scopes and ID-token claims |
| [`errors.md`](errors.md) | Machine-readable error catalog |
| [`../oidc/overview.md`](../oidc/overview.md) | OpenID Connect support |
| [`../applications/configuration.md`](../applications/configuration.md) | Per-application OAuth/auth configuration |

## Configuration (environment)

| Setting | Default | Purpose |
| --- | --- | --- |
| `IDENTITY_UI_BASE_URL` | `http://localhost:3000` | Where the hosted UI lives |
| `PUBLIC_BASE_URL` | `http://localhost:8002` | Public origin used in discovery/endpoint URLs |
| `OIDC_ISSUER` | `http://localhost:8002` | `iss` claim of ID tokens |
| `OAUTH_TRANSACTION_EXPIRATION_MINUTES` | `10` | Transaction TTL |
| `OAUTH_AUTHORIZATION_CODE_EXPIRATION_MINUTES` | `5` | Authorization code TTL |
| `PASSWORD_RESET_TOKEN_EXPIRATION_MINUTES` | `30` | Reset-token TTL |
