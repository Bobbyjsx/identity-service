# OAuth / OIDC Backend Implementation Report

## 1. Executive Summary

The Identity Service now provides a standards-aligned OAuth 2.0 authorization
code flow (RFC 6749) with mandatory PKCE (RFC 7636) and OpenID Connect
support, backed by a stateful server-side transaction model and a hosted
Identity UI contract. All previously existing auth/application/JWT
functionality is preserved and unchanged. Implementation is complete,
verified by 89 passing integration tests against the Firestore emulator, with
a clean lint pass.

**Delivered**

- Authorization endpoint validating client, redirect URI, response type,
  scopes and PKCE challenge.
- OAuth transactions with a pending/authenticated/completed/cancelled/expired
  lifecycle and transaction-bound login, signup, forgot/reset password,
  verify-email and cancel operations.
- Short-lived (5 min), single-use authorization codes, SHA-256 hashed at
  rest, redeemed atomically via Firestore transactions.
- Token endpoint serving `authorization_code` (PKCE required) and the
  pre-existing `client_credentials` grant.
- OIDC ID tokens, discovery document, shared JWKS.
- Email verification and password reset token flows through a notification
  boundary (dev stub provided).
- Per-application OAuth/authentication/branding configuration with admin and
  public endpoints.
- 6 test suites (85 new tests) covering the full feature set plus security
  hardening cases.

## 2. Flow Diagram

```
Browser             Identity UI                Identity Service               Client app
  |  1 authorize req (client_id, redirect_uri, scope, state,      |              |
  |     nonce, code_challenge)                                     |              |
  |--------------------------------------------------------------->| validate    |
  |                   2 302 → {ui}/authorize?transaction_id=tx_..  | create tx    |
  |<---------------------------------------------------------------|             |
  |                   3 GET /oauth/transactions/{tx} (safe ctx)    |             |
  |<-------------------------------------------------------------->|             |
  |                   4 login | signup | reset | verify-email      |             |
  |<--------------------------------------------------------------->|             |
  |  5 302 → <redirect_uri>?code=code_..[&state=..]                |             |
  |----------------------------------------------------------------------------->|
  |                                                                | 6 POST /oauth/token
  |                                                                |   code+verifier
  |                                                                |<------------|
  |                                                                | 7 access+refresh+id_token
  |                                                                |------------->|
```

## 3. Endpoint Inventory

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/v1/oauth/authorize` | Authorization entrypoint (browser redirect) |
| POST | `/api/v1/oauth/transactions` | Admin: create a transaction directly |
| GET | `/api/v1/oauth/transactions/{tx}` | Safe UI context |
| POST | `/api/v1/oauth/transactions/{tx}/login` | Transaction-bound login |
| POST | `/api/v1/oauth/transactions/{tx}/signup` | Transaction-bound signup |
| POST | `/api/v1/oauth/transactions/{tx}/forgot-password` | Reset initiation (enumeration-safe) |
| POST | `/api/v1/oauth/transactions/{tx}/reset-password` | Reset completion |
| POST | `/api/v1/oauth/transactions/{tx}/verify-email` | Email verification |
| POST | `/api/v1/oauth/transactions/{tx}/cancel` | Abort transaction |
| POST | `/api/v1/oauth/token` | Token endpoint (2 grants) |
| GET | `/api/v1/oauth/applications/{client_id}/configuration` | Public branding/auth config |
| POST | `/api/v1/oauth/password/reset` | Standalone password reset |
| GET | `/.well-known/openid-configuration` | OIDC discovery |
| GET | `/.well-known/jwks.json` | Public keys (shared) |
| GET/PATCH | `/api/v1/applications/{client_id}/configuration` | Admin config read/update |
| POST | `/api/v1/applications` | Application registration (unchanged) |
| POST | `/api/v1/auth/oauth/token` | Legacy client-credentials endpoint (unchanged) |

## 4. Firestore Schema

| Collection | Documents | Notes |
| --- | --- | --- |
| `applications` | app config + credentials | extended with `branding`, `authentication`, `oauth` |
| `application_credentials` | `app_id`, `hashed_secret` | unchanged |
| `users` | existing user model | gained `email_verified` |
| `refresh_tokens` | existing | unchanged; revocation on password reset |
| `oauth_transactions` | id = `tx_<32>`; status, redirect_uri, scopes, challenge, nonce, state, expires_at | lookup by id |
| `authorization_codes` | id = `code_<48>` (auto); `code_hash`, binds, status active/used, expires_at | queried by `code_hash` |
| `password_reset_tokens` | `user_id`, `app_id`, `token_hash`, expires_at | queried by `token_hash` |
| `email_verification_tokens` | `user_id`, `app_id`, `token_hash`, expires_at | queried by `token_hash` |

**Indexes**: equality lookups only — no composite indexes required. Document
`expires_at` TTLs are enforced logically (records with expired timestamps are
rejected at use); scheduled deletion of stale documents (e.g. > 24h old) is a
recommended deployment job to bound collection growth — correctness does not
depend on cleanup.

## 5. Token Model

| Token | Type | Audience | Lifetime | Use |
| --- | --- | --- | --- | --- |
| access token | `user` | `application_api` | 15 min (`jwt_expiration_minutes`) | Call resource APIs |
| refresh token | opaque 48-char | — | 7 days, rotating | Re-issue access tokens |
| service token | `service` | requested `audience` | 15 min | Machine-to-machine |
| ID token | OIDC | `client_id` | 15 min | Client-side identity only |

ID tokens carry `iss=oidc_issuer`, `sub`, `aud=client_id`, `jti`, optional
`nonce`, and scope-gated `email`/`email_verified`/`name`/`preferred_username`.
All JWTs are Ed25519-signed (shared keys; JWKS at `/.well-known/jwks.json`).

## 6. Security Model

- **Redirect URIs**: exact-match only; https required (http ↔ localhost);
  dangerous schemes and fragments rejected at registration and runtime.
- **PKCE**: `S256` mandatory for `authorization_code`; `plain` rejected.
- **Codes**: 48-random-byte values, SHA-256 hashed at rest, 5-minute TTL,
  atomic single-use redemption inside a Firestore transaction (double
  redemption impossible; concurrency tested).
- **Transaction secrets**: `code_challenge`/`nonce`/`state`/`client_secret`
  never returned by API responses; callback redirect contains only
  `code` + `state`.
- **Error handling**: structured `OAuthError` → `{"error", "error_description"}`;
  no stack traces; forgot-password is enumeration-safe.
- **Scopes**: explicit per-application allow-list; unknown scopes reject the
  authorization request; ID tokens never contain credentials.
- **Deterministic validation order** at token exchange (13 checks) before any
  token is issued.

## 7. Test Results

```
pytest tests/ → 89 passed, 10 warnings in ~18s
ruff check app/ tests/ → All checks passed!
```

| Suite | Tests | Coverage |
| --- | --- | --- |
| `test_applications.py` | 8 | config schema, admin endpoints, redirect validation, public config |
| `test_oauth_authorization.py` | 18 | authorize endpoint, PKCE, scopes, errors, redirects |
| `test_oauth_login_signup.py` | 14 | transaction auth flows, verification gating |
| `test_oauth_token.py` | 19 | exchange, expiry, client binding, concurrency, rotation |
| `test_password_reset.py` | 9 | hashed tokens, expiry, standalone + transaction flows |
| `test_oauth_security.py` | 17 | ID token audit/JWKS, secret leakage, audience, callback hygiene |
| original auth/rbac suites | — | preserved and passing |

## 8. Breaking Changes

- **None.** All pre-existing endpoints, token formats and behaviors are
  unchanged. The `Token` response schema gained an optional `id_token` field,
  which is additive.
- `client_credentials` failures at `/api/v1/oauth/token` now return OAuth
  error shapes instead of generic 400s — a response-*shape* improvement, not
  a flow change. The legacy `/api/v1/auth/oauth/token` endpoint is untouched.

## 9. Configuration Changes

New environment variables (defaults shown; also documented in `.env.example`):

```
IDENTITY_UI_BASE_URL=http://localhost:3000
PUBLIC_BASE_URL=http://localhost:8002
OIDC_ISSUER=http://localhost:8002
OAUTH_TRANSACTION_EXPIRATION_MINUTES=10
OAUTH_AUTHORIZATION_CODE_EXPIRATION_MINUTES=5
PASSWORD_RESET_TOKEN_EXPIRATION_MINUTES=30
```

## 10. Migrations

No data migration required. Application getters apply defaults for absent
config fields; existing applications immediately support the flow once a
redirect URI is registered via the admin PATCH endpoint.

## 11. Manual Setup

```bash
docker compose up -d firestore          # Firestore emulator @127.0.0.1:8080
.venv/bin/python -m pytest tests/       # 89 passed
.venv/bin/uvicorn app.main:app --port 8002 --reload
curl -X POST http://localhost:8002/api/v1/applications \
  -H "X-Admin-Token: $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"Demo","config":{"oauth":{"redirect_uris":["https://app.example.com/callback"]}}}'
curl http://localhost:8002/.well-known/openid-configuration
```

## 12. Frontend (Identity UI) Contract

1. `GET /api/v1/oauth/transactions/{tx}` → render branding, scopes, auth
   options from the response.
2. Drive login/signup/reset/verify through the transaction endpoints.
3. On `redirect_url` in a response → `window.location = redirect_url`.
4. Handle `email_verification_required` → show "check your inbox" state and
   poll/submit `verify-email` when the user returns with the token.
5. `error`/`error_description` fields are machine-readable (catalog in
   `docs/oauth/errors.md`).

## 13. Integration Guide (Client Apps)

- Register redirect URIs via the admin PATCH configuration endpoint.
- Authorization request: see `docs/oauth/authorization-flow.md`.
- Token exchange & validation order: see `docs/oauth/token-exchange.md`.
- OIDC verification: see `docs/oidc/overview.md`.
- Scope semantics: see `docs/oauth/scopes.md`.

## 14. Limitations & Known Constraints

- `AsyncTransaction.get(ref)` is broken in the installed
  `google-cloud-firestore` 2.28.1; single-use redemption uses an in-transaction
  stream query workaround (`app/repositories/authorization_code.py`). Revisit
  on library upgrade.
- Email delivery is a **notification boundary**: `LoggingNotificationService`
  is a dev stub. A production provider (SMTP/provider SDK) must implement
  `NotificationService` — before that, reset/verification tokens are only
  logged, never delivered.
- OAuth transaction and token expiry are enforced logically; stale Firestore
  documents are not auto-purged (scheduled cleanup recommended).
- `client_id` used as the application context header (`X-Application-Id`) is
  still the client identifier shared with the API; the `app_id` claim remains
  the internal document id.

## 15. Next Steps (Suggested)

1. Production email provider behind `NotificationService`.
2. Stale-document cleanup job (transactions, codes, one-time tokens).
3. Grace-period key rotation for JWKS (already flagged in
   `docs/architecture/current-state.md`).
4. Optional: WebAuthn/passkeys and session management hardening for the hosted UI.
5. Rate limiting on transaction auth endpoints to mitigate online guessing.