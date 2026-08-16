# Reference

Lookup page for endpoints, configuration, errors, and collections. For
the story of how these pieces fit together, start at
[How it works](how-it-works.md).

Interactive request schemas are at `/docs` when the service is running.

## Endpoints

### Applications

Admin routes require `X-Admin-Token`.

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| POST | `/api/v1/applications` | admin | Register an application. Returns `client_id` and `client_secret` once. |
| GET | `/api/v1/applications/{client_id}/configuration` | admin | Full configuration, no secret. |
| PATCH | `/api/v1/applications/{client_id}/configuration` | admin | Merge branding, authentication, and OAuth settings. |
| GET | `/api/v1/applications/{client_id}/configuration` | public | Branding and auth options for the Identity UI. No secret, no redirect URIs. |

### Direct auth

These routes take `X-Application-Id` (the `client_id`) except refresh
and `/me`.

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/v1/auth/signup` | Create a user in that application. |
| POST | `/api/v1/auth/login` | Email + password → access and refresh tokens. |
| POST | `/api/v1/auth/refresh` | Rotate a refresh token. |
| GET | `/api/v1/auth/me` | Current user from a Bearer access token. |
| POST | `/api/v1/oauth/token` | Legacy client-credentials grant. Prefer `/api/v1/oauth/token`. |

### OAuth / OIDC

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/v1/oauth/authorize` | Browser entry. Validates the request, creates an auth session, redirects to the Identity UI. |
| POST | `/api/v1/admin/auth-sessions` | Admin: create an auth session without a browser redirect. |
| GET | `/api/v1/auth-sessions/{session_id}` | Safe context for the Identity UI. |
| POST | `/api/v1/auth-sessions/{session_id}/login` | Session-bound login. |
| POST | `/api/v1/auth-sessions/{session_id}/signup` | Session-bound signup. |
| POST | `/api/v1/auth-sessions/{session_id}/forgot-password` | Start reset. Enumeration-safe. |
| POST | `/api/v1/auth-sessions/{session_id}/reset-password` | Finish reset inside an auth session. |
| POST | `/api/v1/auth-sessions/{session_id}/verify-email` | Confirm email, then issue the code. |
| POST | `/api/v1/auth-sessions/{session_id}/cancel` | Abort. |
| POST | `/api/v1/oauth/token` | `authorization_code` (PKCE required) or `client_credentials`. |
| POST | `/api/v1/auth/password/reset` | Finish a reset outside an auth session. |
| GET | `/.well-known/openid-configuration` | OIDC discovery. |
| GET | `/.well-known/jwks.json` | Public signing keys. |

### RBAC

Both require `X-Application-Id`.

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/v1/rbac/permissions` | Create a permission. |
| GET | `/api/v1/rbac/permissions` | List permissions for the application. |
| POST | `/api/v1/rbac/roles` | Create a role that names existing permissions. |
| GET | `/api/v1/rbac/roles` | List roles for the application. |

### Ops

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Liveness. `{"status":"ok"}`. |

## Environment

| Variable | Default | Used for |
| --- | --- | --- |
| `ENVIRONMENT` | `development` | `production` refuses to start without `PRIVATE_KEY`. |
| `FIRESTORE_DATABASE` | `(default)` | Firestore database id. |
| `GOOGLE_APPLICATION_CREDENTIALS` | `firebase-credentials.json` | Service-account file. Unused when the emulator is set via `FIRESTORE_EMULATOR_HOST`. |
| `ADMIN_SECRET` | `changeme-in-prod` | Value of `X-Admin-Token`. |
| `IDENTITY_ISSUER` | `http://localhost:8002` | Canonical `iss` on access, service, and ID tokens, and in OIDC discovery. |
| `PRIVATE_KEY` | unset | PEM-encoded Ed25519 private key. Generated ephemerally in development if missing. |
| `JWT_EXPIRATION_MINUTES` | `15` | Access, ID, and service token lifetime. |
| `IDENTITY_UI_BASE_URL` | `http://localhost:3000` | Where `/authorize` sends the browser. |
| `PUBLIC_BASE_URL` | `http://localhost:8002` | Origin used in discovery endpoint URLs. |
| `AUTH_SESSION_EXPIRATION_MINUTES` | `10` | How long a login session stays usable. |
| `OAUTH_AUTHORIZATION_CODE_EXPIRATION_MINUTES` | `5` | How long a `code` can be exchanged. |
| `PASSWORD_RESET_TOKEN_EXPIRATION_MINUTES` | `30` | Reset-token lifetime. |

`REFRESH_TOKEN_EXPIRATION_DAYS` is accepted by settings but refresh
tokens are issued with a 7-day lifetime in code. Treat 7 days as the
real value until that is wired through.

## Application configuration shape

Stored on the application document.

```json
{
  "name": "Storefront",
  "description": "Customer accounts",
  "client_id": "app_…",
  "client_type": "public",
  "status": "active",
  "branding": {
    "logo_url": "https://cdn.example.com/logo.png",
    "primary_color": "#111827",
    "secondary_color": "#4F46E5"
  },
  "authentication": {
    "allow_signup": true,
    "allow_password_login": true,
    "require_email_verification": false
  },
  "oauth": {
    "redirect_uris": ["https://app.example.com/callback"],
    "allowed_scopes": ["openid", "profile", "email"],
    "allowed_grants": ["authorization_code"]
  }
}
```

Known scopes: `openid`, `profile`, `email`. `offline_access` is not
supported. Refresh tokens are issued under this service's normal session
policy, not that scope.

Known grants: `authorization_code` (default), `client_credentials`
(opt-in). Known client types: `public` (default), `confidential`.

Existing applications without `client_type` are treated as `public`.
Existing applications without `oauth.allowed_grants` receive
`["authorization_code"]` only. If a deployed application relied on the
old implicit `client_credentials` default, enable that grant explicitly.

## Errors

OAuth routes render:

```json
{ "error": "invalid_grant", "error_description": "Authorization code has already been used" }
```

Authorize-time failures, once the redirect URI is known, are instead
returned as a 302 to that URI with `error`, `error_description`, and
`state` (state only if the request had one).

| `error` | Typical HTTP | When |
| --- | --- | --- |
| `invalid_client` | 400 / 401 / 404 | Unknown or inactive client, or bad client secret. |
| `invalid_redirect_uri` | 400 | Redirect URI is not registered, or is unsafe. |
| `unsupported_response_type` | 400 | `response_type` is not `code`. |
| `invalid_request` | 400 | Missing field, `plain` PKCE, missing audience on client credentials. |
| `invalid_scope` | 400 | A requested scope is not in `allowed_scopes`. |
| `invalid_grant` | 400 | Code missing, expired, used, mismatched, PKCE failed, grant disabled, user gone. |
| `unsupported_grant_type` | 400 | `grant_type` is not `authorization_code` or `client_credentials`. |
| `unauthorized_client` | 400 | The requested grant is not enabled for this application. |
| `server_error` | 500 | Unexpected infrastructure failure. No internal details. |
| `invalid_session` | 404 | Unknown session id. |
| `session_expired` | 400 | Session TTL elapsed. |
| `session_completed` | 400 | Operation on a finished session. |
| `session_cancelled` | 400 | Operation on an aborted session. |
| `email_verification_required` | 400 | Signed in, but the application requires a verified email. |
| `invalid_credentials` | 401 | Bad email or password on session login. |
| `signup_disabled` | 400 / 403 | `allow_signup` is false. |
| `password_login_disabled` | 400 | `allow_password_login` is false. |
| `invalid_reset_token` / `reset_token_expired` | 400 | Password reset token is bad, used, or expired. |
| `invalid_verification_token` / `verification_token_expired` | 400 | Email verification token is bad, used, or expired. |

Direct-auth routes (`/api/v1/auth/*`, `/api/v1/applications`, `/api/v1/rbac`)
use FastAPI's usual `{"detail": "…"}` shape, not the OAuth error object.

## Firestore collections

| Collection | Key / lookup | Notes |
| --- | --- | --- |
| `applications` | document id; also queried by `client_id` | Branding, auth policy, OAuth settings. |
| `application_credentials` | queried by `app_id` | Argon2id of the client secret. |
| `users` | document id; queried by (`app_id`, `email`) | `app_id` is the `client_id`. |
| `roles` / `permissions` | queried by `app_id` | `app_id` here is the internal application document id. |
| `refresh_tokens` | queried by `token` | Deleted on rotate and on password reset. |
| `auth_sessions` | document id = `tx_…` | Pending login state. TTL enforced on read. |
| `authorization_codes` | queried by `code_hash` | Raw code is never stored. Single-use via a Firestore transaction. |
| `password_reset_tokens` | queried by `token_hash` | Single-use. |
| `email_verification_tokens` | queried by `token_hash` | Single-use. |
| `signing_keys` | document id = `kid` | Public keys for JWKS. |

Expiry is enforced when a row is used. Stale documents are not deleted
automatically. A periodic cleanup of rows with `expires_at` older than a
day keeps collections bounded; correctness does not depend on it.

Firestore TTL on `expires_at` for `auth_sessions`,
`authorization_codes`, `password_reset_tokens`, and
`email_verification_tokens` is optional cleanup. TTL is not a security
control. The service always checks `expires_at` itself.

### Indexes

Single-field equality queries are covered by Firestore's automatic
indexes. Composite indexes required in production (the emulator is
lenient) are declared in `firestore.indexes.json`:

| Collection | Fields |
| --- | --- |
| `users` | `app_id` + `email` |
| `roles` | `app_id` + `name` |
| `permissions` | `app_id` + `name` |
| `refresh_tokens` | `user_id` + `app_id` |

Deploy with `gcloud firestore indexes composite create` from that file,
or `firebase deploy --only firestore:indexes`. Do not assume the emulator
has the same indexing requirements as production.

## Project layout

```
app/
  core/           configuration, Firestore client, hashing, OAuth errors
  routers/        HTTP surface (v1 + /.well-known)
  services/       application, auth, oauth, rbac, keys, notifications
  repositories/   Firestore access
  schemas/        request and document shapes
  dependencies.py admin token, application header, current user
  main.py         app startup, middleware, error handler
tests/            pytest against the Firestore emulator
```

## Notifications

Password-reset and verification emails go through `NotificationService`.
The process that runs locally is `LoggingNotificationService`, which
prints the message and does not deliver it. A production deployment
needs a real provider behind that interface before those emails will
arrive.
