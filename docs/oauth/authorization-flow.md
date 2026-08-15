# Authorization Flow

This document walks through the end-to-end OAuth 2.0 authorization code flow
from the perspective of a consuming application and the hosted Identity UI.

## Prerequisites

1. Create an application and obtain its `client_id`/`client_secret` via
   `POST /api/v1/applications` (admin token).
2. Register at least one redirect URI through the application configuration
   endpoint (see [`applications/configuration.md`](../applications/configuration.md)).
   Redirect URIs must be HTTPS (HTTP allowed only for `localhost`), must not
   contain fragments or wildcards, and are matched **exactly**.
3. Optional: request the `openid`, `profile` and `email` scopes in the
   authorization request to receive an ID token.

## Step 1 — The Authorization Request

The consuming application redirects the browser to:

```
GET /api/v1/oauth/authorize
  ?client_id=<client_id>
  &redirect_uri=<registered callback>
  &response_type=code
  &scope=openid profile email          (optional; default openid profile email)
  &state=<client-generated opaque value>
  &nonce=<client-generated opaque value>  (optional; echoed into the ID token)
  &code_challenge=<S256 of verifier>
  &code_challenge_method=S256
```

Validation performed before anything else:

| Check | Failure → error |
| --- | --- |
| `client_id` exists and application is active | `invalid_client` |
| `redirect_uri` is registered for this client | `invalid_redirect_uri` |
| `response_type` is `code` | `unsupported_response_type` |
| `code_challenge_method` is `S256` | `invalid_request` |
| All requested scopes are allowed for the application | `invalid_scope` |

If validation fails after the redirect URI is known, the browser is
redirected back to the **registered** redirect URI with `error`,
`error_description` and `state` (state only when the request carried one).
No app configuration is ever placed in the URL.

## Step 2 — Redirect To The Hosted UI

On success the browser is redirected to:

```
302 -> {IDENTITY_UI_BASE_URL}/authorize?transaction_id=tx_<32-urlsafe-chars>
```

The Identity UI then loads safe transaction context from
`GET /api/v1/oauth/transactions/{transaction_id}`, which contains only:

- transaction id and status,
- requested scopes,
- public branding (name, description, logo URL, primary/secondary colors),
- authentication options (`allow_signup`, `allow_password_login`,
  `require_email_verification`).

The response **never** includes `code_challenge`, `client_secret`, `nonce` or
`state` (verified by tests).

## Step 3 — Authentication In The UI

The UI drives one of the transaction endpoints:

- `POST /transactions/{tx}/login` — email + password. On success returns the
  callback redirect URL (with a fresh authorization code) or
  `{"redirect_url": null, "email_verification_required": true}` when the
  application requires email verification and the user has not verified.
- `POST /transactions/{tx}/signup` — creates the user if `allow_signup` is
  enabled for the application (enforced by `AuthService`, so the generic
  `/auth/signup` endpoint is equally restricted). Proceeds like login.
- `POST /transactions/{tx}/forgot-password` then
  `POST /transactions/{tx}/reset-password` — password recovery inside the
  transaction. The forgot-password response is identical whether or not the
  email exists (enumeration-safe). Reset tokens are delivered only by email.
- `POST /transactions/{tx}/verify-email` — after the user follows the
  verification link, the UI completes verification and receives the callback
  redirect URL.
- `POST /transactions/{tx}/cancel` — aborts the transaction.

## Step 4 — Callback With The Code

When authentication completes, the browser is redirected to the registered
callback URI:

```
302 -> <redirect_uri>?code=code_<48-urlsafe-chars>[&state=<state>]
```

Only `code` and `state` appear in the callback URL. No tokens, no secrets.

## Step 5 — Token Exchange

The consuming application exchanges the code server-side:

```
POST /api/v1/oauth/token   (application/x-www-form-urlencoded)

grant_type=authorization_code
code=<code>
client_id=<client_id>
redirect_uri=<registered callback>
code_verifier=<the verifier from step 1>
[client_secret=<secret>]        (optional; see token-exchange.md)
```

All bindings are validated **before** any token is issued; the code is
atomically consumed. See [`token-exchange.md`](token-exchange.md) for the
full validation order.

## Step 6 — Tokens

The response contains:

```json
{
  "access_token": "…EdDSA JWT…",
  "refresh_token": "…48-char opaque…",
  "token_type": "bearer",
  "expires_in": 900,
  "id_token": "…EdDSA JWT…"        // only when scope includes openid
}
```

- `access_token` — audience `application_api`, `type: user`, `app_id` =
  internal application document id, `scope` claim reflects the granted scopes.
- `refresh_token` — existing 7-day rotation flow via `/api/v1/auth/refresh`.
- `id_token` — see [`../oidc/overview.md`](../oidc/overview.md).

## Error Redirects

Errors after the redirect URI is known are surfaced at the callback:

```
302 -> <redirect_uri>?error=<code>&error_description=<message>[&state=<state>]
```

See [`errors.md`](errors.md) for the catalog.
