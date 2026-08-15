# Token Exchange

`POST /api/v1/oauth/token` (form-encoded) implements the OAuth 2.0 token
endpoint. It supports two grants:

- `authorization_code` — interactive user tokens, **PKCE required**.
- `client_credentials` — service tokens (pre-existing behavior, unchanged).

## authorization_code

Required form fields: `grant_type`, `code`, `client_id`, `redirect_uri`,
`code_verifier`. `client_secret` is optional.

Validation order (all checks run **before** any token is issued):

| # | Check | Failure → error |
| --- | --- | --- |
| 1 | Code exists (by SHA-256 hash lookup) | `invalid_grant: Invalid authorization code` |
| 2 | Code not expired | `invalid_grant: Authorization code has expired` |
| 3 | Code status is `active` | `invalid_grant: Authorization code has already been used` |
| 4 | Code was issued to this `client_id` | `invalid_grant: …different client` |
| 5 | `redirect_uri` matches the authorization request | `invalid_grant: Redirect URI does not match…` |
| 6 | Application exists and is active | `invalid_grant: Application is not active` |
| 7 | Code's client matches the application | `invalid_grant: …does not match the application` |
| 8 | `authorization_code` grant enabled for the app | `invalid_grant: …not enabled` |
| 9 | `client_secret` (if provided) validates | `invalid_client` (401) |
| 10 | PKCE verifier re-derives the stored challenge | `invalid_grant: PKCE verification failed` |
| 11 | Transaction exists and is `completed` | `invalid_grant: …` |
| 12 | User still exists | `invalid_grant: User no longer exists` |
| 13 | **Atomic** mark-used (transaction) | `invalid_grant: …already been used` |

Only after step 13 succeeds are tokens issued:

```json
{
  "access_token": "<EdDSA JWT, type=user, aud=application_api, scope=…>",
  "refresh_token": "<48-char opaque, 7-day rotation>",
  "token_type": "bearer",
  "expires_in": 900,
  "id_token": "<EdDSA JWT — only when scope includes openid>"
}
```

The `scope` claim on the access token mirrors the scopes granted at
authorization time.

## client_credentials

Required form fields: `grant_type`, `client_id`, `client_secret`, `audience`.
This is the pre-existing service-token path (`AuthService.generate_service_token`),
now surfacing failures as OAuth errors:

- missing secret → `invalid_request`
- missing audience → `invalid_request: audience is required for client_credentials`
- bad credentials → `invalid_client` (401)

The returned token has `type: service` and `aud` = the requested audience.
Note: its `app_id` claim is the internal Firestore document id of the
application, not the `client_id` (asserted by tests).

The legacy endpoint `POST /api/v1/auth/oauth/token` remains available and
unchanged.

## Response Model

The `Token` schema (`app/schemas/auth.py`) gained an optional `id_token`
field; existing consumers are unaffected.
