# Tokens

This service issues four kinds of credential. They are not interchangeable.
Use the access token to call APIs, the refresh token to get a new access
token, the ID token to know who signed in, and the service token for
machine-to-machine calls.

All JWTs are Ed25519 (`EdDSA`), signed with the same key ring. Public
keys are at `GET /.well-known/jwks.json`. Every JWT — user access,
service, and ID token — uses one issuer: `IDENTITY_ISSUER` (default
`http://localhost:8002`). That value is also `issuer` in
`/.well-known/openid-configuration`.

## Which credential to use

| Credential | Shape | Lifetime | Audience | Use it for |
| --- | --- | --- | --- | --- |
| Authorization code | Opaque `code_…` | 5 minutes, single-use | — | Server-side exchange at `/oauth/token` only. Never an API credential. |
| Access token | JWT, `type: user` | 15 minutes | `application_api` | `Authorization: Bearer` on your APIs |
| Refresh token | Opaque 48-byte string | 7 days, rotated | — | `POST /api/v1/auth/refresh` |
| ID token | JWT | 15 minutes | your `client_id` | Identify the user in your application. Not an API access token. |
| Service token | JWT, `type: service` | 15 minutes | the audience you requested | App-to-app calls, no user |

Access-token lifetime is `JWT_EXPIRATION_MINUTES` (default 15).

## Access token

Issued by direct login, OAuth token exchange, and refresh.

```json
{
  "iss": "http://localhost:8002",
  "sub": "<user id>",
  "aud": "application_api",
  "app_id": "<client_id>",
  "type": "user",
  "roles": [],
  "scope": "openid profile email",
  "iat": 0,
  "exp": 0,
  "jti": "<random>"
}
```

`scope` is present on tokens from the OAuth path. Direct login does not
set it. `roles` are the role names stored on the user at issue time.

`iss` is `IDENTITY_ISSUER`. The ID token uses the same issuer. They are
distinguished by `aud` and by purpose, not by who signed them.

## Refresh token

An opaque random string stored in `refresh_tokens`. It is not a JWT.

`POST /api/v1/auth/refresh` with `{ "refresh_token": "…" }` validates it,
deletes it, and returns a new access + refresh pair. Reusing the old
value fails. Changing a password also deletes that user's refresh tokens.

## ID token

Issued only by `POST /api/v1/oauth/token` when the granted scopes include
`openid`. Direct login never returns one.

```json
{
  "iss": "http://localhost:8002",
  "sub": "<user id>",
  "aud": "<client_id>",
  "iat": 0,
  "exp": 0,
  "jti": "<random>",
  "nonce": "<echoed if you sent one>",
  "email": "ada@example.com",
  "email_verified": false,
  "name": "Ada Lovelace",
  "preferred_username": "ada"
}
```

`iss` is `IDENTITY_ISSUER`. `aud` is your `client_id`, not
`application_api`. That is deliberate: a resource server that accepts
`application_api` must reject this token. An ID token is identity for
the client, not authorization for an API.

Claims are gated by scope:

| Scope | Adds to the ID token |
| --- | --- |
| `openid` | The token itself, plus `iss` / `sub` / `aud` / `iat` / `exp` / `jti` |
| `email` | `email`, `email_verified` |
| `profile` | `name` (first + last), `preferred_username` |

`nonce` is copied from the original authorize request when you sent one.
Verify it.

Do not send an ID token as `Authorization` to your API.

## Service token

Issued by `grant_type=client_credentials` at `/api/v1/oauth/token`.

```json
{
  "iss": "http://localhost:8002",
  "sub": "service:<application document id>",
  "aud": "<the audience you requested>",
  "app_id": "<application document id>",
  "type": "service",
  "iat": 0,
  "exp": 0,
  "jti": "<random>"
}
```

`app_id` here is the internal Firestore id, not `client_id`. Downstream
services that need to tell user tokens from service tokens should look at
`type`, not at the shape of `app_id`.

There is no refresh token. Request a new one when it expires.

## How another service verifies an access token

Other services do not call Identity Service per request.

1. Fetch `GET /.well-known/jwks.json` and cache it. The keys are Ed25519
   (`kty: OKP`, `crv: Ed25519`).
2. Read the JWT header `kid` and pick that key.
3. Verify the EdDSA signature, `iss` (`IDENTITY_ISSUER`),
   `aud` (`application_api` for user tokens), and `exp`.
4. Trust `sub` as the user id and `app_id` as the application the user
   belongs to.

OpenID Connect clients that want to verify an ID token should start from
`GET /.well-known/openid-configuration` instead. That document points at
the same JWKS, but the expected `iss` and `aud` are different (see above).

Discovery advertises only `response_types_supported: ["code"]`. This
service does not offer implicit or hybrid flows.

## Signing keys

On startup, `KeyManager` loads `PRIVATE_KEY` (a PEM-encoded Ed25519
private key). If that variable is missing in development, an ephemeral
key is generated and printed so you can paste it into `.env`. Production
refuses to start without `PRIVATE_KEY`.

The public half is written to `signing_keys` and published through JWKS.
Rotate the key by changing `PRIVATE_KEY` and restarting; there is no
in-process rotation endpoint yet. Plan a JWKS cache TTL on consumers
that is short enough to pick up a new `kid` after you rotate.
