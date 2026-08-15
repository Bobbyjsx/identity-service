# OpenID Connect (OIDC) Support

The Identity Service acts as an OIDC provider for the `authorization_code`
flow: it publishes a discovery document, issues signed ID tokens, and exposes
its signing keys via JWKS.

## Discovery

`GET /.well-known/openid-configuration` returns:

```json
{
  "issuer": "<settings.oidc_issuer>",
  "authorization_endpoint": "<public_base_url>/api/v1/oauth/authorize",
  "token_endpoint": "<public_base_url>/api/v1/oauth/token",
  "jwks_uri": "<public_base_url>/.well-known/jwks.json",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "client_credentials"],
  "scopes_supported": ["openid", "profile", "email"],
  "code_challenge_methods_supported": ["S256"]
}
```

Only the code response type is advertised — implicit flows are not offered.

## ID Token

An `id_token` is included in the token response **only** when `openid` is
among the granted scopes.

| Claim | Value |
| --- | --- |
| `iss` | `settings.oidc_issuer` (default `http://localhost:8002`) |
| `sub` | The internal user document id |
| `aud` | The **client_id** (never `application_api`) |
| `iat` / `exp` | Standard epoch seconds (same lifetime as the access token) |
| `jti` | Random token id |
| `nonce` | Echoed only when the authorization request carried one |
| `email`, `email_verified` | Only when `email` scope granted |
| `name`, `preferred_username` | Only when `profile` scope granted |

Security properties (asserted by tests):

- Signature verifies against `/.well-known/jwks.json` with EdDSA/Ed25519
  (`test_id_token_signature_verifies_with_jwks`).
- Audience is the client (`test_id_token_audience_is_client`), so resource
  servers must reject ID tokens.
- No credentials or internal secrets appear in the claims.
- A nonce, when supplied, is preserved and echoed.

## Verification Guidance For Clients

1. Fetch `/.well-known/openid-configuration`.
2. Fetch the JWKS from `jwks_uri`.
3. Select the key by the token's `kid` header.
4. Verify the EdDSA signature, `iss`, `aud` (your client_id), `exp`, and —
   if you sent one — `nonce`.
5. `sub` is stable per user and can be used as the user identity.

Do **not** use ID tokens as authorizations for your API; use the access token
(audience `application_api`).

## Shared Key Material

ID tokens are signed with the same Ed25519 signing keys as the existing
access/service JWTs (KeyManager), so the JWKS endpoint is shared. Key
rotation therefore rotates all signatures at once. No separate OIDC key ring
is maintained.