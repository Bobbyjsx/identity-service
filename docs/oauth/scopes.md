# Scopes and Claims

## Default Scopes

Every application gets `["openid", "profile", "email"]` by default and can
restrict them via its `oauth.allowed_scopes` configuration (see
[`applications/configuration.md`](../applications/configuration.md)).

| Scope | Effect |
| --- | --- |
| `openid` | Opts into the OIDC flow; adds `id_token` to the token response. |
| `profile` | Adds profile claims to the ID token. |
| `email` | Adds email claims to the ID token. |

Scope validation at the authorization endpoint:
- Any scope not in `allowed_scopes` → `invalid_scope`.
- Unrecognized scopes are not silently dropped — the whole request is
  rejected. Scope assignment is explicit and opt-in per application.

The granted scopes are persisted on the transaction and the authorization
code, and mirrored into the access token's `scope` claim.

## Access Token Claims

Shared with the existing user-token format:

```json
{
  "iss": "urn:identity-service",
  "sub": "<user id>",
  "aud": "application_api",
  "app_id": "<application doc id>",
  "type": "user",
  "scope": "openid profile email",
  "iat": 0,
  "exp": 0
}
```

## ID Token Claims

Issued only when `openid` is among the granted scopes. See
[`../oidc/overview.md`](../oidc/overview.md) for the full description.

```json
{
  "iss": "<settings.oidc_issuer>",
  "sub": "<user id>",
  "aud": "<client_id>",
  "iat": 0,
  "exp": 0,
  "jti": "<uuid4>",
  "nonce": "<nonce, only when provided in the auth request>",
  "email": "<user email — only when scope includes email>",
  "email_verified": true,
  "name": "<first + last name — only when scope includes profile>",
  "preferred_username": "<username — only when scope includes profile>"
}
```

## Privacy Notes

- ID tokens contain **no** credentials (`client_secret`, `hashed_secret`) and
  **no** internal ids other than the user `sub` (asserted by tests).
- The ID token audience is the **client**, distinct from the access token's
  `application_api` audience — a resource server must not accept ID tokens.
- `email_verified` reflects the user's verification state and is `false`
  until the user verifies via the verification email.
