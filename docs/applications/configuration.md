# Application Configuration

Applications store OAuth, authentication and branding configuration. This
document describes the configurable values, the endpoints that read/write
them, and the defaults.

## Where It Lives

Configuration is stored on the application document (Firestore collection
`applications`) under three structured fields:

```json
{
  "name": "My App",
  "description": "…",
  "client_id": "…",
  "status": "active",
  "branding": {
    "logo_url": "https://…/logo.png",
    "primary_color": "#4F46E5",
    "secondary_color": "#111827"
  },
  "authentication": {
    "allow_signup": true,
    "allow_password_login": true,
    "require_email_verification": false
  },
  "oauth": {
    "redirect_uris": ["https://app.example.com/callback"],
    "allowed_scopes": ["openid", "profile", "email"],
    "allowed_grants": ["authorization_code", "client_credentials"]
  }
}
```

## Defaults

When fields are absent, these defaults apply (so pre-existing applications
work unchanged):

| Field | Default |
| --- | --- |
| `branding.*` | empty / null (UI falls back to its own styles) |
| `authentication.allow_signup` | `true` |
| `authentication.allow_password_login` | `true` |
| `authentication.require_email_verification` | `false` |
| `oauth.redirect_uris` | `[]` (no callback allowed until one is registered) |
| `oauth.allowed_scopes` | `["openid", "profile", "email"]` |
| `oauth.allowed_grants` | `["authorization_code", "client_credentials"]` |

## Redirect URI Rules

Every registered redirect URI is validated at write time (and again at
authorization time) by `validate_redirect_uri` in `app/core/security.py`:

- Must be an absolute https URL; http is allowed **only** for localhost hosts
  (`localhost`, `127.0.0.1`, `::1`).
- Dangerous schemes are rejected: `javascript:`, `data:`, `file:`, `vbscript:`,
  `blob:`.
- Fragments are rejected.
- Wildcards / prefix matching are rejected; runtime matching is exact string
  equality against the registered list.

## Admin Endpoints

Admin-token protected (`X-Admin-Token`):

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/v1/applications/{client_id}/configuration` | Read full configuration |
| PATCH | `/api/v1/applications/{client_id}/configuration` | Partial update (deep merge per field) |

PATCH accepts any subset; e.g. to register a callback and disable signup:

```json
{
  "oauth": {"redirect_uris": ["https://app.example.com/callback"]},
  "authentication": {"allow_signup": false}
}
```

## Public Endpoint

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/v1/oauth/applications/{client_id}/configuration` | Safe config for the hosted Identity UI |

Returns only branding + authentication options + allowed scopes. **Never**
returns `client_secret`, `hashed_secret` or `redirect_uris` (asserted by
`test_transaction_secrets_not_exposed_in_documents`).

## Enforcement Points

- **Authorization endpoint** — validates client, redirect URI, response
  type, scopes and grants from this configuration.
- **Token endpoint** — re-checks grant allow-list and application status at
  redemption.
- **Transaction auth** — `allow_signup` is enforced by `AuthService.create_user`,
  so the generic `/api/v1/auth/signup` path respects it too;
  `allow_password_login` gates transaction login.

## Migration Notes

- Existing application documents need **no migration** — getters apply
  defaults.
- Application creation (`POST /api/v1/applications`) accepts an optional
  `config` body; without it the defaults above apply.