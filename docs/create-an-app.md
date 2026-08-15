# Create an application

Auth in this service starts by registering an application. That record is
the tenant *and* the OAuth client. Users, roles, and tokens only exist in
relation to it.

This page is the operator path: create the app, configure it, then
authenticate. The browser redirect sequence that follows is in
[OAuth lifecycle](oauth-lifecycle.md).

Assume the service is running at `http://localhost:8002` and
`ADMIN_SECRET` is set. Admin calls use the `X-Admin-Token` header.

## 1. Register the application

```bash
curl -s http://localhost:8002/api/v1/applications \
  -H "X-Admin-Token: $ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Storefront",
    "description": "Customer accounts",
    "client_type": "confidential",
    "oauth": {
      "redirect_uris": ["https://app.example.com/callback"]
    }
  }'
```

`name` is the only required field. `client_type`, branding, authentication,
and OAuth settings can be sent on create so provisioning is one request,
or patched later. Existing callers that send only `name` still work.

```json
{
  "client_id": "app_0f3c…",
  "client_secret": "wK8p…"
}
```

`client_secret` is shown once. Store it with your other secrets. The
service keeps only an Argon2id hash.

Creating an application does not take OAuth settings. Those come next.

## 2. Configure how people sign in

```bash
curl -s -X PATCH \
  "http://localhost:8002/api/v1/applications/$CLIENT_ID/configuration" \
  -H "X-Admin-Token: $ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
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
  }'
```

PATCH is a deep merge per namespace. Send only the fields you want to
change.

| Namespace | What it controls |
| --- | --- |
| `branding` | Logo and colors the Identity UI renders |
| `authentication` | Whether people can sign up, use a password, or must verify email first |
| `oauth` | Exact redirect URIs, scopes this client may request, grants it may use |

Defaults if you never PATCH:

- `client_type` is `public`
- signup and password login allowed, email verification off
- allowed scopes `openid profile email`
- allowed grants `authorization_code` only — machine-to-machine is opt-in
- **no redirect URIs** — OAuth cannot start until you register at least one

Redirect URIs are matched as exact strings. `https` is required, except
`http` on localhost / loopback. Fragments, wildcards, and schemes that can
run code (`javascript:`, `data:`, …) are rejected.

The Identity UI can read a public subset of this configuration at
`GET /api/v1/oauth/applications/{client_id}/configuration`. That response
never includes the secret or the redirect URI list.

## 3. Sign a user in

Once the application exists you can authenticate against it. Pick the
path that matches how your product is built.

### Direct auth — you own the login form

Use this when your application collects email and password itself.

```bash
curl -s http://localhost:8002/api/v1/auth/signup \
  -H "X-Application-Id: $CLIENT_ID" \
  -H "Content-Type: application/json" \
  -d '{"email":"ada@example.com","password":"a-long-password","first_name":"Ada"}'
```

```bash
curl -s http://localhost:8002/api/v1/auth/login \
  -H "X-Application-Id: $CLIENT_ID" \
  -H "Content-Type: application/json" \
  -d '{"email":"ada@example.com","password":"a-long-password"}'
```

`X-Application-Id` is the `client_id`. The same email can exist on two
applications; they are different users.

Login returns an access token and a refresh token. There is no ID token
on this path — ID tokens are an OpenID Connect concern and only appear
from the OAuth token endpoint.

`allow_signup` is enforced here too. If you disable signup on the
application, both `/auth/signup` and the OAuth signup endpoint reject
the request.

### OAuth — this service owns the login form

Use this when the browser should leave your application, sign in on the
Identity UI, and come back with a `code`.

You need a registered redirect URI (step 2) and a PKCE pair. Then:

1. Redirect the browser to `GET /api/v1/oauth/authorize` with `client_id`,
   `redirect_uri`, `response_type=code`, `scope`, `state`, and the PKCE
   challenge.
2. The user signs in on the Identity UI.
3. The browser returns to your redirect URI with `code` and `state`.
4. Your backend exchanges the code at `POST /api/v1/oauth/token`.

That sequence, including what each party holds at each step, is
[OAuth lifecycle](oauth-lifecycle.md).

## 4. Machine-to-machine (no user)

Services that act as the application, not as a person, use client
credentials. This grant is **off by default**. Enable it on the
application first:

```json
{ "oauth": { "allowed_grants": ["authorization_code", "client_credentials"] } }
```


```bash
curl -s http://localhost:8002/api/v1/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "audience=orders-api"
```

The result is a short-lived JWT with `type: service` and `aud` set to the
audience you asked for. There is no refresh token. When it expires, request
another.

`POST /api/v1/auth/oauth/token` is the older URL for the same grant. New
integrations should use `/api/v1/oauth/token`.

## 5. Roles and permissions (optional)

RBAC is per application. Create permissions, then roles that name those
permissions. Both endpoints require `X-Application-Id`.

```bash
curl -s http://localhost:8002/api/v1/rbac/permissions \
  -H "X-Application-Id: $CLIENT_ID" \
  -H "Content-Type: application/json" \
  -d '{"name":"orders:write","description":"Create and update orders"}'

curl -s http://localhost:8002/api/v1/rbac/roles \
  -H "X-Application-Id: $CLIENT_ID" \
  -H "Content-Type: application/json" \
  -d '{"name":"merchant","permissions":["orders:write"]}'
```

Role names on a user are copied into the access token's `roles` claim at
issue time. Downstream APIs enforce them; this service does not interpret
them on every request.

## After this

- Users of this application can refresh with `POST /api/v1/auth/refresh`.
- `GET /api/v1/auth/me` returns the user behind a valid access token.
- Other services verify tokens using the keys at `/.well-known/jwks.json`.
  See [Tokens](tokens.md).
