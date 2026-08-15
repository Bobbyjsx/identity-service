# How it works

This service is a multi-tenant identity provider. You do not bolt login onto
each product. You register the product here, users live here, and every
downstream API trusts the tokens this service signs.

## The three parties

OAuth conversations get muddy when "identity provider" and "identity service"
are used as if they were different systems. In this repo they are not.

| Party | What it is | What it does |
| --- | --- | --- |
| **Your application** | The product people actually use. In OAuth this is the *client*. | Starts login, receives the callback, exchanges the code, calls your APIs with the access token. |
| **Identity Service** | This backend. It *is* the identity provider. | Stores applications and users, runs OAuth, signs tokens, publishes public keys. |
| **Identity UI** | The hosted login pages (`IDENTITY_UI_BASE_URL`). | Collects email and password in the browser. Talks only to this service. Never sees client secrets or tokens. |

Your application never talks to a third-party IdP. Google, Auth0, and similar
products are not in this picture. Users authenticate against *this* service.

```
  ┌──────────────────┐         ┌─────────────────────┐         ┌──────────────────┐
  │  Your application │         │  Identity Service    │         │   Identity UI    │
  │  (OAuth client)   │◄───────►│  (this repo / IdP)   │◄───────►│  (hosted login)  │
  └──────────────────┘         └─────────────────────┘         └──────────────────┘
            ▲                              │
            │                              │ signs JWTs
            │                              ▼
            │                   ┌─────────────────────┐
            └───────────────────│  Your APIs          │
              Bearer access     │  verify locally     │
              token             │  via JWKS           │
                                └─────────────────────┘
```

## Everything hangs off an application

An *application* is a tenant. It is also the OAuth client.

Until you create one, there is nowhere for a user to exist. Email addresses
are unique *per application*, not globally. Roles, permissions, refresh
tokens, and OAuth transactions are all scoped the same way.

Creating an application is the start of auth. The walkthrough is in
[Create an application](create-an-app.md).

Two identifiers come back:

- **`client_id`** — public. You put it in `X-Application-Id` and in OAuth
  `client_id`. User records store this value as `app_id`.
- **`client_secret`** — private, shown once. Used for confidential clients
  and for machine-to-machine tokens. Only a hash is stored.

There is also an internal Firestore document id on the application. Service
tokens put that internal id in their `app_id` claim. When you are integrating,
use `client_id`. Treat the document id as an implementation detail.

## How data is stored

Firestore is the only datastore. Each concern has its own collection.

| Collection | Holds |
| --- | --- |
| `applications` | Name, status, branding, auth policy, OAuth settings, `client_id` |
| `application_credentials` | Argon2id hash of the client secret |
| `users` | Email, password hash, profile, roles, `email_verified`, scoped by `app_id` (`client_id`) |
| `roles` / `permissions` | RBAC definitions scoped to an application |
| `refresh_tokens` | Opaque rotating refresh tokens |
| `oauth_transactions` | In-progress browser logins (PKCE challenge, redirect, scopes, state) |
| `authorization_codes` | SHA-256 of the one-time code, plus the bindings needed to redeem it |
| `password_reset_tokens` / `email_verification_tokens` | SHA-256 of one-time email tokens |
| `signing_keys` | Public half of the Ed25519 signing key, used to build JWKS |

Raw secrets are not written. Passwords and client secrets are Argon2id.
Authorization codes, reset tokens, and verification tokens are stored only as
SHA-256. The refresh token value is the exception: it is an opaque random
string stored so it can be looked up and rotated.

## How a request moves through the code

Every HTTP request follows the same path.

```
router  →  service  →  repository  →  Firestore
```

- **Routers** (`app/routers`) parse the request and return the response.
  They do not decide policy.
- **Services** (`app/services`) own the rules: is this client allowed this
  redirect? can this user sign up? is this code still unused?
- **Repositories** (`app/repositories`) read and write Firestore.
- **Schemas** (`app/schemas`) are the shapes going in and out.
- **Core** (`app/core`) is configuration, password hashing, redirect-URI
  rules, and the OAuth error type.

`app/dependencies.py` wires those layers together and enforces the two
gatekeepers:

- `X-Admin-Token` must match `ADMIN_SECRET` to create or configure
  applications.
- `X-Application-Id` must be a real `client_id` for signup, login, and RBAC.

Signing is centralized in `KeyManager`. Routers never touch keys.

## Two ways to authenticate a user

After an application exists, there are two paths to tokens. They share the
same users, the same password hashes, and the same access-token format.

**Direct auth** — your application collects email and password and calls
`POST /api/v1/auth/login` with `X-Application-Id`. You own the login form.
This is the shortest path and is enough for a first-party product.

**OAuth authorization code** — your application redirects the browser to
this service. The user signs in on the Identity UI. Your application
receives a short-lived `code` and exchanges it, server-side, for tokens.
This is the path you want for a hosted login page, OpenID Connect, or any
client that should not handle passwords. The full sequence is in
[OAuth lifecycle](oauth-lifecycle.md).

There is a third path that does not involve a user at all:
**client credentials**. Your application presents `client_id` and
`client_secret` and receives a short-lived *service* token for
machine-to-machine calls.

## What gets written during a typical OAuth login

This is the data flow, not the HTTP flow.

1. **Authorize.** A row is inserted into `oauth_transactions` (`pending`).
   It binds the client, redirect URI, scopes, PKCE challenge, and optional
   `state` / `nonce`. Nothing sensitive is put in the browser URL except
   the transaction id.
2. **Login or signup.** The user row is read or created in `users`. If the
   application requires a verified email and the user is unverified, the
   transaction moves to `authenticated` and a hashed verification token is
   stored. Otherwise an authorization code is issued immediately.
3. **Code issued.** A row is inserted into `authorization_codes` with the
   SHA-256 of the raw code. The transaction moves to `completed`. The raw
   code is returned only in the callback URL.
4. **Token exchange.** The code is looked up by hash, every binding is
   checked, and the row is marked `used` inside a Firestore transaction.
   An access JWT is signed. A refresh-token row is inserted. If `openid`
   was granted, an ID token is signed too.

A failed login writes nothing durable except the existing transaction.
Forgot-password writes a hashed reset token only when the email exists,
but the HTTP response is the same either way.

## What other services do with the result

Downstream APIs do not call this service on every request. They fetch
`/.well-known/jwks.json`, cache the public keys, and verify
`Authorization: Bearer <access_token>` locally.

That verification path, and the difference between access, refresh, ID,
and service tokens, is in [Tokens](tokens.md).
