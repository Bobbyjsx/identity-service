# OAuth Transactions

A transaction is a server-side, stateful record of an in-progress
authorization. It binds the browser session to an application context
(client, redirect URI, scopes, PKCE challenge, optional state/nonce) without
ever placing that context in a URL or in the browser.

## Identity

- **Format:** `tx_<32 url-safe chars>` (base64url of 32 random bytes).
- **Storage:** Firestore collection `oauth_transactions`, document id =
  transaction id.
- **TTL:** `OAUTH_TRANSACTION_EXPIRATION_MINUTES` (default 10 minutes).

## States

```
                +-------------+
                |   pending   |
                +------+------+
                       | authenticate
          +------------+------------+
          |                         |
  +-------v--------+         +------v-------+
  | authenticated  |         |  completed   |  (only after verification
  +----------------+         |              |   when email required)
          |                   +------+------+
          +----verify-email--------+   |
                 |                    |
  +--------------v--------------+     |
  |   completed (code issued)   |<----+
  +--------------+--------------+
                 |
   (expired after TTL, or cancelled by user)
```

| State | Meaning |
| --- | --- |
| `pending` | Created by `/authorize` or admin `POST /transactions`; nothing submitted yet. |
| `authenticated` | User authenticated (login/signup), but the application requires email verification and the user is unverified. A verification token has been emailed. |
| `completed` | Authentication done; authorization code issued and returned via the callback redirect. |
| `cancelled` | User aborted (`POST /transactions/{tx}/cancel`). |
| `expired` | TTL elapsed. Derived at read time by `effective_status()`, never stored. |

## Document Shape

```json
{
  "id": "tx_…",
  "application_id": "<firestore doc id>",
  "client_id": "<client_id>",
  "redirect_uri": "https://app.example.com/callback",
  "scopes": ["openid", "profile", "email"],
  "code_challenge": "<S256 challenge>",
  "code_challenge_method": "S256",
  "state": "<client state or null>",
  "nonce": "<nonce or null>",
  "status": "pending | authenticated | completed | cancelled",
  "expires_at": "<ISO-8601>",
  "created_at": "<ISO-8601>",
  "user_id": "<user id, once authenticated>",
  "completed_at": "<ISO-8601, when completed>"
}
```

Sensitive fields (`code_challenge`, `nonce`, `state`, `client_secret`) are
never included in API responses (asserted by `test_transaction_secrets_not_exposed_in_documents`).

## Lifecycle Rules

- Only `pending` and `authenticated` transactions accept login/signup
  operations. Anything else raises `transaction_expired`,
  `transaction_completed` or `transaction_cancelled`.
- A completed transaction requires its associated authorization code to be
  active; the code owns the actual single-use guarantee.
- Expiry is computed (`effective_status`) rather than written, so no
  background job is required for correctness — expired transactions are
  simply unusable. Scheduled cleanup of stale documents is a deployment
  concern (see below).

## Endpoints

| Method | Path | Access |
| --- | --- | --- |
| GET | `/api/v1/oauth/authorize` | Public (browser) — creates `pending` |
| POST | `/api/v1/oauth/transactions` | Admin token — creates `pending` directly |
| GET | `/api/v1/oauth/transactions/{tx}` | Public — safe context for the UI |
| POST | `/api/v1/oauth/transactions/{tx}/login` | Public |
| POST | `/api/v1/oauth/transactions/{tx}/signup` | Public |
| POST | `/api/v1/oauth/transactions/{tx}/forgot-password` | Public |
| POST | `/api/v1/oauth/transactions/{tx}/reset-password` | Public |
| POST | `/api/v1/oauth/transactions/{tx}/verify-email` | Public |
| POST | `/api/v1/oauth/transactions/{tx}/cancel` | Public |

## Operations Allowed Per State

| State | login | signup | forgot-password | reset-password | verify-email | cancel |
| --- | --- | --- | --- | --- | --- | --- |
| `pending` | yes | yes | yes | no | no | yes |
| `authenticated` | no (`email_verification_required`) | no | no | no | yes | yes |
| `completed` | no | no | no | no | no | yes |
| `expired` | `transaction_expired` | | | | | |
| `cancelled` | `transaction_cancelled` | | | | | |

## Firestore Notes

- **Collection:** `oauth_transactions`
- **Indexes:** lookups are by document id (the transaction id) — no composite
  indexes required for the current access patterns.
- **Cleanup:** documents are not auto-deleted. Run a scheduled job that
  deletes documents with `expires_at < now - 24h` (or lower TTL buckets) to
  bound collection growth. Correctness does not depend on cleanup.
