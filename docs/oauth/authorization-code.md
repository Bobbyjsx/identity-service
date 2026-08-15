# Authorization Codes

Authorization codes are the single-use credentials exchanged for tokens at
the token endpoint.

## Identity

- **Format:** `code_<48 url-safe chars>` (base64url of 48 random bytes).
- **Storage:** Firestore collection `authorization_codes`.
- **TTL:** `OAUTH_AUTHORIZATION_CODE_EXPIRATION_MINUTES` (default 5 minutes).

## Issuance

Issued by `OAuthService.issue_authorization_code()` when authentication (and,
if required, email verification) succeeds, inside the transaction flow.
Issuance **does not** require the client to be online — the code is delivered
to the browser via the callback redirect.

Each code is bound to:

- the transaction (`transaction_id`),
- the application (`application_id`) and client (`client_id`),
- the authenticated user (`user_id`),
- the redirect URI from the authorization request (`redirect_uri`),
- the granted scopes (`scopes`),
- the PKCE challenge (`code_challenge`, `code_challenge_method`),
- an optional `nonce` echoed into the ID token.

## Storage Security

Only the SHA-256 hash of the raw code is persisted (`code_hash`). The raw
code exists only in the callback URL and in the memory of whoever redeems it.
`test_raw_authorization_code_never_persisted` asserts the raw value never
appears in the document.

## Single-Use Enforcement

Redemption (`POST /api/v1/oauth/token`) atomically flips the code from
`active` to `used` inside a Firestore transaction
(`AuthorizationCodeRepository.mark_used_atomic`):

1. Read the code document inside the transaction (via a stream query keyed on
   `code_hash`, because the installed Firestore library's async
   `transaction.get(ref)` is broken — see note below).
2. If the current status is not `active`, abort (already used).
3. Update the status to `used` with `used_at` timestamp and commit.

Concurrent redemption attempts therefore result in exactly one success; the
loser receives `invalid_grant: Authorization code has already been used`.
Verified by `test_concurrent_redemption_second_fails`.

## Document Shape

```json
{
  "code_hash": "<sha256 hex of raw code>",
  "transaction_id": "tx_…",
  "application_id": "<firestore doc id>",
  "client_id": "<client_id>",
  "user_id": "<user id>",
  "redirect_uri": "https://app.example.com/callback",
  "scopes": ["openid", "profile", "email"],
  "code_challenge": "<S256 challenge>",
  "code_challenge_method": "S256",
  "nonce": "<nonce or null>",
  "status": "active | used",
  "expires_at": "<ISO-8601>",
  "created_at": "<ISO-8601>",
  "used_at": "<ISO-8601, when redeemed>"
}
```

## Expiry

Codes are unusable after `OAUTH_AUTHORIZATION_CODE_EXPIRATION_MINUTES`
(`invalid_grant: Authorization code has expired`). Expired codes are not
deleted automatically — scheduled cleanup of documents with
`expires_at < now - 24h` keeps the collection bounded; correctness does not
depend on cleanup.

## Firestore Notes

- **Index:** `authorization_codes` is queried by `code_hash`; a single-field
  equality query is sufficient.
- **Implementation note:** the installed `google-cloud-firestore` 2.28.1
  async client cannot `await transaction.get(ref)` ("object async_generator
  can't be used in 'await' expression"). The workaround reads the document
  with `query.stream(transaction=tx)` using a `FieldFilter("code_hash", "==", code_hash)`
  and validates the match before the conditional update. Keep this pattern
  if the library version changes.
