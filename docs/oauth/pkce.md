# PKCE (RFC 7636)

Proof Key for Code Exchange protects the authorization code from interception
and from authorization-code-injection attacks. The Identity Service
**requires** PKCE for the `authorization_code` grant.

## Requirements

| Aspect | Requirement |
| --- | --- |
| `code_challenge_method` | `S256` only. `plain` is rejected. |
| `code_verifier` at token exchange | Required; the token endpoint errors with `invalid_request` when absent. |
| Challenge derivation | `S256` = base64url(sha256(verifier)) with padding stripped. |
| Verification | Re-derived challenge must match the challenge stored on the transaction/code. Mismatch → `invalid_grant: PKCE verification failed`. |

## Client Flow

1. Generate a high-entropy verifier (43–128 chars of unreserved characters).
2. Compute `code_challenge = base64url(sha256(code_verifier))`.
3. Send `code_challenge` + `code_challenge_method=S256` on the authorization
   request.
4. Keep the verifier; send it as `code_verifier` on the token request.

## Server Implementation

- `pkce_verifier_to_challenge()` in `app/services/oauth.py` implements the
  S256 derivation.
- The challenge is captured on the transaction at authorization time
  (`create_transaction`), carried into the authorization code document, and
  compared at redemption (`exchange_authorization_code`).
- The challenge is never returned by any API response (see
  `test_transaction_secrets_not_exposed_in_documents`).

## Why It Matters Here

Because the Identity Service hosts the login page, the authorization code is
delivered through the browser to the client's redirect URI. PKCE guarantees
that only the party that started the flow can redeem the code, even if the
code is leaked or a malicious client injects its own code.
