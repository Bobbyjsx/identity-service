# Error Catalog

Two error surfaces exist:

1. **OAuth API errors** — JSON responses `{"error": "...", "error_description": "..."}`
   with an HTTP status code. Raised as `OAuthError` and rendered globally by
   `app/main.py` (no stack traces leak; asserted by tests).
2. **Callback redirects** — when the redirect URI is known and validation
   fails at the authorization endpoint, the browser is redirected to the
   **registered** URI with `error`, `error_description` and `state` query
   parameters.

## Error Codes

| Code | HTTP | Meaning | Surface |
| --- | --- | --- | --- |
| `invalid_client` | 401 | Unknown/inactive client, or bad client credentials | authorize, token, config |
| `invalid_client` | 404 | Unknown `client_id` at the public config endpoint | config |
| `invalid_redirect_uri` | 400 | Redirect URI not registered / dangerous / malformed | authorize |
| `unsupported_response_type` | 400 | `response_type` is not `code` | authorize |
| `invalid_request` | 400 | Missing required parameter, `plain` PKCE, missing verifier, missing audience/key fields | authorize, token |
| `invalid_scope` | 400 | Scope not allowed for this application | authorize |
| `invalid_grant` | 400 | Code missing/expired/used/mismatched, PKCE failure, transaction not completed, grant disabled, user gone | token |
| `transaction_expired` | 400 | Transaction TTL elapsed | transaction ops |
| `transaction_completed` | 400 | Operation attempted on a completed transaction | transaction ops |
| `transaction_cancelled` | 400 | Operation attempted on a cancelled transaction | transaction ops |
| `email_verification_required` | 400 | Login succeeded but application requires unverified email address; verification token emailed | login, signup |
| `invalid_transaction` | 404 | Unknown transaction id | transaction load/ops |
| `invalid_credentials` | 401 | Bad email/password in transaction login | login |
| `signup_disabled` | 400 | Application's `allow_signup` is false | signup |
| `password_login_disabled` | 400 | Application's `allow_password_login` is false | login |
| `unsupported_grant_type` | 400 | Unknown `grant_type` at the token endpoint | token |

## Response Shape

```json
{
  "error": "invalid_grant",
  "error_description": "Authorization code has already been used"
}
```

## Redirect Error Shape

```
302 -> https://app.example.com/callback
       ?error=invalid_scope
       &error_description=Scope+not+allowed+for+this+application
       [&state=<original state>]
```

`state` is echoed only when the original request carried one.

## Guarantees

- Errors never include internal details: no Firestore paths, no stack traces,
  no credentials (asserted by `test_error_responses_do_not_leak_stack_traces`).
- Forgot-password responses are identical whether or not the email exists
  (enumeration safety).