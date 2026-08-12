# Current State of Identity Service

## Repository Structure
- `app/models/`: Pydantic models for User, Application, RefreshToken, and Enums.
- `app/schemas/`: API payload representations for User, Auth, Application.
- `app/repositories/`: Database interaction layer using Firestore `AsyncClient`.
- `app/services/`: Business logic for Auth, Applications, and Key Management.
- `app/routers/`: FastAPI routes (`/api/v1/auth`, `/api/v1/applications`, `/api/v1/.well-known/jwks.json`).
- `app/core/`: Configuration, database initialization, and security primitives (Argon2id hashing).
- `docker-compose.yml` & `Dockerfile`: Defines deployment and a local Firestore emulator (which currently isn't actively mapped via `FIRESTORE_EMULATOR_HOST` in the app service definition).

## Models
- **ApplicationModel**: Stores `name`, `description`, `client_id`, `status`, and `created_at`.
- **ApplicationCredentialModel**: Stores `app_id` and `hashed_secret`.
- **UserModel**: Stores `app_id`, `email`, `hashed_password`, `username`, `first_name`, `last_name`, `roles`, and `created_at`.
- **RefreshTokenModel**: Generates a 48-char random secure string, linked to `user_id` and `app_id`.

## Authentication & Authorization
- **App Creation**: Anyone can currently hit the `/api/v1/applications/` endpoint to create a new application tenant and receive client credentials. There is no bootstrap or administrative protection.
- **User Signup/Login**: Users sign up and log in against a specific application context via the `X-Application-Id` header (which lacks strong validation). Passwords use Argon2id. 
- **Tokens**: 
  - Login yields an Access Token (15m) and a Refresh Token (7d).
  - Client credentials grant yields a Service Token via `/api/v1/auth/oauth/token`.
- **JWT Implementation**: 
  - Signs tokens using Ed25519 (EdDSA). 
  - Hardcodes generic issuer (`identity-service`) and generic audiences (`application_api`, `target-service`).
  - Does not distinguish token types explicitly via claims.

## Key Management & JWKS
- **Storage**: Private keys (Ed25519) are generated in Python and stored as plaintext PEM strings inside Firestore (`signing_keys` collection).
- **Rotation**: Basic rotation exists, but it blindly uses the most recent key without maintaining a grace period for the previous active key during the expiration window.
- **JWKS**: Published at `/.well-known/jwks.json`. Safely extracts the public `x` coordinate using Base64URL encoding.

## Weaknesses & Vulnerabilities
1. **Application Creation is Public**: No root/admin auth protects app creation.
2. **Private Key Storage**: Private signing keys in Firestore as plaintext strings are extremely dangerous.
3. **Hardcoded Audiences**: Service tokens don't enforce specific target services, violating least-privilege.
4. **Token Ambiguity**: Service vs. User tokens are not explicitly typed, risking cross-contamination.
5. **No Tests**: The `tests/` directory is entirely missing.
6. **Application Context Spoofing**: `X-Application-Id` blindly trusts the client.

## Next Steps (Phase 1)
- Introduce a secure bootstrap/admin mechanism for App creation.
- Validate application context securely during login/signup.
- Enforce strict JWT issuer and audience validation.
- Differentiate token types (User vs. Service).
- Move private key storage out of Firestore.
- Implement security headers and tests.
