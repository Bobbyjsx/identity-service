# Identity Service

## Architecture
The Identity Service provides multi-tenant authentication and authorization using Google Cloud Firestore.
Applications must register themselves to obtain `client_id` and `client_secret`. Users are strictly partitioned by `app_id`.

## Authentication
1. **User Auth**: Users authenticate with `email` and `password` via `/api/v1/auth/login`. This returns a JWT signed with EdDSA (Ed25519). The JWT payload contains the `app_id` and user roles, meaning downstream services verify the JWT locally (via the JWKS endpoint) without round trips to this service.
2. **Service Auth**: Applications talk to each other by exchanging their `client_id` and `client_secret` via `POST /api/v1/auth/oauth/token` (OAuth Client Credentials grant) to obtain a short-lived Service JWT.

## Setup
1. Create a `firebase-credentials.json` file in the root directory.
2. Set `ENVIRONMENT=development` and run `uvicorn src.main:app --reload`.
3. Keys are dynamically generated in Firestore (`signing_keys` collection).
