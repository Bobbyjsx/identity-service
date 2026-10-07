import base64
from datetime import datetime, timezone
from typing import Any

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from google.cloud.firestore_v1.async_client import AsyncClient
from google.cloud.firestore_v1.base_query import FieldFilter

from app.core.config import settings
from app.schemas.enums import StatusEnum


class KeyManager:
    def __init__(self):
        """
        Initializes the KeyManager instance with default none values.
        """
        self.db: AsyncClient | None = None
        self.current_key_id: str | None = None
        self.private_key: ed25519.Ed25519PrivateKey | None = None
        self.public_key: ed25519.Ed25519PublicKey | None = None
        self.collection = "signing_keys"

    async def initialize(self, db: AsyncClient):
        """
        Bootstraps the KeyManager with a Firestore client and loads the active signing key.
        """
        self.db = db
        await self._load_or_generate_key()

    async def _load_or_generate_key(self):
        """
        Loads the Ed25519 signing key from the secure path.
        If in development and it doesn't exist, generates it.
        Publishes the public key to Firestore for JWKS.
        """
        if not self.db:
            raise RuntimeError("Database client is not initialized")

        key_pem = settings.private_key

        if key_pem:
            # We replace \n with actual newlines if it was escaped in .env
            key_pem = key_pem.replace("\\n", "\n")
            pem_data = key_pem.encode("utf-8")
            loaded_key = serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())
            if not isinstance(loaded_key, ed25519.Ed25519PrivateKey):
                raise ValueError("Loaded key is not an Ed25519 private key")
            self.private_key = loaded_key
            self.public_key = self.private_key.public_key()
        else:
            if settings.environment == "production":
                raise RuntimeError("Private key not found in settings.private_key in production")

            self.private_key = ed25519.Ed25519PrivateKey.generate()
            self.public_key = self.private_key.public_key()

            private_bytes = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            print("WARNING: No PRIVATE_KEY found in environment. Generated an ephemeral key for this session.")
            print(
                f'To persist, add the following to your .env file:\n\nPRIVATE_KEY="{private_bytes.decode("utf-8").replace(chr(10), "\\n")}"\n'
            )

        # Derive kid from public key
        pub_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        self.current_key_id = f"key_{base64.urlsafe_b64encode(pub_bytes[:16]).decode('utf-8').rstrip('=')}"

        # Ensure public key is in Firestore for JWKS
        doc_ref = self.db.collection(self.collection).document(self.current_key_id)
        doc = await doc_ref.get()
        if not doc.exists:
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            await doc_ref.set(
                {
                    "public_key": public_pem.decode("utf-8"),
                    "status": StatusEnum.ACTIVE.value,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
            )

    async def rotate_key(self):
        """
        Key rotation is managed via updating the underlying secure file.
        Full lifecycle rotation implemented in Phase 5.
        """
        raise NotImplementedError("Handled out-of-band by infrastructure for now.")

    async def get_jwks(self) -> dict[str, list[dict[str, Any]]]:
        """
        Retrieves all active public keys and formats them as a JWKS structure.
        """
        if not self.db:
            raise RuntimeError("Database client is not initialized")

        docs = (
            self.db.collection(self.collection)
            .where(filter=FieldFilter("status", "==", StatusEnum.ACTIVE.value))
            .stream()
        )
        keys = []
        async for doc in docs:
            data = doc.to_dict()
            if data is not None:
                public_key_pem = data["public_key"].encode("utf-8")
                loaded_pub = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
                if isinstance(loaded_pub, ed25519.Ed25519PublicKey):
                    raw_bytes = loaded_pub.public_bytes(
                        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
                    )
                    x_b64url = base64.urlsafe_b64encode(raw_bytes).decode("utf-8").rstrip("=")

                    keys.append({"kty": "OKP", "crv": "Ed25519", "kid": doc.id, "x": x_b64url})
        return {"keys": keys}

    def sign_jwt(self, payload: dict[str, Any]) -> str:
        """
        Signs a JWT payload using the currently active Ed25519 private key.
        Injects the key ID into the headers.
        """
        if not self.private_key:
            raise RuntimeError("Private key is not loaded")
        headers = {"kid": self.current_key_id}
        return jwt.encode(payload, self.private_key, algorithm="EdDSA", headers=headers)

    def verify_jwt(self, token: str, audience: list[str] | None = None) -> dict[str, Any]:
        """
        Verifies a JWT using the active public key.
        """
        if not self.public_key:
            raise RuntimeError("Public key is not loaded")

        aud = audience if audience is not None else ["application_api", "target-service"]

        return jwt.decode(token, self.public_key, algorithms=["EdDSA"], audience=aud, issuer=settings.identity_issuer)


key_manager = KeyManager()
