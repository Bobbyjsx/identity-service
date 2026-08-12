import uuid
import base64
from datetime import datetime, timezone
from typing import Any

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from google.cloud.firestore_v1.async_client import AsyncClient
from google.cloud.firestore_v1.base_query import FieldFilter

from app.models.enums import StatusEnum


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
        Loads the most recent active Ed25519 signing key from Firestore.
        If no active key exists, it triggers a key rotation to generate a new one.
        """
        if not self.db:
            raise RuntimeError("Database client is not initialized")
        # Fetch active keys
        docs = self.db.collection(self.collection).where(filter=FieldFilter("status", "==", StatusEnum.ACTIVE.value)).stream()
        active_keys = []
        async for doc in docs:
            data = doc.to_dict()
            if data is not None:
                data["kid"] = doc.id
                active_keys.append(data)

        if active_keys:
            # Use the most recently created key
            active_keys.sort(key=lambda k: k["created_at"], reverse=True)
            key_doc = active_keys[0]
            self.current_key_id = key_doc["kid"]
            loaded_key = serialization.load_pem_private_key(
                key_doc["private_key"].encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            if not isinstance(loaded_key, ed25519.Ed25519PrivateKey):
                raise ValueError("Loaded key is not an Ed25519 private key")
            self.private_key = loaded_key
            self.public_key = self.private_key.public_key()
        else:
            await self.rotate_key()

    async def rotate_key(self):
        """
        Generates a new Ed25519 asymmetric key pair, saves it to Firestore,
        and sets it as the active signing key.
        """
        if not self.db:
            raise RuntimeError("Database client is not initialized")
            
        new_private_key = ed25519.Ed25519PrivateKey.generate()
        private_bytes = new_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_bytes = new_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        kid = f"key_{uuid.uuid4().hex}"
        doc_data = {
            "private_key": private_bytes.decode('utf-8'),
            "public_key": public_bytes.decode('utf-8'),
            "status": StatusEnum.ACTIVE.value,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
        await self.db.collection(self.collection).document(kid).set(doc_data)
        
        self.current_key_id = kid
        self.private_key = new_private_key
        self.public_key = new_private_key.public_key()

    async def get_jwks(self) -> dict[str, list[dict[str, Any]]]:
        """
        Retrieves all active public keys and formats them as a JWKS structure.
        """
        if not self.db:
            raise RuntimeError("Database client is not initialized")
            
        docs = self.db.collection(self.collection).where(filter=FieldFilter("status", "==", StatusEnum.ACTIVE.value)).stream()
        keys = []
        async for doc in docs:
            data = doc.to_dict()
            if data is not None:
                public_key_pem = data["public_key"].encode('utf-8')
                loaded_pub = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
                if isinstance(loaded_pub, ed25519.Ed25519PublicKey):
                    raw_bytes = loaded_pub.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    )
                    x_b64url = base64.urlsafe_b64encode(raw_bytes).decode('utf-8').rstrip('=')
                    
                    keys.append({
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "kid": doc.id,
                        "x": x_b64url
                    })
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

    def verify_jwt(self, token: str) -> dict[str, Any]:
        """
        Verifies a JWT using the active public key.
        """
        if not self.public_key:
            raise RuntimeError("Public key is not loaded")
        return jwt.decode(
            token, 
            self.public_key, 
            algorithms=["EdDSA"], 
            audience=["application_api", "target-service"]
        )

key_manager = KeyManager()
