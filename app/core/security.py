from urllib.parse import urlparse

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

LOCALHOST_HOSTS = {"localhost", "127.0.0.1", "[::1]", "::1"}
DANGEROUS_SCHEMES = {"javascript", "data", "file", "vbscript", "blob"}
MAX_REDIRECT_URI_LENGTH = 2048


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain text password against an Argon2id hash.
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Hashes a password using Argon2id.
    """
    return pwd_context.hash(password)


def hash_token(token: str) -> str:
    """
    Hashes a high-entropy opaque token (authorization code, reset token, etc.)
    with SHA-256 so the raw token is never persisted.
    """
    import hashlib

    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def validate_redirect_uri(uri: str) -> bool:
    """
    Validates a redirect URI for registration.

    Security rules:
    - Rejects dangerous schemes (javascript:, data:, file:, vbscript:, blob:).
    - https is required for any host.
    - http is allowed only for localhost / loopback development hosts.
    - Custom schemes (mobile deep links) are permitted only when explicitly
      registered; runtime matching is always an exact string comparison.
    - Fragments are rejected (RFC 6749 discourages them in redirect URIs).
    - Wildcards are never permitted.

    Raises ValueError with a descriptive message when invalid.
    """
    if not uri or not isinstance(uri, str):
        raise ValueError("redirect URI is required")
    if len(uri) > MAX_REDIRECT_URI_LENGTH:
        raise ValueError("redirect URI is too long")
    if "*" in uri:
        raise ValueError("wildcard redirect URIs are not supported")

    parsed = urlparse(uri)
    scheme = parsed.scheme.lower()

    if scheme in DANGEROUS_SCHEMES:
        raise ValueError(f"redirect URI scheme '{scheme}' is not allowed")
    if parsed.fragment:
        raise ValueError("redirect URIs must not contain a fragment")

    if scheme in {"http", "https"}:
        if not parsed.netloc:
            raise ValueError("redirect URI must include a host")
        if scheme == "http":
            host = (parsed.hostname or "").lower()
            if host not in LOCALHOST_HOSTS:
                raise ValueError("http redirect URIs are only allowed for localhost")
    elif not parsed.netloc:
        raise ValueError("redirect URI must be an absolute URI")
    return True
