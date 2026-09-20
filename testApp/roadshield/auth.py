"""Password, session, and CSRF primitives for the self-contained test application."""

import base64
import hashlib
import hmac
import secrets
import struct
import time

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def hash_password(password: str, pepper: str) -> str:
    """Salt each password and add a host-managed pepper before memory-hard hashing."""
    raw = password.encode()
    if not 12 <= len(raw) <= 256:
        raise ValueError("password must contain 12-256 UTF-8 bytes")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(raw + pepper.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_encode(salt)}${_encode(digest)}"


def verify_password(password: str, encoded: str, pepper: str) -> bool:
    """Treat malformed stored hashes as failures without exposing parser details."""
    try:
        scheme, n, r, p, salt, expected = encoded.split("$")
        raw = password.encode()
        if scheme != "scrypt" or len(raw) > 256:
            return False
        actual = hashlib.scrypt(
            raw + pepper.encode(), salt=_decode(salt), n=int(n), r=int(r), p=int(p), dklen=32
        )
        return hmac.compare_digest(actual, _decode(expected))
    except (ValueError, TypeError):
        return False


def fingerprint(value: str, secret: str) -> str:
    """Only keyed hashes of bearer and CSRF tokens are persisted."""
    return hmac.new(secret.encode(), value.encode(), hashlib.sha256).hexdigest()


def new_token() -> str:
    """A 256-bit URL-safe token is suitable for session and CSRF credentials."""
    return secrets.token_urlsafe(32)


def totp(secret: str, at: int | None = None) -> str:
    """Generate an RFC 6238 SHA-1 code for the synthetic administrator account."""
    counter = (int(time.time()) if at is None else at) // 30
    digest = hmac.new(_decode_base32(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{value:06d}"


def verify_totp(secret: str, code: str | None) -> bool:
    """Allow one period of clock skew while keeping comparisons constant-time."""
    if code is None or len(code) != 6 or not code.isascii() or not code.isdigit():
        return False
    now = int(time.time())
    return any(hmac.compare_digest(totp(secret, now + offset), code) for offset in (-30, 0, 30))


def _decode_base32(value: str) -> bytes:
    return base64.b32decode(value.upper() + "=" * (-len(value) % 8))
