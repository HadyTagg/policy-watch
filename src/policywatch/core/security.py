"""Password hashing helpers for Policy Watch."""

from __future__ import annotations

import hashlib
import os


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    """Return a salted PBKDF2 hash and salt for storage."""

    if salt is None:
        salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120000)
    return pwd_hash.hex(), salt.hex()


def verify_password(password: str, stored_hash: str, salt_hex: str) -> bool:
    """Validate a password against a stored hash and salt."""

    salt = bytes.fromhex(salt_hex)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120000)
    return pwd_hash.hex() == stored_hash
