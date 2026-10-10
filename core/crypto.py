"""
GhostVault Cryptographic Engine
AES-256-GCM Authenticated Encryption with PBKDF2-HMAC-SHA256 Key Derivation
"""

import os
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

MAGIC_HEADER = b"GVAULT\x01"
SALT_SIZE = 16
NONCE_SIZE = 12
DEFAULT_ITERATIONS = 300_000


class CryptoError(Exception):
    """Base exception for cryptographic failures."""
    pass


class AuthenticationError(CryptoError):
    """Raised when password is incorrect or ciphertext has been altered."""
    pass


class CorruptedVaultError(CryptoError):
    """Raised when vault format or magic bytes are invalid."""
    pass


def derive_key(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    """Derives a 256-bit cryptographic key from a password using PBKDF2-HMAC-SHA256."""
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string.")
    if len(salt) != SALT_SIZE:
        raise ValueError(f"Salt must be exactly {SALT_SIZE} bytes.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_data(data: bytes, password: str, associated_data: Optional[bytes] = None) -> bytes:
    """
    Encrypts arbitrary data using AES-256-GCM.
    Returns: MAGIC_HEADER + SALT + NONCE + CIPHERTEXT (includes 16-byte auth tag)
    """
    if not isinstance(data, bytes):
        raise TypeError("Data to encrypt must be bytes.")

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, associated_data)

    return MAGIC_HEADER + salt + nonce + ciphertext


def decrypt_data(payload: bytes, password: str, associated_data: Optional[bytes] = None) -> bytes:
    """
    Decrypts an AES-256-GCM payload.
    Verifies magic header, extracts salt and nonce, derives key, and authenticates tag.
    """
    if not isinstance(payload, bytes):
        raise TypeError("Payload must be bytes.")

    header_len = len(MAGIC_HEADER)
    min_len = header_len + SALT_SIZE + NONCE_SIZE + 16  # 16 is auth tag minimum
    if len(payload) < min_len:
        raise CorruptedVaultError("Payload is too short to be a valid GhostVault.")

    if not payload.startswith(MAGIC_HEADER):
        raise CorruptedVaultError("Invalid magic header. File is not a valid GhostVault.")

    idx = header_len
    salt = payload[idx : idx + SALT_SIZE]
    idx += SALT_SIZE

    nonce = payload[idx : idx + NONCE_SIZE]
    idx += NONCE_SIZE

    ciphertext = payload[idx:]

    try:
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
    except InvalidTag:
        raise AuthenticationError("Authentication failed: Incorrect password or corrupted data.")
