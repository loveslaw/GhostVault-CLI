"""
Unit tests for GhostVault Cryptographic Engine
"""

import pytest
from core.crypto import (
    encrypt_data,
    decrypt_data,
    derive_key,
    AuthenticationError,
    CorruptedVaultError,
    SALT_SIZE,
)


def test_key_derivation_consistency():
    salt = b"A" * SALT_SIZE
    key1 = derive_key("masterpassword", salt, iterations=1000)
    key2 = derive_key("masterpassword", salt, iterations=1000)
    assert key1 == key2
    assert len(key1) == 32


def test_encryption_decryption_roundtrip():
    secret_text = b"Classified military schematics and private keys"
    password = "SuperStrongPassword!#123"

    encrypted = encrypt_data(secret_text, password)
    assert encrypted != secret_text
    assert encrypted.startswith(b"GVAULT\x01")

    decrypted = decrypt_data(encrypted, password)
    assert decrypted == secret_text


def test_wrong_password_raises_authentication_error():
    secret_text = b"Sensitive payload"
    encrypted = encrypt_data(secret_text, "correct_password")

    with pytest.raises(AuthenticationError):
        decrypt_data(encrypted, "wrong_password")


def test_tampered_ciphertext_detection():
    secret_text = b"Immutable financial logs"
    encrypted = bytearray(encrypt_data(secret_text, "correct_password"))

    # Tamper with the last byte
    encrypted[-1] ^= 0x55

    with pytest.raises(AuthenticationError):
        decrypt_data(bytes(encrypted), "correct_password")


def test_invalid_header_raises_corrupted_error():
    garbage = b"NOT_GVAULT_HEADER_DATA_1234567890"
    with pytest.raises(CorruptedVaultError):
        decrypt_data(garbage, "any_password")
