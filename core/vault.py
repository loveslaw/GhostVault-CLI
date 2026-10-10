"""
GhostVault Archive & Packaging Engine
Supports single files, nested directories, and Plausible Deniability (Decoy) Vaults
"""

import io
import json
import os
import tarfile
from typing import Dict, Optional, Tuple
from core.crypto import encrypt_data, decrypt_data, AuthenticationError, CorruptedVaultError
from core.shredder import shred_file, shred_directory


def pack_path(target_path: str) -> bytes:
    """Packs a file or directory into an in-memory compressed tar.gz archive."""
    if not os.path.exists(target_path):
        raise FileNotFoundError(f"Source path does not exist: {target_path}")

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        arcname = os.path.basename(os.path.normpath(target_path))
        tar.add(target_path, arcname=arcname)
    buffer.seek(0)
    return buffer.getvalue()


def unpack_payload(archive_bytes: bytes, destination_dir: str) -> str:
    """Unpacks an in-memory tar.gz archive to the destination directory."""
    if not os.path.exists(destination_dir):
        os.makedirs(destination_dir, exist_ok=True)

    buffer = io.BytesIO(archive_bytes)
    with tarfile.open(fileobj=buffer, mode="r:gz") as tar:
        if hasattr(tarfile, "data_filter"):
            tar.extractall(path=destination_dir, filter="data")
        else:
            tar.extractall(path=destination_dir)
        members = tar.getmembers()
        root_name = members[0].name if members else ""
        return os.path.join(destination_dir, root_name)


class VaultManager:
    """Manages creation, packing, decryption, and decoy verification of vaults."""

    @staticmethod
    def create_vault(
        target_path: str,
        password: str,
        output_file: str,
        decoy_path: Optional[str] = None,
        decoy_password: Optional[str] = None,
        shred_source: bool = False,
    ) -> None:
        """
        Creates an encrypted .gvault file.
        If decoy_path and decoy_password are provided, builds a dual-slot plausible deniability vault.
        """
        if not target_path or not os.path.exists(target_path):
            raise FileNotFoundError(f"Primary target not found: {target_path}")

        primary_bytes = pack_path(target_path)
        encrypted_primary = encrypt_data(primary_bytes, password)

        if decoy_path and decoy_password:
            if not os.path.exists(decoy_path):
                raise FileNotFoundError(f"Decoy target not found: {decoy_path}")
            if decoy_password == password:
                raise ValueError("Decoy password cannot be identical to the primary vault password.")

            decoy_bytes = pack_path(decoy_path)
            encrypted_decoy = encrypt_data(decoy_bytes, decoy_password)

            container = {
                "format": "GHOSTVAULT_V1",
                "mode": "dual_slot",
                "slots": [
                    encrypted_primary.hex(),
                    encrypted_decoy.hex()
                ]
            }
        else:
            container = {
                "format": "GHOSTVAULT_V1",
                "mode": "single_slot",
                "payload": encrypted_primary.hex()
            }

        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(container, f, indent=2)

        if shred_source:
            if os.path.isdir(target_path):
                shred_directory(target_path)
            else:
                shred_file(target_path)
            if decoy_path:
                if os.path.isdir(decoy_path):
                    shred_directory(decoy_path)
                else:
                    shred_file(decoy_path)

    @staticmethod
    def unlock_vault(vault_file: str, password: str, destination_dir: str) -> Tuple[str, bool]:
        """
        Unlocks a .gvault file using the provided password.
        Returns: (extracted_path, is_decoy)
        """
        if not os.path.exists(vault_file):
            raise FileNotFoundError(f"Vault file not found: {vault_file}")

        try:
            with open(vault_file, "r", encoding="utf-8") as f:
                container = json.load(f)
        except Exception as e:
            raise CorruptedVaultError(f"Failed to read vault file structure: {str(e)}")

        if not isinstance(container, dict) or container.get("format") != "GHOSTVAULT_V1":
            raise CorruptedVaultError("Unrecognized vault format.")

        mode = container.get("mode")

        if mode == "single_slot":
            payload_hex = container.get("payload")
            if not payload_hex:
                raise CorruptedVaultError("Missing payload in vault container.")
            raw_encrypted = bytes.fromhex(payload_hex)
            decrypted = decrypt_data(raw_encrypted, password)
            extracted_path = unpack_payload(decrypted, destination_dir)
            return extracted_path, False

        elif mode == "dual_slot":
            slots = container.get("slots", [])
            if len(slots) < 2:
                raise CorruptedVaultError("Dual-slot vault requires 2 payload slots.")

            # Try slot 0 (primary)
            try:
                decrypted = decrypt_data(bytes.fromhex(slots[0]), password)
                extracted_path = unpack_payload(decrypted, destination_dir)
                return extracted_path, False
            except AuthenticationError:
                pass

            # Try slot 1 (decoy)
            try:
                decrypted = decrypt_data(bytes.fromhex(slots[1]), password)
                extracted_path = unpack_payload(decrypted, destination_dir)
                return extracted_path, True
            except AuthenticationError:
                pass

            raise AuthenticationError("Incorrect password. Neither primary nor decoy vault could be unlocked.")

        else:
            raise CorruptedVaultError(f"Unsupported vault mode: {mode}")
