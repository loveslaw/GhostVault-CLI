"""
Unit tests for GhostVault Packing & Plausible Deniability Vaults
"""

import os
import pytest
from core.vault import VaultManager, pack_path, unpack_payload
from core.crypto import AuthenticationError


def test_pack_and_unpack_path(tmp_path):
    sample_dir = tmp_path / "dataset"
    sample_dir.mkdir()
    sample_file = sample_dir / "data.csv"
    sample_file.write_text("id,val\n1,alpha\n2,beta")

    packed = pack_path(str(sample_dir))
    assert isinstance(packed, bytes)
    assert len(packed) > 0

    dest_dir = tmp_path / "extracted"
    extracted_path = unpack_payload(packed, str(dest_dir))

    restored_file = os.path.join(extracted_path, "data.csv")
    assert os.path.exists(restored_file)
    with open(restored_file, "r") as f:
        assert "alpha" in f.read()


def test_standard_vault_creation_and_unlock(tmp_path):
    secret_file = tmp_path / "top_secret.txt"
    secret_file.write_text("Project Obsidian Architecture Plans")

    vault_path = tmp_path / "vault.gvault"
    VaultManager.create_vault(
        target_path=str(secret_file),
        password="MyVaultPassword@999",
        output_file=str(vault_path),
        shred_source=False,
    )

    assert os.path.exists(vault_path)

    dest_dir = tmp_path / "out"
    extracted, is_decoy = VaultManager.unlock_vault(
        vault_file=str(vault_path),
        password="MyVaultPassword@999",
        destination_dir=str(dest_dir),
    )

    assert not is_decoy
    assert os.path.exists(extracted)
    with open(extracted, "r") as f:
        assert "Project Obsidian" in f.read()


def test_dual_slot_plausible_deniability_vault(tmp_path):
    # Primary payload
    real_doc = tmp_path / "real_intel.txt"
    real_doc.write_text("TRUE CLASSIFIED PAYLOAD")

    # Decoy payload
    decoy_doc = tmp_path / "decoy_intel.txt"
    decoy_doc.write_text("BORING INNOCENT SHOPPING LIST")

    vault_path = tmp_path / "dual_vault.gvault"
    VaultManager.create_vault(
        target_path=str(real_doc),
        password="RealPassword123",
        output_file=str(vault_path),
        decoy_path=str(decoy_doc),
        decoy_password="DecoyPassword456",
        shred_source=False,
    )

    # 1. Test unlocking with Decoy password
    decoy_out = tmp_path / "decoy_extracted"
    extracted_decoy, is_decoy = VaultManager.unlock_vault(
        vault_file=str(vault_path),
        password="DecoyPassword456",
        destination_dir=str(decoy_out),
    )
    assert is_decoy is True
    with open(extracted_decoy, "r") as f:
        assert "BORING INNOCENT SHOPPING LIST" in f.read()

    # 2. Test unlocking with Real password
    real_out = tmp_path / "real_extracted"
    extracted_real, is_decoy_real = VaultManager.unlock_vault(
        vault_file=str(vault_path),
        password="RealPassword123",
        destination_dir=str(real_out),
    )
    assert is_decoy_real is False
    with open(extracted_real, "r") as f:
        assert "TRUE CLASSIFIED PAYLOAD" in f.read()

    # 3. Test wrong password
    with pytest.raises(AuthenticationError):
        VaultManager.unlock_vault(
            vault_file=str(vault_path),
            password="WrongPassword789",
            destination_dir=str(tmp_path / "fail"),
        )
