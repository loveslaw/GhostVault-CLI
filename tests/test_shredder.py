"""
Unit tests for GhostVault File Shredder
"""

import os
import pytest
from core.shredder import shred_file, shred_directory


def test_shred_single_file(tmp_path):
    target_file = tmp_path / "confidential.txt"
    target_file.write_text("Extremely sensitive credentials and tokens")

    assert os.path.exists(target_file)
    shred_file(str(target_file), passes=2)

    # File must no longer exist on filesystem
    assert not os.path.exists(target_file)


def test_shred_directory_recursively(tmp_path):
    sub_dir = tmp_path / "secret_folder"
    sub_dir.mkdir()
    f1 = sub_dir / "keys.json"
    f1.write_text('{"api_key": "secret"}')
    f2 = sub_dir / "notes.txt"
    f2.write_text("confidential meeting logs")

    assert os.path.exists(sub_dir)
    assert os.path.exists(f1)
    assert os.path.exists(f2)

    shred_directory(str(sub_dir), passes=1)

    assert not os.path.exists(sub_dir)
    assert not os.path.exists(f1)
    assert not os.path.exists(f2)
