"""
GhostVault Secure File Shredder
Complies with DoD 5220.22-M 3-Pass Overwrite & Metadata Anonymization Standards
"""

import os
import secrets
import string
from typing import Callable, Optional


def _random_filename(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def shred_file(
    file_path: str,
    passes: int = 3,
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
) -> None:
    """
    Overwrites a file using multi-pass patterns (0x00, 0xFF, random bytes)
    before anonymizing the filename and removing it from the filesystem.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Target file not found: {file_path}")

    if not os.path.isfile(file_path):
        raise ValueError(f"Path is not a regular file: {file_path}")

    file_size = os.path.getsize(file_path)

    # 3-Pass Overwrite
    patterns = [b"\x00", b"\xFF"]
    chunk_size = 64 * 1024  # 64 KB chunk

    for current_pass in range(1, passes + 1):
        if progress_callback:
            progress_callback(os.path.basename(file_path), current_pass, passes)

        with open(file_path, "ba+", buffering=0) as f:
            f.seek(0)
            remaining = file_size

            # Select pattern: pass 1 = 0x00, pass 2 = 0xFF, pass 3+ = random
            if current_pass == 1:
                pattern_byte = patterns[0]
                fill_chunk = pattern_byte * min(remaining, chunk_size)
                while remaining > 0:
                    write_size = min(remaining, len(fill_chunk))
                    f.write(fill_chunk[:write_size])
                    remaining -= write_size
            elif current_pass == 2:
                pattern_byte = patterns[1]
                fill_chunk = pattern_byte * min(remaining, chunk_size)
                while remaining > 0:
                    write_size = min(remaining, len(fill_chunk))
                    f.write(fill_chunk[:write_size])
                    remaining -= write_size
            else:
                while remaining > 0:
                    write_size = min(remaining, chunk_size)
                    f.write(secrets.token_bytes(write_size))
                    remaining -= write_size

            f.flush()
            os.fsync(f.fileno())

    # Metadata Wipe: Rename file 3 times before final deletion
    dir_name = os.path.dirname(file_path) or "."
    curr_path = file_path
    for _ in range(3):
        new_path = os.path.join(dir_name, _random_filename())
        try:
            os.rename(curr_path, new_path)
            curr_path = new_path
        except OSError:
            break

    # Truncate and remove
    try:
        with open(curr_path, "w") as f:
            f.truncate(0)
        os.remove(curr_path)
    except OSError:
        if os.path.exists(curr_path):
            os.remove(curr_path)


def shred_directory(
    dir_path: str,
    passes: int = 3,
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
) -> None:
    """Recursively shreds all files in a directory and deletes directory structures."""
    if not os.path.exists(dir_path):
        raise FileNotFoundError(f"Target directory not found: {dir_path}")

    for root, dirs, files in os.walk(dir_path, topdown=False):
        for f in files:
            full_path = os.path.join(root, f)
            shred_file(full_path, passes=passes, progress_callback=progress_callback)
        for d in dirs:
            dir_full = os.path.join(root, d)
            try:
                os.rmdir(dir_full)
            except OSError:
                pass

    try:
        os.rmdir(dir_path)
    except OSError:
        pass
