"""
GhostVault-CLI
High-Performance Zero-Knowledge Encrypted Vault & DoD 5220.22-M File Shredder
Author: loveslaw
"""

import argparse
import getpass
import os
import sys

from core.ui import (
    console,
    show_banner,
    print_success,
    print_error,
    print_info,
    print_summary_table,
)
from core.vault import VaultManager
from core.shredder import shred_file, shred_directory
from core.crypto import AuthenticationError, CorruptedVaultError


def cmd_lock(args):
    target = os.path.abspath(args.target)
    if not os.path.exists(target):
        print_error(f"Target path not found: {target}")
        sys.exit(1)

    out_file = args.output
    if not out_file:
        out_file = target.rstrip(os.sep) + ".gvault"

    password = args.password
    if not password:
        password = getpass.getpass("🔑 Enter master vault password: ")
        confirm = getpass.getpass("🔑 Confirm master vault password: ")
        if password != confirm:
            print_error("Passwords do not match!")
            sys.exit(1)

    decoy_path = None
    decoy_password = None
    if args.decoy:
        decoy_path = os.path.abspath(args.decoy)
        if not os.path.exists(decoy_path):
            print_error(f"Decoy target path not found: {decoy_path}")
            sys.exit(1)
        decoy_password = args.decoy_password
        if not decoy_password:
            decoy_password = getpass.getpass("🎭 Enter decoy vault password: ")
            decoy_confirm = getpass.getpass("🎭 Confirm decoy vault password: ")
            if decoy_password != decoy_confirm:
                print_error("Decoy passwords do not match!")
                sys.exit(1)

    with console.status("[bold red]Locking vault and applying AES-256-GCM encryption..."):
        VaultManager.create_vault(
            target_path=target,
            password=password,
            output_file=out_file,
            decoy_path=decoy_path,
            decoy_password=decoy_password,
            shred_source=args.shred,
        )

    summary = {
        "Status": "Locked & Encrypted",
        "Target Path": target,
        "Vault File": out_file,
        "Plausible Deniability": "Enabled (Dual-Slot)" if decoy_path else "Standard (Single-Slot)",
        "Source Shredded": "Yes (DoD 5220.22-M)" if args.shred else "No (Preserved)",
    }
    print_success("Vault created and secured successfully!")
    print_summary_table(summary)


def cmd_unlock(args):
    vault_file = os.path.abspath(args.vault)
    if not os.path.exists(vault_file):
        print_error(f"Vault file not found: {vault_file}")
        sys.exit(1)

    dest = args.dest or os.path.dirname(vault_file) or "."
    password = args.password
    if not password:
        password = getpass.getpass("🔑 Enter vault password: ")

    with console.status("[bold green]Authenticating and decrypting vault..."):
        try:
            extracted_path, is_decoy = VaultManager.unlock_vault(
                vault_file=vault_file,
                password=password,
                destination_dir=dest,
            )
        except AuthenticationError as e:
            print_error(str(e), title="AUTHENTICATION FAILED")
            sys.exit(1)
        except CorruptedVaultError as e:
            print_error(str(e), title="CORRUPTED VAULT")
            sys.exit(1)

    summary = {
        "Vault File": vault_file,
        "Extracted Destination": extracted_path,
        "Payload Type": "🎭 Decoy Vault Unpacked" if is_decoy else "🛡️ Primary Vault Unpacked",
    }
    print_success("Vault decrypted and extracted successfully!")
    print_summary_table(summary)


def cmd_shred(args):
    target = os.path.abspath(args.target)
    if not os.path.exists(target):
        print_error(f"Target not found: {target}")
        sys.exit(1)

    passes = args.passes or 3
    console.print(f"[bold yellow]⚠️ WARNING: Irreversible 3-Pass DoD shred requested on: {target}[/bold yellow]")
    if not args.force:
        confirm = input("Type 'SHRED' to confirm permanent destruction: ")
        if confirm != "SHRED":
            print_info("Shredding cancelled.")
            sys.exit(0)

    with console.status(f"[bold red]Overwriting ({passes} passes) and anonymizing metadata..."):
        if os.path.isdir(target):
            shred_directory(target, passes=passes)
        else:
            shred_file(target, passes=passes)

    print_success(f"Target securely shredded and wiped from filesystem: {target}")


def interactive_menu():
    show_banner()
    console.print("[bold white]1.[/bold white] 🔒 Lock File or Directory (.gvault)")
    console.print("[bold white]2.[/bold white] 🔓 Unlock Existing Vault")
    console.print("[bold white]3.[/bold white] 🗑️  Shred File or Directory (DoD 5220.22-M)")
    console.print("[bold white]4.[/bold white] 🚪 Exit")
    choice = input("\nSelect an option [1-4]: ").strip()

    if choice == "1":
        path = input("Enter path to file or directory to lock: ").strip()
        shred_q = input("Shred original source after locking? (y/N): ").strip().lower()
        args = argparse.Namespace(
            target=path,
            output=None,
            password=None,
            decoy=None,
            decoy_password=None,
            shred=(shred_q == "y"),
        )
        cmd_lock(args)
    elif choice == "2":
        path = input("Enter path to .gvault file: ").strip()
        dest = input("Enter extraction destination folder (leave blank for current dir): ").strip()
        args = argparse.Namespace(
            vault=path,
            dest=dest or None,
            password=None,
        )
        cmd_unlock(args)
    elif choice == "3":
        path = input("Enter path to file or directory to permanently shred: ").strip()
        args = argparse.Namespace(
            target=path,
            passes=3,
            force=False,
        )
        cmd_shred(args)
    else:
        print_info("Exiting GhostVault. Stay secure!")
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description="GhostVault-CLI - AES-256-GCM Zero-Knowledge Vault & DoD 5220.22-M Shredder"
    )
    subparsers = parser.add_subparsers(dest="command")

    # Lock
    lock_p = subparsers.add_parser("lock", help="Encrypt and lock a file or directory")
    lock_p.add_argument("target", help="File or directory path to lock")
    lock_p.add_argument("-o", "--output", help="Output .gvault file path")
    lock_p.add_argument("-p", "--password", help="Master encryption password")
    lock_p.add_argument("--decoy", help="Optional decoy file/directory for plausible deniability")
    lock_p.add_argument("--decoy-password", help="Password to unlock the decoy payload")
    lock_p.add_argument("--shred", action="store_true", help="Permanently shred original files after locking")

    # Unlock
    unlock_p = subparsers.add_parser("unlock", help="Decrypt and extract a .gvault file")
    unlock_p.add_argument("vault", help="Path to .gvault file")
    unlock_p.add_argument("-d", "--dest", help="Destination directory for extracted content")
    unlock_p.add_argument("-p", "--password", help="Decryption password")

    # Shred
    shred_p = subparsers.add_parser("shred", help="Securely overwrite and shred files or directories")
    shred_p.add_argument("target", help="File or directory path to destroy")
    shred_p.add_argument("--passes", type=int, default=3, help="Number of overwrite passes (default: 3)")
    shred_p.add_argument("-f", "--force", action="store_true", help="Skip confirmation prompt")

    if len(sys.argv) == 1:
        interactive_menu()
    else:
        args = parser.parse_args()
        show_banner()
        if args.command == "lock":
            cmd_lock(args)
        elif args.command == "unlock":
            cmd_unlock(args)
        elif args.command == "shred":
            cmd_shred(args)
        else:
            parser.print_help()


if __name__ == "__main__":
    main()
