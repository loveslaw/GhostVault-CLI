"""
GhostVault CLI User Interface
Rich Terminal Banners, Panels, and Interactive Progress Display
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

BANNER = """[bold red]
  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗
 ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝
 ██║  ███╗███████║██║   ██║███████╗   ██║   ██║   ██║███████║██║   ██║██║     ██║   
 ██║   ██║██╔══██║██║   ██║╚════██║   ██║   ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   
 ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║    ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝     ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   
[/bold red]
[dim cyan]  AES-256-GCM Zero-Knowledge File Locker · DoD 5220.22-M Shredder · Decoy Vaults[/dim cyan]
[dim white]  Author: loveslaw | Version: 1.0.0[/dim white]
"""


def show_banner():
    console.print(BANNER)


def print_success(message: str, title: str = "SUCCESS"):
    panel = Panel(
        Text(message, style="bold green"),
        title=f"[bold green]✔ {title}[/bold green]",
        border_style="green",
    )
    console.print(panel)


def print_error(message: str, title: str = "ERROR"):
    panel = Panel(
        Text(message, style="bold red"),
        title=f"[bold red]✖ {title}[/bold red]",
        border_style="red",
    )
    console.print(panel)


def print_info(message: str, title: str = "INFO"):
    panel = Panel(
        Text(message, style="cyan"),
        title=f"[bold cyan]ℹ {title}[/bold cyan]",
        border_style="cyan",
    )
    console.print(panel)


def print_summary_table(data: dict, title: str = "Vault Operation Summary"):
    table = Table(title=title, border_style="dim white", show_header=True)
    table.add_column("Property", style="bold cyan")
    table.add_column("Value", style="bold white")
    for k, v in data.items():
        table.add_row(str(k), str(v))
    console.print(table)
