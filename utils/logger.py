"""
ReconAI - Logger
Rich-colored structured logging for terminal output.
"""
import logging
import sys
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# Custom theme
_theme = Theme({
    "info":     "bold cyan",
    "warning":  "bold yellow",
    "error":    "bold red",
    "success":  "bold green",
    "recon":    "bold magenta",
    "module":   "bold blue",
})

console = Console(theme=_theme)

def setup_logger(log_file: str = None) -> logging.Logger:
    handlers = [RichHandler(console=console, show_time=True, rich_tracebacks=True)]

    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=handlers
    )
    return logging.getLogger("reconai")

log = setup_logger("recon-data/reconai.log")


def banner():
    console.print("""
[bold red]
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗ █████╗ ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║███████║██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══██║██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║  ██║██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝[/bold red]
[bold yellow]  Autonomous Hybrid Recon AI Agent for Bug Bounty & Pentesting[/bold yellow]
[dim]  v2.0 | Linux | Multi-LLM | Parallel Recon Engine[/dim]
""")


def section(title: str):
    console.print(f"\n[bold blue]{'─'*60}[/bold blue]")
    console.print(f"[bold blue]  ▶ {title}[/bold blue]")
    console.print(f"[bold blue]{'─'*60}[/bold blue]")


def success(msg: str):
    console.print(f"[bold green]  ✔ {msg}[/bold green]")


def warn(msg: str):
    console.print(f"[bold yellow]  ⚠ {msg}[/bold yellow]")


def error(msg: str):
    console.print(f"[bold red]  ✘ {msg}[/bold red]")


def info(msg: str):
    console.print(f"[cyan]  → {msg}[/cyan]")


def stat(label: str, value):
    console.print(f"  [dim]{label}:[/dim] [bold white]{value}[/bold white]")
