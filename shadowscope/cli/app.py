"""
SHADOWSCOPE CLI Application
Main entry point for the command-line interface.
"""

import os
import sys
import typer
from typing import Optional, List
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from pathlib import Path

# Initialize console
console = Console()

# Create Typer app
app = typer.Typer(
    name="shadowscope",
    help="SHADOWSCOPE - Modular OSINT Framework for Deep Reconnaissance",
    epilog="Designed for elite operators. No attribution. No limits.",
    add_completion=True,
    no_args_is_help=True,
    pretty_exceptions_enable=False
)

# State for the application
app_state = {
    "current_scope": [],
    "running_modules": {},
    "verbose": False,
    "debug": False
}


def print_banner():
    """Print the SHADOWSCOPE banner"""
    banner = r"""
   _____ _   _ _____ _____ ____  _   _ _____ _____ ____  
  / ____| \ | |_   _|_   _|  _ \| \ | |_   _| ____/ ___| 
 | |  __|  \| | | |   | | | |_) |  \| | | | |  _| \___ \ 
 | | |_ | . ` | | |   | | |  _ <| . ` | | | | |___| |__| |
 | |__| | |\  |_| |_  | |_| |_) | |\  |_| |_| |____  __| |
  \_____|_| \_|___/|_| |_____|____/|_| \_|___/|_____|____/ 
    """
    
    console.print(Panel(
        f"[bold red]{banner}[/bold red]",
        title="[bold white]SHADOWSCOPE[/bold white]",
        subtitle="[dim]Modular OSINT Framework v1.0.0[/dim]",
        border_style="blue"
    ))


def print_footer():
    """Print footer information"""
    console.print("[dim]\nNo attribution. No limits. No apologies.[/dim]")


# Callback for the main app
@app.callback()
def main_callback(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
    debug: bool = typer.Option(False, "--debug", "-d", help="Enable debug mode"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Skip the banner on startup"),
    version: bool = typer.Option(False, "--version", help="Show version and exit")
):
    """Main callback for the CLI"""
    if version:
        console.print("[bold]SHADOWSCOPE v1.0.0[/bold]")
        console.print("[dim]Modular OSINT Framework[/dim]")
        raise typer.Exit()
    
    # Set state
    app_state["verbose"] = verbose
    app_state["debug"] = debug
    
    # Print banner
    if not no_banner:
        print_banner()


# Import command groups
from .commands import (
    target_commands,
    module_commands,
    scope_commands,
    config_commands,
    storage_commands
)

# Try to import optional command groups
try:
    from .commands import proxy_commands
    HAS_PROXY = True
except ImportError:
    HAS_PROXY = False
    proxy_commands = None

try:
    from .commands import sandbox_commands
    HAS_SANDBOX = True
except ImportError:
    HAS_SANDBOX = False
    sandbox_commands = None

try:
    from .commands import tui_commands
    HAS_TUI = True
except ImportError:
    HAS_TUI = False
    tui_commands = None

# Register command groups
app.add_typer(target_commands.app, name="target", help="Target management commands")
app.add_typer(module_commands.app, name="module", help="Module management commands")
app.add_typer(scope_commands.app, name="scope", help="Scope management commands")
app.add_typer(config_commands.app, name="config", help="Configuration commands")
app.add_typer(storage_commands.app, name="storage", help="Storage and database commands")

if HAS_PROXY:
    app.add_typer(proxy_commands.app, name="proxy", help="Proxy and anonymity commands")

if HAS_SANDBOX:
    app.add_typer(sandbox_commands.app, name="sandbox", help="Sandbox management commands")

if HAS_TUI:
    app.add_typer(tui_commands.app, name="tui", help="Text-based user interface")


# Main entry point
def main():
    """Main entry point for the CLI"""
    app()


if __name__ == "__main__":
    main()
