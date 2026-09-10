"""
TUI Commands for SHADOWSCOPE CLI
Textual-based terminal user interface
"""

import typer
from typing import Optional
from rich.console import Console

from shadowscope.cli.app import console, app_state

app = typer.Typer(name="tui", help="Terminal User Interface commands")


@app.command()
def start(
    module: Optional[str] = typer.Option(None, "--module", "-m", help="Start TUI with specific module"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Target to investigate")
):
    """Start the Textual-based TUI"""
    try:
        from shadowscope.tui.app import run_tui
        run_tui(module=module, target=target)
    except ImportError:
        console.print("[yellow]Textual not installed. Install with: pip install textual[/yellow]")
        raise typer.Exit(1)


@app.command()
def scope():
    """Open scope management in TUI"""
    try:
        from shadowscope.tui.app import run_scope_tui
        run_scope_tui()
    except ImportError:
        console.print("[yellow]Textual not installed. Install with: pip install textual[/yellow]")
        raise typer.Exit(1)


@app.command()
def results():
    """Open results viewer in TUI"""
    try:
        from shadowscope.tui.app import run_results_tui
        run_results_tui()
    except ImportError:
        console.print("[yellow]Textual not installed. Install with: pip install textual[/yellow]")
        raise typer.Exit(1)


@app.command()
def modules():
    """Open module management in TUI"""
    try:
        from shadowscope.tui.app import run_modules_tui
        run_modules_tui()
    except ImportError:
        console.print("[yellow]Textual not installed. Install with: pip install textual[/yellow]")
        raise typer.Exit(1)


@app.command()
def logs():
    """Open logs viewer in TUI"""
    try:
        from shadowscope.tui.app import run_logs_tui
        run_logs_tui()
    except ImportError:
        console.print("[yellow]Textual not installed. Install with: pip install textual[/yellow]")
        raise typer.Exit(1)
