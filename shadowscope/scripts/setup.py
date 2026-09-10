"""
SHADOWSCOPE Setup Script
Initializes the SHADOWSCOPE environment and configuration
"""

import os
import sys
import stat
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

console = Console()


def setup_shadowscope(
    config_path: Optional[str] = None,
    data_dir: Optional[str] = None,
    modules_dir: Optional[str] = None,
    force: bool = False
) -> bool:
    """
    Setup SHADOWSCOPE environment
    
    Args:
        config_path: Path to configuration file
        data_dir: Path to data directory
        modules_dir: Path to modules directory
        force: Force setup even if already exists
        
    Returns:
        bool: True if setup was successful
    """
    try:
        # Get home directory
        home_dir = Path.home()
        
        # Default paths
        if not config_path:
            config_path = str(home_dir / ".shadowscope" / "config.yaml")
        if not data_dir:
            data_dir = str(home_dir / ".shadowscope" / "data")
        if not modules_dir:
            modules_dir = str(home_dir / ".shadowscope" / "modules")
        
        # Create directories
        shadowscope_dir = home_dir / ".shadowscope"
        
        console.print(Panel(
            "[bold blue]SHADOWSCOPE Setup[/bold blue]\n"
            "Initializing environment...",
            title="Setup",
            border_style="blue"
        ))
        
        # Create main directory
        if not shadowscope_dir.exists():
            shadowscope_dir.mkdir(parents=True, exist_ok=True)
            console.print(f"[green]+[/green] Created directory: {shadowscope_dir}")
        else:
            if not force:
                console.print(f"[yellow]![/yellow] Directory already exists: {shadowscope_dir}")
            else:
                console.print(f"[blue]i[/blue] Using existing directory: {shadowscope_dir}")
        
        # Create subdirectories
        subdirs = [
            "data", "modules", "cache", "logs", "exports", "backups", "temp"
        ]
        
        for subdir in subdirs:
            dir_path = shadowscope_dir / subdir
            if not dir_path.exists():
                dir_path.mkdir(parents=True, exist_ok=True)
                console.print(f"[green]+[/green] Created directory: {dir_path}")
            else:
                console.print(f"[blue]i[/blue] Directory exists: {dir_path}")
        
        # Copy default config if not exists
        config_file = Path(config_path)
        default_config = Path(__file__).parent.parent / "config" / "default_config.yaml"
        
        if not config_file.exists():
            # Create from template
            config_content = default_config.read_text() if default_config.exists() else ""
            config_file.write_text(config_content)
            console.print(f"[green]+[/green] Created config: {config_file}")
        else:
            console.print(f"[blue]i[/blue] Config exists: {config_file}")
        
        # Set permissions
        for root, dirs, files in os.walk(shadowscope_dir):
            for d in dirs:
                dir_path = Path(root) / d
                os.chmod(dir_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)
        
        console.print("\n[green]✓[/green] SHADOWSCOPE environment initialized successfully!")
        
        # Print next steps
        console.print("\n[bold]Next Steps:[/bold]")
        console.print("  1. Edit configuration: ~/.shadowscope/config.yaml")
        console.print("  2. Install dependencies: pip install -r requirements.txt")
        console.print("  3. Run SHADOWSCOPE: shadowscope --help")
        
        return True
        
    except Exception as e:
        console.print(f"[red]✗[/red] Setup failed: {e}")
        return False


def interactive_setup() -> bool:
    """Run interactive setup"""
    console.print(Panel(
        "[bold blue]SHADOWSCOPE Interactive Setup[/bold blue]\n\n"
        "This will guide you through the initial setup of SHADOWSCOPE.\n"
        "You can accept defaults by pressing Enter.",
        title="Interactive Setup",
        border_style="blue"
    ))
    
    # Ask for installation type
    install_type = Prompt.ask(
        "\nInstallation type",
        choices=["personal", "team", "production"],
        default="personal"
    )
    
    # Ask for data directory
    data_dir = Prompt.ask(
        "Data directory",
        default=str(Path.home() / ".shadowscope" / "data")
    )
    
    # Ask for modules directory
    modules_dir = Prompt.ask(
        "Modules directory",
        default=str(Path.home() / ".shadowscope" / "modules")
    )
    
    # Ask to install dependencies
    if Confirm.ask("\nInstall Python dependencies now?"):
        import subprocess
        console.print("[blue]i[/blue] Installing dependencies...")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            console.print("[green]✓[/green] Dependencies installed successfully")
        else:
            console.print(f"[yellow]![/yellow] Failed to install dependencies")
            console.print(result.stderr)
    
    # Run setup
    return setup_shadowscope(
        data_dir=data_dir,
        modules_dir=modules_dir
    )


if __name__ == "__main__":
    success = interactive_setup()
    sys.exit(0 if success else 1)
