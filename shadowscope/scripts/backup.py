"""
SHADOWSCOPE Backup Script
Handles database backup and restore operations
"""

import os
import shutil
import sqlite3
from pathlib import Path
from typing import Optional, Union
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

from shadowscope.core import storage

console = Console()


def backup_database(
    output_path: Optional[Union[str, Path]] = None,
    compress: bool = True,
    include_config: bool = True
) -> Optional[Path]:
    """
    Create a backup of the SHADOWSCOPE database
    
    Args:
        output_path: Path to save the backup (default: ~/.shadowscope/backups/)
        compress: Whether to compress the backup
        include_config: Whether to include configuration files
        
    Returns:
        Path to the created backup file, or None if failed
    """
    try:
        # Get storage path
        db_path = storage.get_database_path()
        if not db_path or not Path(db_path).exists():
            console.print("[red]✗[/red] Database not found")
            return None
        
        db_path = Path(db_path)
        
        # Default output path
        if output_path is None:
            home_dir = Path.home()
            backup_dir = home_dir / ".shadowscope" / "backups"
            backup_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = backup_dir / f"shadowscope_backup_{timestamp}"
        else:
            output_path = Path(output_path)
        
        output_path = Path(output_path)
        
        console.print(Panel(
            f"[bold blue]Creating Backup[/bold blue]\n\n"
            f"Source: {db_path}\n"
            f"Destination: {output_path}",
            title="Backup",
            border_style="blue"
        ))
        
        # Create backup directory
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Copy database file
        if compress:
            # Use gzip compression
            import gzip
            backup_file = output_path.with_suffix(".db.gz")
            
            with open(db_path, 'rb') as f_in:
                with gzip.open(backup_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            console.print(f"[green]✓[/green] Compressed backup created: {backup_file}")
            result = backup_file
        else:
            backup_file = output_path.with_suffix(".db")
            shutil.copy2(db_path, backup_file)
            console.print(f"[green]✓[/green] Backup created: {backup_file}")
            result = backup_file
        
        # Include config if requested
        if include_config:
            config_path = Path.home() / ".shadowscope" / "config.yaml"
            if config_path.exists():
                config_backup = output_path.parent / f"config_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
                shutil.copy2(config_path, config_backup)
                console.print(f"[green]✓[/green] Config backed up: {config_backup}")
        
        console.print(f"\n[green]✓[/green] Backup completed successfully!")
        return result
        
    except Exception as e:
        console.print(f"[red]✗[/red] Backup failed: {e}")
        return None


def restore_database(
    backup_path: Union[str, Path],
    force: bool = False
) -> bool:
    """
    Restore SHADOWSCOPE database from backup
    
    Args:
        backup_path: Path to the backup file
        force: Force restore even if database exists
        
    Returns:
        bool: True if restore was successful
    """
    try:
        backup_path = Path(backup_path)
        
        if not backup_path.exists():
            console.print(f"[red]✗[/red] Backup file not found: {backup_path}")
            return False
        
        # Get database path
        db_path = storage.get_database_path()
        if not db_path:
            console.print("[red]✗[/red] Database path not configured")
            return False
        
        db_path = Path(db_path)
        
        # Check if database exists
        if db_path.exists() and not force:
            if not Confirm.ask(
                f"[yellow]![/yellow] Database already exists at {db_path}. Overwrite?",
                default=False
            ):
                console.print("[blue]i[/blue] Restore cancelled")
                return False
        
        console.print(Panel(
            f"[bold blue]Restoring Database[/bold blue]\n\n"
            f"Source: {backup_path}\n"
            f"Destination: {db_path}",
            title="Restore",
            border_style="blue"
        ))
        
        # Handle compressed backup
        if backup_path.suffix == ".gz":
            import gzip
            with gzip.open(backup_path, 'rb') as f_in:
                with open(db_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
        else:
            shutil.copy2(backup_path, db_path)
        
        console.print(f"[green]✓[/green] Database restored: {db_path}")
        console.print("\n[green]✓[/green] Restore completed successfully!")
        return True
        
    except Exception as e:
        console.print(f"[red]✗[/red] Restore failed: {e}")
        return False


def list_backups() -> list:
    """List available backups"""
    backup_dir = Path.home() / ".shadowscope" / "backups"
    
    if not backup_dir.exists():
        console.print("[yellow]![/yellow] No backups found")
        return []
    
    backups = []
    for f in sorted(backup_dir.iterdir(), reverse=True):
        if f.is_file() and (f.suffix == ".db" or f.suffix == ".db.gz"):
            backups.append({
                "path": f,
                "name": f.name,
                "size": f.stat().st_size,
                "modified": datetime.fromtimestamp(f.stat().st_mtime)
            })
    
    return backups


def cleanup_old_backups(max_backups: int = 10) -> int:
    """
    Clean up old backup files
    
    Args:
        max_backups: Maximum number of backups to keep
        
    Returns:
        int: Number of backups deleted
    """
    backup_dir = Path.home() / ".shadowscope" / "backups"
    
    if not backup_dir.exists():
        return 0
    
    backups = []
    for f in backup_dir.iterdir():
        if f.is_file() and (f.suffix == ".db" or f.suffix == ".db.gz"):
            backups.append({
                "path": f,
                "modified": f.stat().st_mtime
            })
    
    # Sort by modification time (oldest first)
    backups.sort(key=lambda x: x["modified"])
    
    deleted = 0
    while len(backups) > max_backups:
        old_backup = backups.pop(0)
        old_backup["path"].unlink()
        deleted += 1
    
    if deleted > 0:
        console.print(f"[green]✓[/green] Deleted {deleted} old backups")
    
    return deleted


if __name__ == "__main__":
    import sys
    
    # Parse command line arguments
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "create" or command == "backup":
            output = sys.argv[2] if len(sys.argv) > 2 else None
            compress = "--no-compress" not in sys.argv
            backup_database(output, compress)
        
        elif command == "restore":
            if len(sys.argv) > 2:
                backup = sys.argv[2]
                force = "--force" in sys.argv
                restore_database(backup, force)
            else:
                console.print("[red]✗[/red] Please specify backup file")
        
        elif command == "list":
            backups = list_backups()
            console.print(f"\n[bold]Available Backups:[/bold]")
            for b in backups:
                console.print(f"  {b['modified'].strftime('%Y-%m-%d %H:%M:%S')} - {b['name']} ({b['size'] / 1024 / 1024:.2f} MB)")
        
        elif command == "cleanup":
            max_backups = int(sys.argv[2]) if len(sys.argv) > 2 else 10
            cleanup_old_backups(max_backups)
        
        else:
            console.print(f"[red]✗[/red] Unknown command: {command}")
            console.print("\nUsage: python -m shadowscope.scripts.backup [command]")
            console.print("\nCommands:")
            console.print("  create [output]    - Create backup")
            console.print("  restore <file>     - Restore from backup")
            console.print("  list              - List available backups")
            console.print("  cleanup [max]      - Clean up old backups")
    else:
        # Interactive mode
        console.print("\n[bold]Backup Operations:[/bold]")
        console.print("  1. Create backup")
        console.print("  2. Restore from backup")
        console.print("  3. List backups")
        console.print("  4. Clean up old backups")
        
        choice = Prompt.ask("\nSelect operation", default="1")
        
        if choice == "1":
            output = Prompt.ask("Output path (leave blank for default)", default="")
            compress = Confirm.ask("Compress backup?", default=True)
            backup_database(output if output else None, compress)
        
        elif choice == "2":
            backups = list_backups()
            if backups:
                console.print("\n[bold]Available Backups:[/bold]")
                for i, b in enumerate(backups, 1):
                    console.print(f"  {i}. {b['modified'].strftime('%Y-%m-%d %H:%M:%S')} - {b['name']}")
                
                selection = Prompt.ask("\nSelect backup to restore", default="1")
                try:
                    idx = int(selection) - 1
                    if 0 <= idx < len(backups):
                        force = Confirm.ask("Force overwrite?", default=False)
                        restore_database(backups[idx]["path"], force)
                except ValueError:
                    console.print("[red]✗[/red] Invalid selection")
            else:
                console.print("[yellow]![/yellow] No backups available")
        
        elif choice == "3":
            backups = list_backups()
            console.print(f"\n[bold]Available Backups:[/bold]")
            for b in backups:
                console.print(f"  {b['modified'].strftime('%Y-%m-%d %H:%M:%S')} - {b['name']} ({b['size'] / 1024 / 1024:.2f} MB)")
        
        elif choice == "4":
            max_backups = Prompt.ask("Maximum backups to keep", default="10")
            cleanup_old_backups(int(max_backups))
