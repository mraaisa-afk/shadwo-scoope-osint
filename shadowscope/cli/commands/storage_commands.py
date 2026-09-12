"""
Storage Commands for SHADOWSCOPE CLI
"""

from pathlib import Path

import typer
from rich.panel import Panel
from rich.table import Table

from shadowscope.cli.app import console
from shadowscope.core import config, storage

app = typer.Typer(name="storage", help="Storage and database commands")


@app.command()
def stats():
    """Show storage statistics"""
    stats_data = storage.get_stats()

    console.print(Panel("[bold]Storage Statistics[/bold]", style="blue", border_style="blue"))

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="white")
    table.add_column("Count", style="green")

    table.add_row("Total Targets", str(stats_data["targets"]))
    table.add_row("Total Results", str(stats_data["results"]))
    table.add_row("Total Modules", str(stats_data["modules"]))

    console.print(table)

    if stats_data["targets_by_type"]:
        console.print("\n[bold]Targets by Type:[/bold]")
        for target_type, count in sorted(stats_data["targets_by_type"].items(), key=lambda x: (-x[1], x[0])):
            console.print(f"  {target_type}: {count}")

    if stats_data["results_by_module"]:
        console.print("\n[bold]Results by Module:[/bold]")
        for module, count in sorted(stats_data["results_by_module"].items(), key=lambda x: (-x[1], x[0]))[:10]:
            console.print(f"  {module}: {count}")

    if stats_data["results_by_status"]:
        console.print("\n[bold]Results by Status:[/bold]")
        for status_val, count in sorted(stats_data["results_by_status"].items(), key=lambda x: (-x[1], x[0])):
            console.print(f"  {status_val}: {count}")


@app.command()
def search(
    query: str,
    limit: int = typer.Option(50, "--limit", "-l", help="Maximum number of results")
):
    """Search across all stored data"""
    results = storage.search(query, limit)

    if not results:
        console.print("[yellow]No results found matching query[/yellow]")
        return

    table = Table(title=f"Search Results for '{query}'", show_header=True, header_style="bold blue")
    table.add_column("Type", style="cyan")
    table.add_column("ID", style="dim")
    table.add_column("Value", style="green")
    table.add_column("Details", style="white")
    table.add_column("Timestamp", style="dim")

    for result in results:
        details = ""
        if "target_type" in result:
            details = result["target_type"]
        elif "module" in result:
            details = result["module"]
        elif "category" in result:
            details = result["category"]

        table.add_row(
            result["type"],
            str(result["id"]),
            result["value"],
            details,
            result["timestamp"][:10] if result["timestamp"] else "-"
        )

    console.print(table)
    console.print(f"[dim]Found {len(results)} results[/dim]")


@app.command()
def backup(
    path: str | None = typer.Option(None, "--path", "-p", help="Backup file path (auto-generated if not specified)")
):
    """Create a backup of the database"""
    backup_path = storage.backup(path)
    console.print(f"[green]+[/green] Created backup: {backup_path}")


@app.command()
def export(
    path: str,
    targets: bool = typer.Option(True, "--targets", help="Export targets"),
    results: bool = typer.Option(True, "--results", help="Export results"),
    modules: bool = typer.Option(True, "--modules", help="Export modules"),
    format: str = typer.Option("json", "--format", "-f", help="Export format (json, csv, html)")
):
    """Export stored targets and results to a file (JSON, CSV, or HTML report)"""
    fmt = format.lower().strip()
    if fmt == "csv":
        output_path = storage.export_csv(path)
    elif fmt in ("html", "htm"):
        output_path = storage.export_html(path)
    else:
        output_path = storage.export_json(path, targets=targets, results=results, modules=modules)

    console.print(f"[green]+[/green] Exported data to {output_path} (Format: {fmt.upper()})")


@app.command()
def import_data(
    path: str
):
    """Import data from a file"""
    file_path = Path(path)

    if not file_path.exists():
        console.print(f"[red]Error: File not found: {path}[/red]")
        raise typer.Exit(1)

    try:
        storage.import_json(path)
        console.print(f"[green]+[/green] Imported data from {path}")
    except Exception as e:
        console.print(f"[red]Error importing data: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def clear(
    targets: bool = typer.Option(False, "--targets", help="Clear all targets"),
    results: bool = typer.Option(False, "--results", help="Clear all results"),
    modules: bool = typer.Option(False, "--modules", help="Clear all modules"),
    all: bool = typer.Option(False, "--all", "-a", help="Clear everything"),
    force: bool = typer.Option(False, "--force", "-f", help="Force clear without confirmation")
):
    """Clear stored data"""
    if not (targets or results or modules or all):
        console.print("[red]Please specify what to clear[/red]")
        raise typer.Exit(1)

    if all:
        targets = results = modules = True

    count = 0
    if targets:
        count += storage.get_stats()["targets"]
    if results:
        count += storage.get_stats()["results"]
    if modules:
        count += storage.get_stats()["modules"]

    if count == 0:
        console.print("[yellow]Nothing to clear[/yellow]")
        return

    if not force:
        typer.confirm(f"Are you sure you want to clear {count} items?", abort=True)

    if targets:
        all_targets = storage.get_all_targets()
        for target in all_targets:
            storage.delete_target(target.id)

    if results:
        all_results = storage.get_results_by_module("")
        for result in all_results:
            storage.delete_result(result.id)

    if modules:
        all_modules = storage.get_all_modules()
        for module in all_modules:
            storage.delete_module(module.name)

    console.print("[yellow]![/yellow] Cleared data")


@app.command()
def info():
    """Show storage information"""
    console.print(Panel("[bold]Storage Information[/bold]", style="blue", border_style="blue"))

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Property", style="white")
    table.add_column("Value", style="green")

    db_path = Path(config.storage.path).expanduser()
    if db_path.exists():
        db_size = db_path.stat().st_size
        table.add_row("Database Path", str(db_path))
        table.add_row("Database Size", f"{db_size / (1024 * 1024):.2f} MB")
        table.add_row("Database Exists", "[green]Yes[/green]")
    else:
        table.add_row("Database Path", str(db_path))
        table.add_row("Database Exists", "[red]No[/red]")

    table.add_row("Backend", config.storage.backend)

    encryption_enabled = config.storage.encryption.get("enabled", True)
    table.add_row("Encryption", "[green]Enabled[/green]" if encryption_enabled else "[red]Disabled[/red]")
    table.add_row("Encryption Algorithm", config.storage.encryption.get("algorithm", "aes-256-cbc"))

    backup_enabled = config.storage.backup.get("enabled", True)
    table.add_row("Backup Enabled", "[green]Yes[/green]" if backup_enabled else "[red]No[/red]")

    console.print(table)


@app.command()
def optimize():
    """Optimize the database"""
    console.print("[blue]#[/blue] Optimizing database...")

    try:
        with storage._get_connection() as conn:
            conn.execute("VACUUM")
            conn.execute("ANALYZE")
            conn.commit()

        console.print("[green]+[/green] Database optimized")
    except Exception as e:
        console.print(f"[red]Error optimizing database: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def check():
    """Check database integrity"""
    console.print("[blue]#[/blue] Checking database integrity...")

    try:
        db_path = Path(config.storage.path).expanduser()
        if not db_path.exists():
            console.print("[yellow]Database file does not exist[/yellow]")
            return

        stats_data = storage.get_stats()
        console.print("[green]+[/green] Database is accessible")
        console.print(f"  Targets: {stats_data['targets']}")
        console.print(f"  Results: {stats_data['results']}")
        console.print(f"  Modules: {stats_data['modules']}")

        all_results = storage.get_results_by_module("")
        all_target_ids = {t.id for t in storage.get_all_targets()}
        orphaned = [r for r in all_results if r.target_id not in all_target_ids]

        if orphaned:
            console.print(f"[yellow]Found {len(orphaned)} orphaned results[/yellow]")
        else:
            console.print("[green]+[/green] No orphaned results found")

    except Exception as e:
        console.print(f"[red]Database integrity check failed: {e}[/red]")
        raise typer.Exit(1)
