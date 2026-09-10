"""
Scope Management Commands for SHADOWSCOPE CLI
"""

import typer
from typing import Optional, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from shadowscope.core import targets, storage
from shadowscope.cli.app import console, app_state

app = typer.Typer(name="scope", help="Scope management commands")


@app.command()
def show(
    format: str = typer.Option("table", "--format", "-f", help="Output format (table, json)")
):
    """Show the current scope"""
    import json
    
    all_targets = targets.get_all()
    
    if format == "json":
        data = [t.to_dict() for t in all_targets]
        console.print(json.dumps(data, indent=2, default=str))
    else:
        targets.display_table()


@app.command()
def add(
    targets_list: List[str],
    tags: Optional[List[str]] = typer.Option(None, "--tag", help="Tags to add to all targets"),
    type: Optional[str] = typer.Option(None, "--type", "-t", help="Target type for all targets")
):
    """Add targets to the current scope"""
    added = targets.add_bulk(targets_list, tags=tags)
    console.print(f"[green]+[/green] Added {len(added)} targets to scope")


@app.command()
def remove(
    targets_list: List[str],
    force: bool = typer.Option(False, "--force", "-f", help="Force removal without confirmation")
):
    """Remove targets from the current scope"""
    if not force:
        console.print(f"[yellow]Warning: About to remove {len(targets_list)} targets[/yellow]")
        typer.confirm("Are you sure?", abort=True)
    
    count = 0
    for target in targets_list:
        target_obj = targets.get(target)
        if target_obj:
            targets.remove(target_obj)
            count += 1
    
    console.print(f"[red]-[/red] Removed {count} targets from scope")


@app.command()
def clear(
    force: bool = typer.Option(False, "--force", "-f", help="Force clear without confirmation")
):
    """Clear the current scope"""
    count = targets.count()
    
    if count == 0:
        console.print("[yellow]Scope is already empty[/yellow]")
        return
    
    if not force:
        typer.confirm(f"Are you sure you want to clear all {count} targets from scope?", abort=True)
    
    targets.clear()
    console.print(f"[yellow]![/yellow] Cleared {count} targets from scope")


@app.command()
def stats():
    """Show scope statistics"""
    all_targets = targets.get_all()
    
    # Count by type
    type_counts = {}
    for target in all_targets:
        type_counts[target.target_type] = type_counts.get(target.target_type, 0) + 1
    
    # Count by status
    status_counts = {}
    for target in all_targets:
        status_counts[target.status] = status_counts.get(target.status, 0) + 1
    
    # Count tags
    tag_counts = {}
    for target in all_targets:
        for tag in target.tags:
            tag_counts[tag] = tag_counts.get(tag, 0) + 1
    
    console.print(Panel("[bold]Scope Statistics[/bold]", style="blue", border_style="blue"))
    
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="white")
    table.add_column("Count", style="green")
    
    table.add_row("Total Targets", str(len(all_targets)))
    table.add_row("Unique Types", str(len(type_counts)))
    table.add_row("Unique Tags", str(len(tag_counts)))
    
    console.print(table)
    
    if type_counts:
        console.print("\n[bold]By Type:[/bold]")
        for target_type, count in sorted(type_counts.items(), key=lambda x: (-x[1], x[0])):
            console.print(f"  {target_type}: {count}")
    
    if status_counts:
        console.print("\n[bold]By Status:[/bold]")
        for status, count in sorted(status_counts.items(), key=lambda x: (-x[1], x[0])):
            console.print(f"  {status}: {count}")
    
    if tag_counts:
        console.print("\n[bold]Top Tags:[/bold]")
        for tag, count in sorted(tag_counts.items(), key=lambda x: (-x[1], x[0]))[:10]:
            console.print(f"  {tag}: {count}")


@app.command()
def save(
    file: str,
    format: str = typer.Option("json", "--format", "-f", help="Export format (json, text, csv)")
):
    """Save the current scope to a file"""
    output_path = targets.export_to_file(file, format=format)
    console.print(f"[green]+[/green] Saved scope to {output_path}")


@app.command()
def load(
    file: str,
    tags: Optional[List[str]] = typer.Option(None, "--tag", help="Tags to add to imported targets")
):
    """Load targets from a file into the current scope"""
    count = targets.import_from_file(file, target_type=None)
    
    if count > 0:
        console.print(f"[green]+[/green] Loaded {count} targets into scope from {file}")
    else:
        console.print(f"[red]No targets loaded from {file}[/red]")


@app.command()
def search(
    query: str,
    limit: int = typer.Option(50, "--limit", "-l", help="Maximum number of results")
):
    """Search the current scope"""
    results = targets.search(query, limit)
    
    if not results:
        console.print("[yellow]No targets found matching query[/yellow]")
        return
    
    table = Table(title=f"Search Results for '{query}'", show_header=True, header_style="bold blue")
    table.add_column("Target", style="green")
    table.add_column("Type", style="cyan")
    table.add_column("Tags", style="magenta")
    table.add_column("Added", style="dim")
    
    for target in results:
        tags = ", ".join(target.tags) if target.tags else "-"
        table.add_row(
            target.value,
            target.target_type,
            tags,
            target.added_at[:10] if target.added_at else "-"
        )
    
    console.print(table)
    console.print(f"[dim]Found {len(results)} targets[/dim]")


@app.command()
def tag(
    targets_list: List[str],
    tags: List[str],
    remove: bool = typer.Option(False, "--remove", "-r", help="Remove tags instead of adding")
):
    """Add or remove tags from targets in scope"""
    target_objs = []
    for t in targets_list:
        obj = targets.get(t)
        if obj:
            target_objs.append(obj)
        else:
            console.print(f"[yellow]Warning: Target not found: {t}[/yellow]")
    
    if not target_objs:
        console.print("[red]No valid targets specified[/red]")
        raise typer.Exit(1)
    
    if remove:
        count = targets.untag(target_objs, tags)
        console.print(f"[blue]#[/blue] Removed tags from {count} targets: {tags}")
    else:
        count = targets.tag(target_objs, tags)
        console.print(f"[blue]#[/blue] Tagged {count} targets with: {tags}")


@app.command()
def filter(
    type: Optional[str] = typer.Option(None, "--type", "-t", help="Filter by target type"),
    status: Optional[str] = typer.Option(None, "--status", "-s", help="Filter by status"),
    tag: Optional[str] = typer.Option(None, "--tag", help="Filter by tag")
):
    """Filter the current scope"""
    if not type and not status and not tag:
        console.print("[red]Please specify at least one filter[/red]")
        raise typer.Exit(1)
    
    filtered = targets.get_all(target_type=type, status=status, tags=[tag] if tag else None)
    
    if not filtered:
        console.print("[yellow]No targets match the specified filters[/yellow]")
        return
    
    console.print(f"[blue]#[/blue] Found {len(filtered)} targets matching filters:")
    
    table = Table(show_header=True, header_style="bold blue")
    table.add_column("Target", style="green")
    table.add_column("Type", style="cyan")
    table.add_column("Tags", style="magenta")
    table.add_column("Status", style="yellow")
    
    for target in filtered:
        tags = ", ".join(target.tags) if target.tags else "-"
        status_style = "green" if target.status == "completed" else "yellow" if target.status == "processing" else "dim"
        table.add_row(
            target.value,
            target.target_type,
            tags,
            f"[{status_style}]{target.status}[/{status_style}]"
        )
    
    console.print(table)
