"""
Target Management Commands for SHADOWSCOPE CLI
"""

import typer
from typing import Optional, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from pathlib import Path

from shadowscope.core import targets, storage, config
from shadowscope.cli.app import console, app_state

app = typer.Typer(name="target", help="Target management commands")


@app.command()
def add(
    target: str,
    type: Optional[str] = typer.Option(None, "--type", "-t", help="Target type (auto-detected if not specified)"),
    tags: Optional[List[str]] = typer.Option(None, "--tag", help="Tags to add to the target"),
    metadata: Optional[str] = typer.Option(None, "--metadata", "-m", help="Metadata as JSON string"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Don't print output")
):
    """Add a new target to the scope"""
    import json
    
    metadata_dict = {}
    if metadata:
        try:
            metadata_dict = json.loads(metadata)
        except json.JSONDecodeError:
            console.print("[red]Invalid JSON for metadata[/red]")
            raise typer.Exit(1)
    
    # Add target
    target_obj = targets.add(target, tags=tags, metadata=metadata_dict)
    
    if not quiet:
        console.print(f"[green]+[/green] Added target: {target_obj}")
        if target_obj.tags:
            console.print(f"    Tags: {', '.join(target_obj.tags)}")
        if target_obj.metadata:
            console.print(f"    Metadata: {json.dumps(target_obj.metadata, indent=4)}")


@app.command()
def add_bulk(
    file: str,
    type: Optional[str] = typer.Option(None, "--type", "-t", help="Target type for all targets"),
    tags: Optional[List[str]] = typer.Option(None, "--tag", help="Tags to add to all targets"),
    delimiter: str = typer.Option("\n", "--delimiter", "-d", help="Delimiter for splitting targets")
):
    """Add multiple targets from a file"""
    file_path = Path(file)
    
    if not file_path.exists():
        console.print(f"[red]Error: File not found: {file}[/red]")
        raise typer.Exit(1)
    
    content = file_path.read_text()
    target_list = [t.strip() for t in content.split(delimiter) if t.strip()]
    
    added = targets.add_bulk(target_list, tags=tags)
    console.print(f"[green]+[/green] Added {len(added)} targets from {file}")


@app.command()
def list(
    type: Optional[str] = typer.Option(None, "--type", "-t", help="Filter by target type"),
    status: Optional[str] = typer.Option(None, "--status", "-s", help="Filter by status"),
    tag: Optional[str] = typer.Option(None, "--tag", help="Filter by tag"),
    limit: int = typer.Option(50, "--limit", "-l", help="Maximum number of targets to show"),
    format: str = typer.Option("table", "--format", "-f", help="Output format (table, json, csv)")
):
    """List all targets in the current scope"""
    import json
    import csv
    from datetime import datetime
    
    # Get targets with filters
    if tag:
        all_targets = targets.get_all(tags=[tag])
    else:
        all_targets = targets.get_all(target_type=type, status=status)
    
    # Apply limit
    display_targets = all_targets[:limit]
    
    if format == "json":
        data = [t.to_dict() for t in display_targets]
        console.print(json.dumps(data, indent=2, default=str))
    
    elif format == "csv":
        if not display_targets:
            return
        
        # Get all field names
        fieldnames = ["id", "value", "target_type", "tags", "added_at", "updated_at", "status"]
        
        import io
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for target in display_targets:
            row = target.to_dict()
            row["tags"] = ";".join(row["tags"])
            writer.writerow(row)
        
        console.print(output.getvalue())
    
    else:  # table format
        table = Table(title="Current Scope Targets", show_header=True, header_style="bold blue")
        table.add_column("ID", style="dim")
        table.add_column("Target", style="green")
        table.add_column("Type", style="cyan")
        table.add_column("Tags", style="magenta")
        table.add_column("Status", style="yellow")
        table.add_column("Added", style="dim")
        
        for target in display_targets:
            tags = ", ".join(target.tags) if target.tags else "-"
            status_style = "green" if target.status == "completed" else "yellow" if target.status == "processing" else "dim"
            
            table.add_row(
                str(target.id) if target.id else "-",
                target.value,
                target.target_type,
                tags,
                f"[{status_style}]{target.status}[/{status_style}]",
                target.added_at[:10] if target.added_at else "-"
            )
        
        console.print(table)
        
        if len(all_targets) > limit:
            console.print(f"[dim]... and {len(all_targets) - limit} more targets[/dim]")
        
        console.print(f"[dim]Total: {len(all_targets)} targets[/dim]")


@app.command()
def show(
    target: str,
    format: str = typer.Option("table", "--format", "-f", help="Output format (table, json)")
):
    """Show details for a specific target"""
    import json
    
    target_obj = targets.get(target)
    
    if not target_obj:
        console.print(f"[red]Target not found: {target}[/red]")
        raise typer.Exit(1)
    
    if format == "json":
        console.print(json.dumps(target_obj.to_dict(), indent=2, default=str))
    else:
        table = Table(title=f"Target: {target_obj.value}", show_header=True, header_style="bold blue")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("ID", str(target_obj.id) if target_obj.id else "-")
        table.add_row("Value", target_obj.value)
        table.add_row("Type", target_obj.target_type)
        table.add_row("Status", target_obj.status)
        table.add_row("Added At", target_obj.added_at)
        table.add_row("Updated At", target_obj.updated_at)
        table.add_row("Tags", ", ".join(target_obj.tags) if target_obj.tags else "-")
        table.add_row("Metadata", json.dumps(target_obj.metadata) if target_obj.metadata else "-")
        
        console.print(table)


@app.command()
def remove(
    target: str,
    force: bool = typer.Option(False, "--force", "-f", help="Force removal without confirmation")
):
    """Remove a target from the scope"""
    target_obj = targets.get(target)
    
    if not target_obj:
        console.print(f"[red]Target not found: {target}[/red]")
        raise typer.Exit(1)
    
    if not force:
        typer.confirm(f"Are you sure you want to remove {target}?", abort=True)
    
    success = targets.remove(target_obj)
    
    if success:
        console.print(f"[red]-[/red] Removed target: {target}")
    else:
        console.print(f"[red]Failed to remove target: {target}[/red]")
        raise typer.Exit(1)


@app.command()
def update(
    target: str,
    tags: Optional[List[str]] = typer.Option(None, "--tag", help="Update tags"),
    metadata: Optional[str] = typer.Option(None, "--metadata", "-m", help="Update metadata as JSON"),
    status: Optional[str] = typer.Option(None, "--status", "-s", help="Update status")
):
    """Update a target's properties"""
    import json
    
    target_obj = targets.get(target)
    
    if not target_obj:
        console.print(f"[red]Target not found: {target}[/red]")
        raise typer.Exit(1)
    
    # Prepare updates
    updates = {}
    
    if tags is not None:
        updates["tags"] = tags
    
    if metadata:
        try:
            updates["metadata"] = json.loads(metadata)
        except json.JSONDecodeError:
            console.print("[red]Invalid JSON for metadata[/red]")
            raise typer.Exit(1)
    
    if status:
        updates["status"] = status
    
    if updates:
        success = targets.update(target_obj, **updates)
        
        if success:
            console.print(f"[green]+[/green] Updated target: {target}")
            if "tags" in updates:
                console.print(f"    Tags: {', '.join(updates['tags'])}")
            if "metadata" in updates:
                console.print(f"    Metadata: {json.dumps(updates['metadata'])}")
            if "status" in updates:
                console.print(f"    Status: {updates['status']}")
        else:
            console.print(f"[red]Failed to update target: {target}[/red]")
            raise typer.Exit(1)


@app.command()
def tag(
    targets_list: List[str],
    tags: List[str],
    remove: bool = typer.Option(False, "--remove", "-r", help="Remove tags instead of adding")
):
    """Add or remove tags from multiple targets"""
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
def search(
    query: str,
    limit: int = typer.Option(50, "--limit", "-l", help="Maximum number of results")
):
    """Search targets by value or metadata"""
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
def clear(
    force: bool = typer.Option(False, "--force", "-f", help="Force clear without confirmation"),
    type: Optional[str] = typer.Option(None, "--type", "-t", help="Clear only targets of this type")
):
    """Clear all targets from the scope"""
    if type:
        count = targets.count(target_type=type)
        if count == 0:
            console.print(f"[yellow]No targets of type '{type}' found[/yellow]")
            return
        
        if not force:
            typer.confirm(f"Are you sure you want to remove all {count} targets of type '{type}'?", abort=True)
        
        # Remove all targets of this type
        all_targets = targets.get_all(target_type=type)
        for target in all_targets:
            targets.remove(target)
        
        console.print(f"[yellow]![/yellow] Cleared {count} targets of type '{type}'")
    else:
        count = targets.count()
        if count == 0:
            console.print("[yellow]No targets in scope[/yellow]")
            return
        
        if not force:
            typer.confirm(f"Are you sure you want to remove all {count} targets?", abort=True)
        
        targets.clear()
        console.print(f"[yellow]![/yellow] Cleared all {count} targets")


@app.command()
def types():
    """Show all target types in the current scope"""
    target_types = targets.get_types()
    
    if not target_types:
        console.print("[yellow]No target types in scope[/yellow]")
        return
    
    table = Table(title="Target Types", show_header=True, header_style="bold blue")
    table.add_column("Type", style="cyan")
    table.add_column("Count", style="green")
    
    for target_type in sorted(target_types):
        count = targets.count(target_type=target_type)
        table.add_row(target_type, str(count))
    
    console.print(table)
    console.print(f"[dim]Total types: {len(target_types)}[/dim]")


@app.command()
def tags():
    """Show all tags in the current scope"""
    all_tags = targets.get_tags()
    
    if not all_tags:
        console.print("[yellow]No tags in scope[/yellow]")
        return
    
    # Count usage of each tag
    tag_counts = {}
    all_targets = targets.get_all()
    for target in all_targets:
        for tag in target.tags:
            tag_counts[tag] = tag_counts.get(tag, 0) + 1
    
    table = Table(title="Tags", show_header=True, header_style="bold blue")
    table.add_column("Tag", style="magenta")
    table.add_column("Usage", style="green")
    
    for tag, count in sorted(tag_counts.items(), key=lambda x: (-x[1], x[0])):
        table.add_row(tag, str(count))
    
    console.print(table)
    console.print(f"[dim]Total tags: {len(all_tags)}[/dim]")


@app.command()
def import_file(
    file: str,
    type: Optional[str] = typer.Option(None, "--type", "-t", help="Target type for imported targets"),
    tags: Optional[List[str]] = typer.Option(None, "--tag", help="Tags to add to imported targets")
):
    """Import targets from a file"""
    count = targets.import_from_file(file, target_type=type)
    
    if count > 0:
        console.print(f"[green]+[/green] Imported {count} targets from {file}")
    else:
        console.print(f"[red]No targets imported from {file}[/red]")


@app.command()
def export_file(
    file: str,
    format: str = typer.Option("text", "--format", "-f", help="Export format (text, json, csv)")
):
    """Export targets to a file"""
    output_path = targets.export_to_file(file, format=format)
    console.print(f"[green]+[/green] Exported targets to {output_path}")


@app.command()
def validate():
    """Validate all targets in the scope"""
    issues = targets.validate_targets()
    
    if not issues["invalid"] and not issues["duplicate"]:
        console.print("[green]+[/green] All targets are valid")
        return
    
    if issues["duplicate"]:
        console.print("[yellow]Duplicate targets found:[/yellow]")
        for dup in issues["duplicate"]:
            console.print(f"  - {dup}")
    
    if issues["invalid"]:
        console.print("[red]Invalid targets found:[/red]")
        for inv in issues["invalid"]:
            console.print(f"  - {inv}")
