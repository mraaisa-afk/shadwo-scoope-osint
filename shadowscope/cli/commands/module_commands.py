"""
Module Management Commands for SHADOWSCOPE CLI
"""

import typer
import asyncio
from typing import Optional, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from pathlib import Path

from shadowscope.core import modules, targets, storage, config
from shadowscope.cli.app import console, app_state

app = typer.Typer(name="module", help="Module management commands")


@app.command()
def list(
    category: Optional[str] = typer.Option(None, "--category", "-c", help="Filter by category"),
    target_type: Optional[str] = typer.Option(None, "--target-type", "-t", help="Filter by target type"),
    show_disabled: bool = typer.Option(False, "--show-disabled", "-a", help="Show disabled modules"),
    format: str = typer.Option("table", "--format", "-f", help="Output format (table, json)")
):
    """List all available modules"""
    import json
    
    # Discover modules
    modules.discover_modules()
    
    # Get modules with filters
    if category:
        module_list = modules.get_modules_by_category(category)
    elif target_type:
        module_list = modules.get_modules_by_target_type(target_type)
    else:
        module_list = modules.list_modules(show_disabled=show_disabled)
    
    if format == "json":
        data = [m.to_dict() for m in module_list]
        console.print(json.dumps(data, indent=2, default=str))
    else:
        table = Table(title="Available Modules", show_header=True, header_style="bold blue")
        table.add_column("Name", style="green")
        table.add_column("Version", style="dim")
        table.add_column("Category", style="cyan")
        table.add_column("Target Types", style="magenta")
        table.add_column("Status", style="yellow")
        table.add_column("Description", style="white")
        
        for module in module_list:
            status = "[green]enabled[/green]" if module.enabled else "[red]disabled[/red]"
            target_types = ", ".join(module.target_types) if module.target_types else "all"
            description = module.description[:50] + "..." if len(module.description) > 50 else module.description
            
            table.add_row(
                module.name,
                module.version,
                module.category,
                target_types,
                status,
                description
            )
        
        console.print(table)
        console.print(f"[dim]Total: {len(module_list)} modules[/dim]")


@app.command()
def show(
    module: str,
    format: str = typer.Option("table", "--format", "-f", help="Output format (table, json)")
):
    """Show details for a specific module"""
    import json
    
    module_metadata = modules.get_module(module)
    
    if not module_metadata:
        console.print(f"[red]Module not found: {module}[/red]")
        raise typer.Exit(1)
    
    if format == "json":
        console.print(json.dumps(module_metadata.to_dict(), indent=2, default=str))
    else:
        table = Table(title=f"Module: {module_metadata.name}", show_header=True, header_style="bold blue")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Name", module_metadata.name)
        table.add_row("Version", module_metadata.version)
        table.add_row("Author", module_metadata.author)
        table.add_row("Category", module_metadata.category)
        table.add_row("Description", module_metadata.description)
        table.add_row("Target Types", ", ".join(module_metadata.target_types) if module_metadata.target_types else "all")
        table.add_row("Dependencies", ", ".join(module_metadata.dependencies) if module_metadata.dependencies else "-")
        table.add_row("Enabled", "Yes" if module_metadata.enabled else "No")
        table.add_row("Sandboxed", "Yes" if module_metadata.is_sandboxed else "No")
        table.add_row("Timeout", f"{module_metadata.timeout} seconds")
        
        console.print(table)


@app.command()
def install(
    module: str,
    source: str = typer.Option("registry", "--source", "-s", help="Source to install from (registry, local)")
):
    """Install a module"""
    success = modules.install_module(module, source)
    
    if success:
        console.print(f"[green]+[/green] Successfully installed module: {module}")
    else:
        console.print(f"[red]Failed to install module: {module}[/red]")
        raise typer.Exit(1)


@app.command()
def uninstall(
    module: str,
    force: bool = typer.Option(False, "--force", "-f", help="Force uninstall without confirmation")
):
    """Uninstall a module"""
    if not force:
        typer.confirm(f"Are you sure you want to uninstall {module}?", abort=True)
    
    success = modules.uninstall_module(module)
    
    if success:
        console.print(f"[yellow]-[/yellow] Successfully uninstalled module: {module}")
    else:
        console.print(f"[red]Failed to uninstall module: {module}[/red]")
        raise typer.Exit(1)


@app.command()
def enable(
    module: str
):
    """Enable a module"""
    success = modules.enable_module(module)
    
    if success:
        console.print(f"[green]+[/green] Enabled module: {module}")
    else:
        console.print(f"[red]Failed to enable module: {module}[/red]")
        raise typer.Exit(1)


@app.command()
def disable(
    module: str
):
    """Disable a module"""
    success = modules.disable_module(module)
    
    if success:
        console.print(f"[yellow]-[/yellow] Disabled module: {module}")
    else:
        console.print(f"[red]Failed to disable module: {module}[/red]")
        raise typer.Exit(1)


@app.command()
def update(
    module: str
):
    """Update a module to the latest version"""
    success = modules.update_module(module)
    
    if success:
        console.print(f"[green]+[/green] Updated module: {module}")
    else:
        console.print(f"[red]Failed to update module: {module}[/red]")
        raise typer.Exit(1)


@app.command()
def run(
    module: str,
    targets_list: Optional[List[str]] = typer.Argument(None, help="Target(s) to run the module on"),
    all_targets: bool = typer.Option(False, "--all", "-a", help="Run on all targets in scope"),
    tag: Optional[str] = typer.Option(None, "--tag", "-t", help="Run on targets with this tag"),
    type: Optional[str] = typer.Option(None, "--type", help="Run on targets of this type"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Module configuration as JSON"),
    timeout: Optional[int] = typer.Option(None, "--timeout", help="Module timeout in seconds"),
    no_sandbox: bool = typer.Option(False, "--no-sandbox", help="Disable sandboxing for this run"),
    parallel: int = typer.Option(1, "--parallel", "-p", help="Number of parallel executions")
):
    """Run a module on one or more targets"""
    import json
    
    # Parse config
    config_dict = {}
    if config:
        try:
            config_dict = json.loads(config)
        except json.JSONDecodeError:
            console.print("[red]Invalid JSON for config[/red]")
            raise typer.Exit(1)
    
    # Get targets to run on
    if targets_list:
        target_values = targets_list
    elif all_targets:
        target_values = [t.value for t in targets.get_all()]
    elif tag:
        target_values = [t.value for t in targets.get_all(tags=[tag])]
    elif type:
        target_values = [t.value for t in targets.get_all(target_type=type)]
    else:
        console.print("[red]No targets specified. Use --all, --tag, --type, or provide target(s)[/red]")
        raise typer.Exit(1)
    
    if not target_values:
        console.print("[yellow]No targets match the specified criteria[/yellow]")
        return
    
    console.print(f"[blue]#[/blue] Running module '{module}' on {len(target_values)} targets")
    
    # Run module
    async def run_module():
        results = []
        
        if parallel > 1:
            # Run in parallel batches
            import asyncio
            
            semaphore = asyncio.Semaphore(parallel)
            
            async def run_single(target):
                async with semaphore:
                    return await modules.executor.execute(
                        module, target, config=config_dict, timeout=timeout
                    )
            
            tasks = [run_single(t) for t in target_values]
            results = await asyncio.gather(*tasks)
        else:
            # Run sequentially
            for target in target_values:
                result = await modules.executor.execute(
                    module, target, config=config_dict, timeout=timeout
                )
                results.append(result)
                
                # Print progress
                console.print(f"  [green]+[/green] Completed: {target}")
        
        return results
    
    # Execute async
    results = asyncio.run(run_module())
    
    # Display results
    success_count = sum(1 for r in results if r.status == "success")
    failure_count = sum(1 for r in results if r.status == "failed")
    partial_count = sum(1 for r in results if r.status == "partial")
    
    console.print(f"\n[green]+[/green] Completed: {success_count} success, {failure_count} failed, {partial_count} partial")
    
    # Show failures
    if failure_count > 0:
        console.print("\n[red]Failures:[/red]")
        for result in results:
            if result.status == "failed":
                console.print(f"  [red]-[/red] {result.target}: {result.error}")


@app.command()
def chain(
    modules_list: List[str],
    targets_list: Optional[List[str]] = typer.Argument(None, help="Target(s) to run the chain on"),
    all_targets: bool = typer.Option(False, "--all", "-a", help="Run on all targets in scope"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Chain configuration as JSON")
):
    """Run multiple modules in sequence (chaining)"""
    import json
    
    if not modules_list:
        console.print("[red]No modules specified for chaining[/red]")
        raise typer.Exit(1)
    
    # Parse config
    config_dict = {}
    if config:
        try:
            config_dict = json.loads(config)
        except json.JSONDecodeError:
            console.print("[red]Invalid JSON for config[/red]")
            raise typer.Exit(1)
    
    # Get targets
    if targets_list:
        target_values = targets_list
    elif all_targets:
        target_values = [t.value for t in targets.get_all()]
    else:
        console.print("[red]No targets specified. Use --all or provide target(s)[/red]")
        raise typer.Exit(1)
    
    if not target_values:
        console.print("[yellow]No targets match the specified criteria[/yellow]")
        return
    
    console.print(f"[blue]#[/blue] Running module chain on {len(target_values)} targets")
    
    # Run chain
    async def run_chain():
        all_results = {}
        
        for module_name in modules_list:
            console.print(f"\n[blue]#[/blue] Running module: {module_name}")
            
            module_results = []
            
            for target in target_values:
                result = await modules.executor.execute(
                    module_name, target, config=config_dict
                )
                module_results.append(result)
                console.print(f"  [green]+[/green] Completed: {target}")
            
            all_results[module_name] = module_results
        
        return all_results
    
    # Execute async
    results = asyncio.run(run_chain())
    
    # Display summary
    console.print("\n[green]+[/green] Chain completed")
    
    for module_name, module_results in results.items():
        success_count = sum(1 for r in module_results if r.status == "success")
        failure_count = sum(1 for r in module_results if r.status == "failed")
        console.print(f"  {module_name}: {success_count} success, {failure_count} failed")


@app.command()
def categories():
    """List all available module categories"""
    # Discover modules
    modules.discover_modules()
    
    # Get all categories
    categories = set()
    for module in modules.list_modules(show_disabled=True):
        categories.add(module.category)
    
    if not categories:
        console.print("[yellow]No module categories found[/yellow]")
        return
    
    table = Table(title="Module Categories", show_header=True, header_style="bold blue")
    table.add_column("Category", style="cyan")
    table.add_column("Module Count", style="green")
    
    for category in sorted(categories):
        count = len(modules.get_modules_by_category(category))
        table.add_row(category, str(count))
    
    console.print(table)
    console.print(f"[dim]Total categories: {len(categories)}[/dim]")


@app.command()
def discover():
    """Discover all available modules from all sources"""
    console.print("[blue]#[/blue] Discovering modules...")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        # Local modules
        task = progress.add_task("Discovering local modules...", total=None)
        local_modules = modules._discover_local_modules()
        progress.update(task, description=f"Found {len(local_modules)} local modules")
        
        # Package modules
        task = progress.add_task("Discovering package modules...", total=None)
        package_modules = modules._discover_package_modules()
        progress.update(task, description=f"Found {len(package_modules)} package modules")
        
        # Registry modules
        task = progress.add_task("Discovering registry modules...", total=None)
        registry_modules = modules._discover_registry_modules()
        progress.update(task, description=f"Found {len(registry_modules)} registry modules")
    
    total = len(local_modules) + len(package_modules) + len(registry_modules)
    console.print(f"\n[green]+[/green] Discovered {total} modules from all sources")


@app.command()
def stats():
    """Show module usage statistics"""
    # Get all results from storage
    all_results = storage.get_results_by_module("")
    
    if not all_results:
        console.print("[yellow]No module execution statistics available[/yellow]")
        return
    
    # Count by module
    module_stats = {}
    for result in all_results:
        module_name = result.module
        if module_name not in module_stats:
            module_stats[module_name] = {"success": 0, "failed": 0, "partial": 0, "total": 0}
        
        module_stats[module_name][result.status] += 1
        module_stats[module_name]["total"] += 1
    
    table = Table(title="Module Execution Statistics", show_header=True, header_style="bold blue")
    table.add_column("Module", style="green")
    table.add_column("Total Runs", style="cyan")
    table.add_column("Success", style="green")
    table.add_column("Failed", style="red")
    table.add_column("Partial", style="yellow")
    table.add_column("Success Rate", style="white")
    
    for module_name, stats in sorted(module_stats.items(), key=lambda x: (-x[1]["total"], x[0])):
        success_rate = (stats["success"] / stats["total"]) * 100 if stats["total"] > 0 else 0
        table.add_row(
            module_name,
            str(stats["total"]),
            str(stats["success"]),
            str(stats["failed"]),
            str(stats["partial"]),
            f"{success_rate:.1f}%"
        )
    
    console.print(table)
    console.print(f"[dim]Total module executions: {sum(s['total'] for s in module_stats.values())}[/dim]")
