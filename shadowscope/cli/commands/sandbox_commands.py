"""
Sandbox Management Commands for SHADOWSCOPE CLI
"""

import typer
from typing import Optional, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from shadowscope.core import sandbox, config
from shadowscope.cli.app import console, app_state

app = typer.Typer(name="sandbox", help="Sandbox management commands")


@app.command()
def status():
    """Show sandbox status"""
    sb = sandbox.get_sandbox()
    
    table = Table(title="Sandbox Status", show_header=True)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("Backend", sb.config.backend)
    table.add_row("Docker Available", "[green]Yes[/green]" if sb._docker_available else "[red]No[/red]")
    table.add_row("Timeout", f"{sb.config.timeout}s")
    table.add_row("CPU Limit", sb.config.cpu_limit)
    table.add_row("Memory Limit", sb.config.memory_limit)
    table.add_row("Temp Directory", sb.config.temp_dir)
    table.add_row("Read-Only", "[green]Yes[/green]" if sb.config.read_only else "[red]No[/red]")
    
    console.print(table)
    
    if sb.config.network_restrictions:
        console.print("\n[bold]Network Restrictions:[/bold]")
        for restriction in sb.config.network_restrictions:
            console.print(f"  - {restriction}")


@app.command()
def backend(
    name: str = typer.Argument(..., help="Backend to use (docker, gvisor, firejail)")
):
    """Set sandbox backend"""
    valid_backends = ["docker", "gvisor", "firejail"]
    if name not in valid_backends:
        console.print(f"[red]Invalid backend. Choose from: {', '.join(valid_backends)}[/red]")
        raise typer.Exit(1)
    
    sandbox.set_backend(name)
    console.print(f"[green]+[/green] Sandbox backend set to: {name}")


@app.command()
def config(
    timeout: Optional[int] = typer.Option(None, "--timeout", "-t", help="Execution timeout in seconds"),
    cpu: Optional[str] = typer.Option(None, "--cpu", help="CPU limit (e.g., '1.0', '0.5')"),
    memory: Optional[str] = typer.Option(None, "--memory", "-m", help="Memory limit (e.g., '512m', '1g')"),
    temp_dir: Optional[str] = typer.Option(None, "--temp-dir", help="Temporary directory path"),
    read_only: Optional[bool] = typer.Option(None, "--read-only/--read-write", help="Enable read-only filesystem")
):
    """Configure sandbox settings"""
    sb = sandbox.get_sandbox()
    
    if timeout is not None:
        sb.config.timeout = timeout
    if cpu is not None:
        sb.config.cpu_limit = cpu
    if memory is not None:
        sb.config.memory_limit = memory
    if temp_dir is not None:
        sb.config.temp_dir = temp_dir
    if read_only is not None:
        sb.config.read_only = read_only
    
    sandbox.set_config(sb.config)
    console.print("[green]+[/green] Sandbox configuration updated")


@app.command()
def restrictions(
    add: Optional[List[str]] = typer.Option(None, "--add", "-a", help="Add network restriction (CIDR)"),
    remove: Optional[List[str]] = typer.Option(None, "--remove", "-r", help="Remove network restriction"),
    list: bool = typer.Option(False, "--list", "-l", help="List current restrictions"),
    clear: bool = typer.Option(False, "--clear", help="Clear all restrictions")
):
    """Manage network restrictions"""
    sb = sandbox.get_sandbox()
    
    if clear:
        sb.config.network_restrictions = []
        sandbox.set_config(sb.config)
        console.print("[green]+[/green] All network restrictions cleared")
        return
    
    if list:
        console.print("[bold]Network Restrictions:[/bold]")
        for restriction in sb.config.network_restrictions:
            console.print(f"  - {restriction}")
        return
    
    if add:
        sb.config.network_restrictions.extend(add)
        sandbox.set_config(sb.config)
        console.print(f"[green]+[/green] Added {len(add)} network restrictions")
    
    if remove:
        for r in remove:
            if r in sb.config.network_restrictions:
                sb.config.network_restrictions.remove(r)
        sandbox.set_config(sb.config)
        console.print(f"[green]+[/green] Removed {len(remove)} network restrictions")


@app.command()
def blocked(
    add: Optional[List[str]] = typer.Option(None, "--add", "-a", help="Add blocked domain"),
    remove: Optional[List[str]] = typer.Option(None, "--remove", "-r", help="Remove blocked domain"),
    list: bool = typer.Option(False, "--list", "-l", help="List blocked domains"),
    clear: bool = typer.Option(False, "--clear", help="Clear all blocked domains")
):
    """Manage blocked domains"""
    sb = sandbox.get_sandbox()
    
    if clear:
        sb.config.blocked_domains = []
        sandbox.set_config(sb.config)
        console.print("[green]+[/green] All blocked domains cleared")
        return
    
    if list:
        console.print("[bold]Blocked Domains:[/bold]")
        for domain in sb.config.blocked_domains:
            console.print(f"  - {domain}")
        return
    
    if add:
        sb.config.blocked_domains.extend(add)
        sandbox.set_config(sb.config)
        console.print(f"[green]+[/green] Added {len(add)} blocked domains")
    
    if remove:
        for d in remove:
            if d in sb.config.blocked_domains:
                sb.config.blocked_domains.remove(d)
        sandbox.set_config(sb.config)
        console.print(f"[green]+[/green] Removed {len(remove)} blocked domains")


@app.command()
def test(
    module: Optional[str] = typer.Option(None, "--module", "-m", help="Test with specific module"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Test target")
):
    """Test sandbox execution"""
    import asyncio
    
    async def run_test():
        sb = sandbox.get_sandbox()
        
        if module and target:
            result = await sb.execute(module, target)
            console.print(f"[bold]Test Result:[/bold]")
            console.print(f"  Return Code: {result.returncode}")
            console.print(f"  Execution Time: {result.execution_time:.2f}s")
            if result.stdout:
                console.print(f"  [green]Stdout:[/green]\n{result.stdout[:200]}")
            if result.stderr:
                console.print(f"  [red]Stderr:[/red]\n{result.stderr[:200]}")
        else:
            # Simple test
            result = await sb.execute("test", "echo 'Sandbox test'")
            console.print(f"[green]+[/green] Sandbox test completed in {result.execution_time:.2f}s")
    
    asyncio.run(run_test())


@app.command()
def containers(
    list: bool = typer.Option(False, "--list", "-l", help="List running containers"),
    clean: bool = typer.Option(False, "--clean", "-c", help="Clean up all containers"),
    force: bool = typer.Option(False, "--force", "-f", help="Force cleanup")
):
    """Manage sandbox containers"""
    sb = sandbox.get_sandbox()
    
    if list:
        containers = sb.list_containers()
        if containers:
            table = Table(title="Running Containers", show_header=True)
            table.add_column("ID", style="cyan")
            table.add_column("Name", style="white")
            table.add_column("Status", style="green")
            
            for c in containers:
                table.add_row(c["id"][:12], c.get("name", "N/A"), c.get("status", "running"))
            console.print(table)
        else:
            console.print("No running containers")
    
    if clean:
        count = sb.cleanup_containers(force=force)
        console.print(f"[green]+[/green] Cleaned up {count} containers")


@app.command()
def logs(
    module: Optional[str] = typer.Option(None, "--module", "-m", help="Show logs for module"),
    clear: bool = typer.Option(False, "--clear", "-c", help="Clear logs")
):
    """View sandbox logs"""
    sb = sandbox.get_sandbox()
    
    if clear:
        sb.clear_logs()
        console.print("[green]+[/green] Sandbox logs cleared")
        return
    
    logs = sb.get_logs(module=module)
    if logs:
        console.print("[bold]Sandbox Logs:[/bold]")
        for log in logs:
            console.print(f"  [{log['level']}] {log['message']}")
    else:
        console.print("No logs found")


@app.command()
def reset():
    """Reset sandbox to default configuration"""
    sandbox.reset_config()
    console.print("[yellow]![/yellow] Sandbox configuration reset to defaults")
