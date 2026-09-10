"""
Proxy Management Commands for SHADOWSCOPE CLI
"""

import typer
from typing import Optional, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from shadowscope.core import proxy, config
from shadowscope.cli.app import console, app_state

app = typer.Typer(name="proxy", help="Proxy management commands")


@app.command()
def list(
    all: bool = typer.Option(False, "--all", "-a", help="Show all proxies including disabled"),
    format: str = typer.Option("table", "--format", "-f", help="Output format (table, json)")
):
    """List configured proxies"""
    import json
    
    proxies_list = proxy.list_proxies(include_disabled=all)
    
    if format == "json":
        data = [p.to_dict() for p in proxies_list]
        console.print(json.dumps(data, indent=2, default=str))
        return
    
    table = Table(title="Proxy Pool", show_header=True, header_style="bold cyan")
    table.add_column("#", style="dim")
    table.add_column("URL", style="green")
    table.add_column("Protocol", style="blue")
    table.add_column("Location", style="white")
    table.add_column("Status", style="")
    table.add_column("Success/Fail", style="")
    
    for i, p in enumerate(proxies_list, 1):
        status = "[green]active[/green]" if p.success_count > 0 else "[yellow]untested[/yellow]"
        if p.failure_count > p.success_count * 2:
            status = "[red]disabled[/red]"
        
        table.add_row(
            str(i),
            p.url,
            p.protocol,
            p.location or "N/A",
            status,
            f"{p.success_count}/{p.failure_count}"
        )
    
    console.print(table)
    console.print(f"\nTotal: {len(proxies_list)} proxies")


@app.command()
def add(
    url: str,
    protocol: str = typer.Option("http", "--protocol", "-p", help="Proxy protocol (http, https, socks5)"),
    username: Optional[str] = typer.Option(None, "--username", "-u", help="Proxy username"),
    password: Optional[str] = typer.Option(None, "--password", "-P", help="Proxy password"),
    location: Optional[str] = typer.Option(None, "--location", "-l", help="Proxy location"),
    test: bool = typer.Option(True, "--test", "-t", help="Test proxy after adding")
):
    """Add a new proxy to the pool"""
    proxy_config = proxy.add_proxy(url, protocol, username, password, location)
    
    if test:
        result = proxy.test_proxy(proxy_config)
        if result:
            console.print(f"[green]+[/green] Added and verified proxy: {proxy_config.url}")
        else:
            console.print(f"[yellow]+[/yellow] Added proxy (verification failed): {proxy_config.url}")
    else:
        console.print(f"[green]+[/green] Added proxy: {proxy_config.url}")


@app.command()
def remove(
    url: str,
    all: bool = typer.Option(False, "--all", "-a", help="Remove all proxies")
):
    """Remove a proxy from the pool"""
    if all:
        count = proxy.remove_all_proxies()
        console.print(f"[red]-[/red] Removed {count} proxies")
    else:
        success = proxy.remove_proxy(url)
        if success:
            console.print(f"[red]-[/red] Removed proxy: {url}")
        else:
            console.print(f"[yellow]![/yellow] Proxy not found: {url}")


@app.command()
def test(
    url: Optional[str] = typer.Option(None, "--url", "-u", help="Test specific proxy"),
    all: bool = typer.Option(False, "--all", "-a", help="Test all proxies")
):
    """Test proxy connectivity"""
    if all:
        results = proxy.test_all_proxies()
        table = Table(title="Proxy Test Results", show_header=True)
        table.add_column("URL", style="green")
        table.add_column("Status", style="")
        table.add_column("Response Time", style="blue")
        
        for url, result in results.items():
            status = "[green]OK[/green]" if result["success"] else "[red]FAILED[/red]"
            table.add_row(url, status, f"{result['time']:.2f}s")
        
        console.print(table)
    else:
        if not url:
            console.print("[yellow]Specify --url or --all[/yellow]")
            return
        
        result = proxy.test_proxy_url(url)
        if result:
            console.print(f"[green]+[/green] Proxy {url} is working ({result['time']:.2f}s)")
        else:
            console.print(f"[red]-[/red] Proxy {url} failed")


@app.command()
def rotate(
    enable: bool = typer.Option(True, "--enable", help="Enable proxy rotation"),
    interval: int = typer.Option(10, "--interval", "-i", help="Requests between rotation")
):
    """Configure proxy rotation"""
    proxy.set_rotation(enable, interval)
    status = "[green]enabled[/green]" if enable else "[red]disabled[/red]"
    console.print(f"Proxy rotation {status} (interval: {interval} requests)")


@app.command()
def stats():
    """Show proxy usage statistics"""
    stats = proxy.get_stats()
    
    table = Table(title="Proxy Statistics", show_header=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("Total Requests", str(stats.total_requests))
    table.add_row("Successful", f"[green]{stats.successful_requests}[/green]")
    table.add_row("Failed", f"[red]{stats.failed_requests}[/red]")
    table.add_row("Working Proxies", str(stats.working_proxies))
    table.add_row("Avg Response Time", f"{stats.avg_response_time:.2f}s")
    
    console.print(table)


@app.command()
def tor(
    enable: bool = typer.Option(True, "--enable", help="Enable Tor routing"),
    port: int = typer.Option(9050, "--port", "-p", help="Tor SOCKS5 port"),
    control_port: int = typer.Option(9051, "--control-port", help="Tor control port")
):
    """Configure Tor integration"""
    proxy.set_tor(enable, port, control_port)
    status = "[green]enabled[/green]" if enable else "[red]disabled[/red]"
    console.print(f"Tor routing {status} (SOCKS5://127.0.0.1:{port})")


@app.command()
def ua(
    list: bool = typer.Option(False, "--list", "-l", help="List user agents"),
    add: Optional[str] = typer.Option(None, "--add", "-a", help="Add custom user agent"),
    remove: Optional[str] = typer.Option(None, "--remove", "-r", help="Remove user agent")
):
    """Manage user agent spoofing"""
    ua_manager = proxy.UserAgentManager()
    
    if list:
        uas = ua_manager.list_user_agents()
        for ua in uas:
            console.print(f"  {ua}")
        console.print(f"\nTotal: {len(uas)} user agents")
    elif add:
        ua_manager.add_user_agent(add)
        console.print(f"[green]+[/green] Added user agent")
    elif remove:
        ua_manager.remove_user_agent(remove)
        console.print(f"[red]-[/red] Removed user agent")
    else:
        current = ua_manager.get_random()
        console.print(f"Current random UA: {current}")


@app.command()
def clear():
    """Clear all proxy statistics"""
    proxy.clear_stats()
    console.print("[yellow]![/yellow] Proxy statistics cleared")
