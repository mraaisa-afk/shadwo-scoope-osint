"""
Configuration Commands for SHADOWSCOPE CLI
"""

import typer
import json
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from pathlib import Path

from shadowscope.core import config, storage
from shadowscope.cli.app import console, app_state

app = typer.Typer(name="config", help="Configuration commands")


@app.command()
def show(
    section: Optional[str] = typer.Option(None, "--section", "-s", help="Show specific configuration section"),
    format: str = typer.Option("table", "--format", "-f", help="Output format (table, json)")
):
    """Show current configuration"""
    if format == "json":
        # Convert config to dictionary
        config_dict = {
            "api": {
                "shodan": config.api.shodan,
                "censys": config.api.censys,
                "zoomeye": config.api.zoomeye,
                "hunter": config.api.hunter,
                "clearbit": config.api.clearbit,
                "hibp": config.api.hibp,
                "virustotal": config.api.virustotal,
                "google_maps": config.api.google_maps,
                "twitter": config.api.twitter,
                "telegram": config.api.telegram,
                "tor": config.api.tor
            },
            "proxy": {
                "http": config.proxy.http,
                "https": config.proxy.https,
                "socks5": config.proxy.socks5,
                "tor": config.proxy.tor,
                "rotation": config.proxy.rotation,
                "user_agents": config.proxy.user_agents
            },
            "sandbox": {
                "enabled": config.sandbox.enabled,
                "backend": config.sandbox.backend,
                "timeout": config.sandbox.timeout,
                "cpu_limit": config.sandbox.cpu_limit,
                "memory_limit": config.sandbox.memory_limit,
                "network_restrictions": config.sandbox.network_restrictions,
                "blocked_domains": config.sandbox.blocked_domains
            },
            "storage": {
                "backend": config.storage.backend,
                "path": str(config.storage.path),
                "encryption": config.storage.encryption,
                "backup": config.storage.backup
            },
            "logging": {
                "level": config.logging.level,
                "file": str(config.logging.file),
                "sanitize": config.logging.sanitize,
                "encrypt": config.logging.encrypt,
                "max_size": config.logging.max_size,
                "max_files": config.logging.max_files
            },
            "performance": {
                "max_concurrency": config.performance.max_concurrency,
                "rate_limit": config.performance.rate_limit,
                "cache": config.performance.cache
            }
        }
        
        if section:
            if section in config_dict:
                console.print(json.dumps(config_dict[section], indent=2, default=str))
            else:
                console.print(f"[red]Section '{section}' not found[/red]")
                raise typer.Exit(1)
        else:
            console.print(json.dumps(config_dict, indent=2, default=str))
    else:
        if section:
            # Show specific section
            if section == "api":
                show_api_config()
            elif section == "proxy":
                show_proxy_config()
            elif section == "sandbox":
                show_sandbox_config()
            elif section == "storage":
                show_storage_config()
            elif section == "logging":
                show_logging_config()
            elif section == "performance":
                show_performance_config()
            else:
                console.print(f"[red]Unknown section: {section}[/red]")
                raise typer.Exit(1)
        else:
            # Show all sections
            show_api_config()
            console.print()
            show_proxy_config()
            console.print()
            show_sandbox_config()
            console.print()
            show_storage_config()
            console.print()
            show_logging_config()
            console.print()
            show_performance_config()


def show_api_config():
    """Show API configuration"""
    table = Table(title="API Configuration", show_header=True, header_style="bold blue")
    table.add_column("Service", style="cyan")
    table.add_column("Enabled", style="green")
    table.add_column("API Key", style="dim")
    
    api_services = [
        ("Shodan", config.api.shodan.get("enabled", False), config.api.shodan.get("api_key", "")),
        ("Censys", config.api.censys.get("enabled", False), config.api.censys.get("api_id", "")),
        ("ZoomEye", config.api.zoomeye.get("enabled", False), config.api.zoomeye.get("api_key", "")),
        ("Hunter.io", config.api.hunter.get("enabled", False), config.api.hunter.get("api_key", "")),
        ("Clearbit", config.api.clearbit.get("enabled", False), config.api.clearbit.get("api_key", "")),
        ("HIBP", config.api.hibp.get("enabled", False), config.api.hibp.get("api_key", "")),
        ("VirusTotal", config.api.virustotal.get("enabled", False), config.api.virustotal.get("api_key", "")),
        ("Google Maps", config.api.google_maps.get("enabled", False), config.api.google_maps.get("api_key", "")),
        ("Twitter", config.api.twitter.get("enabled", False), config.api.twitter.get("api_key", "")),
        ("Telegram", config.api.telegram.get("enabled", False), config.api.telegram.get("api_id", "")),
        ("Tor", config.api.tor.get("enabled", False), config.api.tor.get("control_port", ""))
    ]
    
    for service, enabled, api_key in api_services:
        enabled_str = "[green]Yes[/green]" if enabled else "[red]No[/red]"
        api_key_display = "***" if api_key and len(api_key) > 3 else api_key
        table.add_row(service, enabled_str, api_key_display)
    
    console.print(table)


def show_proxy_config():
    """Show proxy configuration"""
    table = Table(title="Proxy Configuration", show_header=True, header_style="bold blue")
    table.add_column("Type", style="cyan")
    table.add_column("Count", style="green")
    table.add_column("Rotation", style="yellow")
    
    table.add_row("HTTP", str(len(config.proxy.http)))
    table.add_row("HTTPS", str(len(config.proxy.https)))
    table.add_row("SOCKS5", str(len(config.proxy.socks5)))
    
    rotation_enabled = config.proxy.rotation.get("enabled", False)
    rotation_interval = config.proxy.rotation.get("interval", 60)
    rotation_str = f"[green]Enabled[/green] ({rotation_interval}s)" if rotation_enabled else "[red]Disabled[/red]"
    table.add_row("Rotation", "", rotation_str)
    
    tor_enabled = config.proxy.tor.get("enabled", False)
    tor_port = config.proxy.tor.get("port", 9050)
    tor_str = f"[green]Enabled[/green] (port {tor_port})" if tor_enabled else "[red]Disabled[/red]"
    table.add_row("Tor", "", tor_str)
    
    console.print(table)


def show_sandbox_config():
    """Show sandbox configuration"""
    table = Table(title="Sandbox Configuration", show_header=True, header_style="bold blue")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Enabled", "[green]Yes[/green]" if config.sandbox.enabled else "[red]No[/red]")
    table.add_row("Backend", config.sandbox.backend)
    table.add_row("Timeout", f"{config.sandbox.timeout} seconds")
    table.add_row("CPU Limit", config.sandbox.cpu_limit)
    table.add_row("Memory Limit", config.sandbox.memory_limit)
    table.add_row("Network Restrictions", ", ".join(config.sandbox.network_restrictions))
    table.add_row("Blocked Domains", ", ".join(config.sandbox.blocked_domains))
    
    console.print(table)


def show_storage_config():
    """Show storage configuration"""
    table = Table(title="Storage Configuration", show_header=True, header_style="bold blue")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Backend", config.storage.backend)
    table.add_row("Path", str(config.storage.path))
    
    encryption_enabled = config.storage.encryption.get("enabled", True)
    table.add_row("Encryption", "[green]Enabled[/green]" if encryption_enabled else "[red]Disabled[/red]")
    table.add_row("Algorithm", config.storage.encryption.get("algorithm", "aes-256-cbc"))
    
    backup_enabled = config.storage.backup.get("enabled", True)
    backup_interval = config.storage.backup.get("interval", "24h")
    backup_retention = config.storage.backup.get("retention", 7)
    backup_str = f"[green]Enabled[/green] ({backup_interval}, {backup_retention} days)" if backup_enabled else "[red]Disabled[/red]"
    table.add_row("Backup", backup_str)
    
    console.print(table)


def show_logging_config():
    """Show logging configuration"""
    table = Table(title="Logging Configuration", show_header=True, header_style="bold blue")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Level", config.logging.level)
    table.add_row("File", str(config.logging.file))
    table.add_row("Sanitize", "[green]Yes[/green]" if config.logging.sanitize else "[red]No[/red]")
    table.add_row("Encrypt", "[green]Yes[/green]" if config.logging.encrypt else "[red]No[/red]")
    table.add_row("Max Size", f"{config.logging.max_size} MB")
    table.add_row("Max Files", str(config.logging.max_files))
    
    console.print(table)


def show_performance_config():
    """Show performance configuration"""
    table = Table(title="Performance Configuration", show_header=True, header_style="bold blue")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Max Concurrency", str(config.performance.max_concurrency))
    
    rate_limit_enabled = config.performance.rate_limit.get("enabled", True)
    rate_limit_rps = config.performance.rate_limit.get("requests_per_second", 5)
    rate_limit_burst = config.performance.rate_limit.get("burst_size", 20)
    rate_limit_str = f"[green]Enabled[/green] ({rate_limit_rps} req/s, burst {rate_limit_burst})" if rate_limit_enabled else "[red]Disabled[/red]"
    table.add_row("Rate Limit", rate_limit_str)
    
    cache_enabled = config.performance.cache.get("enabled", True)
    cache_backend = config.performance.cache.get("backend", "diskcache")
    cache_ttl = config.performance.cache.get("ttl", 3600)
    cache_str = f"[green]Enabled[/green] ({cache_backend}, TTL {cache_ttl}s)" if cache_enabled else "[red]Disabled[/red]"
    table.add_row("Cache", cache_str)
    
    console.print(table)


@app.command()
def set(
    section: str,
    key: str,
    value: str,
    save: bool = typer.Option(True, "--save", "-s", help="Save changes to config file")
):
    """Set a configuration value"""
    # This is a simplified version - in practice, you'd need to handle nested sections
    try:
        # Try to set API key
        if section == "api":
            config.set_api_key(key, value)
            console.print(f"[green]+[/green] Set API key for {key}")
        else:
            console.print(f"[yellow]Setting arbitrary config values not yet implemented[/yellow]")
            console.print(f"  Use 'shadowscope config set api {key} {value}' for API keys")
    except Exception as e:
        console.print(f"[red]Error setting config: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def set_api_key(
    service: str,
    key: str,
    save: bool = typer.Option(True, "--save", "-s", help="Save changes to config file")
):
    """Set an API key for a service"""
    config.set_api_key(service, key)
    console.print(f"[green]+[/green] Set API key for {service}")


@app.command()
def enable(
    section: str,
    key: str
):
    """Enable a configuration option"""
    try:
        if section == "api":
            # Enable API service
            if hasattr(config.api, key):
                api_config = getattr(config.api, key)
                if isinstance(api_config, dict):
                    api_config["enabled"] = True
                    config.save()
                    console.print(f"[green]+[/green] Enabled {key} API")
                else:
                    console.print(f"[red]Invalid API service: {key}[/red]")
                    raise typer.Exit(1)
        elif section == "proxy":
            if key == "rotation":
                config.proxy.rotation["enabled"] = True
                config.save()
                console.print("[green]+[/green] Enabled proxy rotation")
            elif key == "tor":
                config.proxy.tor["enabled"] = True
                config.save()
                console.print("[green]+[/green] Enabled Tor")
            else:
                console.print(f"[red]Invalid proxy option: {key}[/red]")
                raise typer.Exit(1)
        elif section == "sandbox":
            if key == "enabled":
                config.sandbox.enabled = True
                config.save()
                console.print("[green]+[/green] Enabled sandbox")
            else:
                console.print(f"[red]Invalid sandbox option: {key}[/red]")
                raise typer.Exit(1)
        else:
            console.print(f"[red]Invalid section: {section}[/red]")
            raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error enabling config: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def disable(
    section: str,
    key: str
):
    """Disable a configuration option"""
    try:
        if section == "api":
            # Disable API service
            if hasattr(config.api, key):
                api_config = getattr(config.api, key)
                if isinstance(api_config, dict):
                    api_config["enabled"] = False
                    config.save()
                    console.print(f"[yellow]-[/yellow] Disabled {key} API")
                else:
                    console.print(f"[red]Invalid API service: {key}[/red]")
                    raise typer.Exit(1)
        elif section == "proxy":
            if key == "rotation":
                config.proxy.rotation["enabled"] = False
                config.save()
                console.print("[yellow]-[/yellow] Disabled proxy rotation")
            elif key == "tor":
                config.proxy.tor["enabled"] = False
                config.save()
                console.print("[yellow]-[/yellow] Disabled Tor")
            else:
                console.print(f"[red]Invalid proxy option: {key}[/red]")
                raise typer.Exit(1)
        elif section == "sandbox":
            if key == "enabled":
                config.sandbox.enabled = False
                config.save()
                console.print("[yellow]-[/yellow] Disabled sandbox")
            else:
                console.print(f"[red]Invalid sandbox option: {key}[/red]")
                raise typer.Exit(1)
        else:
            console.print(f"[red]Invalid section: {section}[/red]")
            raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error disabling config: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def save():
    """Save current configuration to file"""
    try:
        config.save()
        console.print("[green]+[/green] Configuration saved")
    except Exception as e:
        console.print(f"[red]Error saving configuration: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def edit():
    """Edit configuration in default editor"""
    import subprocess
    import os
    
    config_path = config._config_path
    
    if not config_path.exists():
        console.print("[red]Configuration file not found[/red]")
        raise typer.Exit(1)
    
    # Get editor from environment or use default
    editor = os.environ.get("EDITOR", "nano")
    
    try:
        subprocess.run([editor, str(config_path)], check=True)
        console.print("[green]+[/green] Configuration file edited")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Error editing configuration: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def init():
    """Initialize configuration with interactive setup"""
    console.print("[blue]#[/blue] Initializing SHADOWSCOPE configuration")
    console.print()
    
    # API keys
    console.print("[bold]API Configuration[/bold]")
    
    services = ["shodan", "censys", "zoomeye", "hunter", "clearbit", "hibp", "virustotal", "google_maps"]
    
    for service in services:
        api_key = typer.prompt(f"  {service.capitalize()} API Key (leave empty to skip)", default="")
        if api_key:
            config.set_api_key(service, api_key)
    
    # Proxy configuration
    console.print("\n[bold]Proxy Configuration[/bold]")
    
    http_proxies = typer.prompt("  HTTP proxies (comma-separated, leave empty to skip)", default="")
    if http_proxies:
        config.proxy.http = [p.strip() for p in http_proxies.split(",") if p.strip()]
    
    https_proxies = typer.prompt("  HTTPS proxies (comma-separated, leave empty to skip)", default="")
    if https_proxies:
        config.proxy.https = [p.strip() for p in https_proxies.split(",") if p.strip()]
    
    socks5_proxies = typer.prompt("  SOCKS5 proxies (comma-separated, leave empty to skip)", default="")
    if socks5_proxies:
        config.proxy.socks5 = [p.strip() for p in socks5_proxies.split(",") if p.strip()]
    
    # Tor configuration
    use_tor = typer.confirm("  Use Tor for anonymity?")
    if use_tor:
        config.proxy.tor["enabled"] = True
        tor_port = typer.prompt("    Tor port", default="9050")
        config.proxy.tor["port"] = int(tor_port)
    
    # Save configuration
    config.save()
    console.print("\n[green]+[/green] Configuration initialized and saved")


@app.command()
def check():
    """Check configuration for issues"""
    issues = []
    
    # Check API keys
    if config.api.shodan.get("api_key", ""):
        console.print("[green]+[/green] Shodan API key configured")
    else:
        issues.append("Shodan API key not configured")
    
    if config.api.censys.get("api_id", "") and config.api.censys.get("api_secret", ""):
        console.print("[green]+[/green] Censys API keys configured")
    else:
        issues.append("Censys API keys not configured")
    
    # Check proxies
    proxy_count = len(config.proxy.http) + len(config.proxy.https) + len(config.proxy.socks5)
    if proxy_count > 0:
        console.print(f"[green]+[/green] {proxy_count} proxies configured")
    else:
        issues.append("No proxies configured")
    
    # Check Tor
    if config.proxy.tor.get("enabled", False):
        console.print("[green]+[/green] Tor enabled")
    
    # Check sandbox
    if config.sandbox.enabled:
        console.print("[green]+[/green] Sandbox enabled")
    else:
        issues.append("Sandbox disabled")
    
    # Check storage
    if config.storage.path:
        console.print("[green]+[/green] Storage configured")
    
    if issues:
        console.print("\n[red]Issues found:[/red]")
        for issue in issues:
            console.print(f"  - {issue}")
    else:
        console.print("\n[green]+[/green] Configuration looks good!")
