#!/usr/bin/env python3
"""
CloudVault CLI - Click-based Command Line Interface
Modern, modular CLI with Heimdall-inspired features
"""

import click
from rich.console import Console

# Import commands
from .commands.scan import scan
from .commands.dashboard import dashboard
from .commands.tui import tui_command
from .commands.analyze import analyze
from .commands.export_cmd import export
from .commands.baseline import baseline
from .commands.test_alerts import test_alerts
from .commands.history import history
from .commands.remediate import remediate
from .commands.graph import graph
from .commands.compliance import compliance
from .commands.recon import recon

console = Console()


@click.group(invoke_without_command=True)
@click.option('--version', is_flag=True, help='Show version and exit')
@click.pass_context
def cli(ctx, version):
    """
    CloudVault - Multi-cloud storage bucket discovery and security scanner.
    
    Discover exposed AWS S3, Google Cloud Storage, and Azure Blob containers
    with advanced vulnerability detection and MITRE ATT&CK mapping.
    """
    if version:
        console.print("[bold cyan]CloudVault[/bold cyan] v1.0.1")
        console.print("Cloud security scanner with attack chain analysis")
        ctx.exit()
    
    # If no command specified, run scan (default behavior)
    if ctx.invoked_subcommand is None:
        ctx.invoke(scan)


# Add subcommands
cli.add_command(scan)
cli.add_command(dashboard)
cli.add_command(tui_command, name='tui')
cli.add_command(analyze)
cli.add_command(export, name='export')
cli.add_command(baseline)
cli.add_command(test_alerts, name='test-alerts')
cli.add_command(history)
cli.add_command(remediate)
cli.add_command(graph)
cli.add_command(compliance)
cli.add_command(recon)


# Config initialization helper
@cli.command()
def init_config():
    """Create a default configuration file."""
    from .config_helper import create_default_config
    
    try:
        if create_default_config():
            console.print("[bold green]✓[/bold green] Configuration file created: config.yaml")
            console.print("[dim]Edit the file to customize your settings[/dim]")
        else:
            console.print("[yellow]⚠[/yellow] Configuration file already exists")
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")
        raise click.Abort()


def main():
    """Main entry point for CloudVault CLI"""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[bold red]✗ Fatal error:[/bold red] {e}")
        raise


__all__ = ['main', 'cli']


if __name__ == "__main__":
    main()
