"""
TUI Command - Launch interactive terminal UI
cloudvault tui [OPTIONS]
"""

import click
from rich.console import Console

console = Console()


@click.command(name='tui')
@click.option('-i', '--input', 'input_file', type=click.Path(exists=True),
              help='JSON file with scan results to display')
def tui_command(input_file: str = None):
    """
    Launch interactive Terminal User Interface (TUI).
    
    Provides a full-screen interactive interface for exploring scan results,
    viewing attack chains, and managing findings.
    """
    try:
        from ...tui.app import CloudVaultTUI
        
        console.print("[bold cyan]Launching CloudVault TUI...[/bold cyan]")
        
        # Create and run TUI app
        app = CloudVaultTUI(input_file=input_file)
        app.run()
        
    except ImportError as e:
        console.print(f"[bold red]✗ Error:[/bold red] TUI dependencies not installed")
        console.print("Install with: [cyan]pip install cloudvault4[full][/cyan]")
        raise click.Abort()
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")
        console.print_exception()
        raise click.Abort()


__all__ = ['tui_command']
