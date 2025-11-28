"""
History Command
View scan history and trends
"""

import click
from rich.console import Console
import asyncio

console = Console()


@click.group()
def history():
    """Scan history and trend analysis"""
    pass


@history.command()
@click.option('--limit', '-n', default=10, type=int,
              help='Number of scans to show')
def list(limit: int):
    """List scan history"""
    from ...history import get_scan_history, render_history_tree
    
    console.print("[bold cyan]CloudVault Scan History[/bold cyan]\n")
    
    try:
        scans = asyncio.run(get_scan_history(limit))
        
        if not scans:
            console.print("[yellow]No scan history found[/yellow]")
            console.print("Run scans with [cyan]--save-history[/cyan] to track results")
            return
        
        tree_output = render_history_tree(scans)
        console.print(tree_output)
        
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")


@history.command()
@click.option('--days', '-d', default=30, type=int,
              help='Number of days to analyze')
def trends(days: int):
    """Show security trends over time"""
    from ...history import get_trends, visualize_trends
    
    console.print(f"[bold cyan]Security Trends (Last {days} Days)[/bold cyan]\n")
    
    try:
        trends_data = asyncio.run(get_trends(days))
        
        if not trends_data:
            console.print("[yellow]No trend data available[/yellow]")
            return
        
        tree_output = visualize_trends(trends_data, days)
        console.print(tree_output)
        
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")


@history.command()
@click.option('--from-scan', type=int, required=True,
              help='First scan ID')
@click.option('--to-scan', type=int, required=True,
              help='Second scan ID')
def compare(from_scan: int, to_scan: int):
    """Compare two scans"""
    from ...history import compare_scans
    
    console.print(f"[bold cyan]Comparing Scans #{from_scan} vs #{to_scan}[/bold cyan]\n")
    
    try:
        delta = asyncio.run(compare_scans(from_scan, to_scan))
        
        console.print(f"📊 New findings: {len(delta.get('new_findings', []))}")
        console.print(f"✓ Fixed findings: {len(delta.get('fixed_findings', []))}")
        console.print(f"═ Common findings: {len(delta.get('common_findings', []))}")
        
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")


__all__ = ['history']
