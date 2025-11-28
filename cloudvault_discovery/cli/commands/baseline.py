"""
Baseline Command - Manage scan baselines and ignore patterns
cloudvault baseline [SUBCOMMAND] [OPTIONS]
"""

import click
from rich.console import Console
from typing import Optional
import json

console = Console()


@click.group()
def baseline():
    """
    Manage scan baselines for delta reporting.
    
    Create baseline snapshots, compare scans, and manage ignore patterns.
    """
    pass


@baseline.command()
@click.option('-i', '--input', 'input_file', required=True,
              type=click.Path(exists=True),
              help='JSON file with scan results')
@click.option('-o', '--output', default='.cloudvault-ignore',
              type=click.Path(),
              help='Baseline file path')
def create(input_file: str, output: str):
    """Create a baseline from scan results."""
    from ...baseline.manager import create_baseline
    
    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
        
        # Handle both formats
        if isinstance(data, dict) and 'findings' in data:
            findings = data['findings']
        elif isinstance(data, list):
            findings = data
        else:
            findings = []
        
        console.print(f"[cyan]Creating baseline from {len(findings)} findings...[/cyan]")
        
        create_baseline(findings, output)
        
        console.print(f"[bold green]✓[/bold green] Baseline created: {output}")
        console.print(f"[dim]Added {len(findings)} findings to baseline[/dim]")
        
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")
        raise click.Abort()


@baseline.command()
@click.option('-c', '--current', required=True,
              type=click.Path(exists=True),
              help='Current scan results (JSON)')
@click.option('-b', '--baseline', 'baseline_file',
              default='.cloudvault-ignore',
              type=click.Path(exists=True),
              help='Baseline file to compare against')
@click.option('-o', '--output', type=click.Path(),
              help='Save delta to file')
def diff(current: str, baseline_file: str, output: Optional[str]):
    """Compare current scan with baseline (show only new findings)."""
    from ...baseline.manager import compare_with_baseline
    
    try:
        with open(current, 'r') as f:
            current_findings = json.load(f)
        
        console.print(f"[cyan]Comparing with baseline...[/cyan]")
        
        new_findings = compare_with_baseline(current_findings, baseline_file)
        
        console.print(f"\n[bold]Delta Report:[/bold]")
        console.print(f"  Total findings: {len(current_findings)}")
        console.print(f"  New findings: [bold yellow]{len(new_findings)}[/bold yellow]")
        console.print(f"  Known findings: {len(current_findings) - len(new_findings)}")
        
        if new_findings:
            console.print("\n[bold yellow]New Findings:[/bold yellow]")
            for finding in new_findings[:10]:  # Show first 10
                console.print(f"  • {finding.get('title', 'Unknown')}")
            
            if len(new_findings) > 10:
                console.print(f"  ... and {len(new_findings) - 10} more")
        
        if output:
            with open(output, 'w') as f:
                json.dump(new_findings, f, indent=2)
            console.print(f"\n[green]✓[/green] New findings saved to: {output}")
        
    except FileNotFoundError as e:
        console.print(f"[bold red]✗ Error:[/bold red] File not found: {e.filename}")
        raise click.Abort()
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")
        raise click.Abort()


@baseline.command()
@click.option('-b', '--baseline', 'baseline_file',
              default='.cloudvault-ignore',
              type=click.Path(),
              help='Baseline file')
@click.argument('pattern')
def ignore(baseline_file: str, pattern: str):
    """Add an ignore pattern to baseline."""
    from ...baseline.manager import add_ignore_pattern
    
    try:
        add_ignore_pattern(baseline_file, pattern)
        console.print(f"[green]✓[/green] Added ignore pattern: {pattern}")
        
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")
        raise click.Abort()


__all__ = ['baseline']
