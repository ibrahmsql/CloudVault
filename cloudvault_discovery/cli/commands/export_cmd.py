"""
Export Command - Export findings in multiple formats
cloudvault export [OPTIONS]
"""

import click
from rich.console import Console
from typing import Optional
import json

console = Console()


@click.command(name='export')
@click.option('-i', '--input', 'input_file', required=True,
              type=click.Path(exists=True),
              help='JSON file with scan results')
@click.option('-f', '--format', 'export_format',
              type=click.Choice(['sarif', 'csv', 'json', 'html', 'tree'], 
                              case_sensitive=False),
              default='json',
              help='Export format')
@click.option('-o', '--output', required=True, type=click.Path(),
              help='Output file path')
@click.option('--pretty', is_flag=True,
              help='Pretty-print JSON output')
def export(input_file: str, export_format: str, output: str, pretty: bool):
    """
    Export findings in various formats (SARIF, CSV, JSON, HTML, Tree).
    
    Supports GitHub Security (SARIF), Excel/Sheets (CSV), CI/CD (JSON),
    and web reports (HTML).
    """
    try:
        # Load findings
        with open(input_file, 'r') as f:
            data = json.load(f)
        
        # Handle both formats: {"findings": [...]} and [...]
        if isinstance(data, dict) and 'findings' in data:
            findings = data['findings']
        elif isinstance(data, list):
            findings = data
        else:
            findings = []
        
        console.print(f"[cyan]Exporting {len(findings)} findings as {export_format.upper()}...[/cyan]")
        
        # Export based on format
        if export_format == 'sarif':
            from ...export.formats.sarif import export_sarif
            export_sarif(findings, output)
        elif export_format == 'csv':
            from ...export.formats.csv import export_csv
            export_csv(findings, output)
        elif export_format == 'json':
            from ...export.formats.json import export_json
            export_json(findings, output, pretty=pretty)
        elif export_format == 'html':
            from ...export.formats.html import export_html
            export_html(findings, output)
        elif export_format == 'tree':
            from ...export.formats.tree import export_tree
            export_tree(findings, output)
        
        console.print(f"[bold green]✓[/bold green] Exported to: {output}")
        
        # Format-specific tips
        if export_format == 'sarif':
            console.print("\n[dim]💡 Upload to GitHub Security:[/dim]")
            console.print("[dim]   Settings → Security → Code scanning alerts → Upload SARIF[/dim]")
        elif export_format == 'html':
            console.print(f"\n[dim]💡 View in browser:[/dim]")
            console.print(f"[dim]   open {output}[/dim]")
        
    except FileNotFoundError:
        console.print(f"[bold red]✗ Error:[/bold red] File not found: {input_file}")
        raise click.Abort()
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")
        console.print_exception()
        raise click.Abort()


__all__ = ['export']
