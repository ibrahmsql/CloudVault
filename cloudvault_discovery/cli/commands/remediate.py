"""Remediate command - Auto-remediation suggestions"""

import click
from rich.console import Console
import json

console = Console()


@click.command()
@click.option('-i', '--input-file', type=click.Path(exists=True), required=True,
              help='Input findings file')
@click.option('-f', '--format', 
              type=click.Choice(['terraform', 'awscli', 'policy']),
              default='terraform',
              help='Remediation format')
@click.option('--dry-run', is_flag=True,
              help='Show remediation without executing')
def remediate(input_file: str, format: str, dry_run: bool):
    """Generate auto-remediation scripts"""
    from ...remediation.generator import generate_remediation_tree
    
    console.print("[bold cyan]CloudVault Auto-Remediation[/bold cyan]\n")
    
    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
        
        findings = data.get('findings', []) if isinstance(data, dict) else data
        
        if not findings:
            console.print("[yellow]No findings to remediate[/yellow]")
            return
        
        # Generate remediation tree
        tree_output = generate_remediation_tree(findings, format)
        console.print(tree_output)
        
        if dry_run:
            console.print("\n[yellow]🔒 Dry-run mode - No changes applied[/yellow]")
        
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")


__all__ = ['remediate']
