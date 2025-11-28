"""Compliance command - Framework mapping"""

import click
from rich.console import Console
import json

console = Console()


@click.command()
@click.option('-i', '--input-file', type=click.Path(exists=True), required=True)
@click.option('--framework',
              type=click.Choice(['CIS', 'PCI-DSS', 'HIPAA']),
              default='CIS',
              help='Compliance framework')
def compliance(input_file: str, framework: str):
    """Map findings to compliance frameworks"""
    from ...compliance.mapper import map_to_compliance, render_compliance_tree
    
    console.print(f"[bold cyan]{framework} Compliance Audit[/bold cyan]\n")
    
    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
        
        findings = data.get( 'findings', []) if isinstance(data, dict) else data
        
        # Map to compliance
        compliance_data = map_to_compliance(findings, framework)
        
        # Render tree
        tree_output = render_compliance_tree(compliance_data)
        console.print(tree_output)
        
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")


__all__ = ['compliance']
