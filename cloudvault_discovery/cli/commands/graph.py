"""Graph command - Trust graph visualization"""

import click
from rich.console import Console
import json

console = Console()


@click.command()
@click.option('-i', '--input-file', type=click.Path(exists=True), required=True)
def graph(input_file: str):
    """Visualize trust relationships"""
    from ...graph.renderer import render_graph_tree
    
    console.print("[bold cyan]Trust Graph[/bold cyan]\n")
    
    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
        
        findings = data.get('findings', []) if isinstance(data, dict) else data
        
        tree_output = render_graph_tree(findings)
        console.print(tree_output)
        
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")


__all__ = ['graph']
