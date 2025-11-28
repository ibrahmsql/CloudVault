"""
Analyze Command - Attack chain analysis and MITRE ATT&CK mapping
cloudvault analyze [OPTIONS]
"""

import click
from rich.console import Console
from rich.tree import Tree
from typing import Optional
import json

console = Console()


@click.command()
@click.option('-i', '--input', 'input_file', required=True,
              type=click.Path(exists=True),
              help='JSON file with scan results')
@click.option('-f', '--format', 'output_format',
              type=click.Choice(['tree', 'json', 'table'], case_sensitive=False),
              default='tree',
              help='Output format')
@click.option('-o', '--output', type=click.Path(),
              help='Output file (default: stdout)')
@click.option('--show-mitre', is_flag=True,
              help='Show MITRE ATT&CK techniques')
@click.option('--min-blast-radius', type=float,
              help='Minimum blast radius score')
@click.option('--filter', 'filter_str',
              help='Filter findings before analysis')
@click.option('--exclude', 'exclude_str',
              help='Exclude findings')
def analyze(input_file: str, output_format: str, output: Optional[str], show_mitre: bool,
            min_blast_radius: Optional[float], filter_str: Optional[str], exclude_str: Optional[str]):
    """Analyze attack chains and privilege escalation paths."""
    from ...analysis.chain_builder import build_attack_chains
    from ...analysis.mitre_mapper import get_mitre_technique
    from rich.tree import Tree
    from rich.table import Table
    from ...filtering import apply_filters
    
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
        
        # Apply filters
        if filter_str or exclude_str:
            findings = apply_filters(findings, filter_str, exclude_str)
            console.print(f"[cyan]Applied filters:[/cyan] {len(findings)} findings")
        
        if not findings:
            console.print("[yellow]⚠ No findings to analyze[/yellow]")
            return
        
        console.print(f"[cyan]Analyzing {len(findings)} findings...[/cyan]")
        
        # Build attack chains
        attack_chains = build_attack_chains(findings)
        console.print(f"[green]✓[/green] Found {len(attack_chains)} attack chains")
        
        # Filter by blast radius if specified
        if min_blast_radius is not None:
            attack_chains = [c for c in attack_chains if c.blast_radius >= min_blast_radius]
            console.print(f"[cyan]Min blast radius {min_blast_radius}:[/cyan] {len(attack_chains)} chains")
        
        # Output based on format
        if output_format == 'tree':
            _render_tree(attack_chains, show_mitre)
        elif output_format == 'json':
            _render_json(attack_chains, output)
        elif output_format == 'table':
            _render_table(attack_chains)
        
        # Summary
        multi_hop = sum(1 for chain in attack_chains if chain.blast_radius > 80)
        console.print(f"\n\nSummary:")
        console.print(f"  Multi-hop attacks: {multi_hop}/{len(attack_chains)}")
        
    except FileNotFoundError:
        console.print(f"[bold red]✗ Error:[/bold red] File not found: {input_file}")
        raise click.Abort()
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")
        console.print_exception()
        raise click.Abort()


def _render_tree(attack_chains, show_mitre: bool):
    """Render attack chains as tree"""
    for chain in attack_chains:
        tree = Tree(f"[bold]{chain.name}[/bold] (Blast Radius: {chain.blast_radius:.1f})")
        
        for step in chain.steps:
            label = f"{step.action}"
            if show_mitre:
                label += f" [dim]({step.mitre_technique})[/dim]"
            tree.add(label)
        
        console.print(tree)
        console.print()


def _render_json(attack_chains, output_file: Optional[str]):
    """Render attack chains as JSON"""
    data = [chain.to_dict() for chain in attack_chains]
    
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        console.print(f"[green]✓[/green] Saved to {output_file}")
    else:
        console.print_json(data=data)


def _render_table(attack_chains):
    """Render attack chains as table"""
    from rich.table import Table
    
    table = Table(title="Attack Chains")
    table.add_column("Name", style="cyan")
    table.add_column("Hops", justify="right")
    table.add_column("Severity", style="bold")
    table.add_column("Blast Radius", justify="right")
    
    for chain in attack_chains:
        table.add_row(
            chain.name,
            str(chain.hop_count),
            str(chain.severity),
            f"{chain.blast_radius:.1f}"
        )
    
    console.print(table)


__all__ = ['analyze']
