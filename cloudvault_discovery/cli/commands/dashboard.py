"""
Dashboard Command - Security overview and risk scoring
cloudvault dashboard [OPTIONS]
"""

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich.progress import BarColumn, Progress, TextColumn
from rich import box
from typing import Optional
import json

console = Console()


@click.command()
@click.option('-i', '--input-file', type=click.Path(exists=True),
              help='Input file with findings (JSON)')
@click.option('--filter',
              help='Filter findings (e.g., "severity=CRITICAL,HIGH AND provider=aws")')
@click.option('--exclude',
              help='Exclude findings (e.g., "bucket_name~.*-test-.*")')
@click.option('--only-public', is_flag=True,
              help='Show only public buckets')
@click.option('--min-risk-score', type=float,
              help='Minimum risk score')
@click.option('--no-color', is_flag=True,
              help='Disable colored output')
def dashboard(input_file: Optional[str], filter: Optional[str], exclude: Optional[str],
              only_public: bool, min_risk_score: Optional[float], no_color: bool):
    """Display security dashboard with risk scores and insights."""
    from ...dashboard.generator import generate_dashboard_data
    from ...dashboard.renderer import render_dashboard
    from ...filtering import apply_filters, filter_public_only, filter_by_risk_score
    
    try:
        # Generate dashboard data
        if input_file:
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
            if filter or exclude:
                findings = apply_filters(findings, filter, exclude)
                console.print(f"[cyan]Applied filters:[/cyan] {len(findings)} findings matched")
            
            if only_public:
                findings = filter_public_only(findings)
                console.print(f"[cyan]Public only:[/cyan] {len(findings)} findings")
            
            if min_risk_score is not None:
                findings = filter_by_risk_score(findings, min_score=min_risk_score)
                console.print(f"[cyan]Min risk score {min_risk_score}:[/cyan] {len(findings)} findings")
            
            if not findings:
                console.print("\n[yellow]⚠ No findings match the filter criteria[/yellow]")
                return
            
            dashboard_data = generate_dashboard_data(findings)
        else:
            # Mock data for demonstration
            dashboard_data = {
                'risk_score': 67.5,
                'total_findings': 42,
                'severity_counts': {
                    'CRITICAL': 3,
                    'HIGH': 8,
                    'MEDIUM': 15,
                    'LOW': 12,
                    'INFO': 4
                },
                'provider_stats': {
                    'aws': {'checked': 856, 'found': 25, 'public': 12},
                    'gcp': {'checked': 234, 'found': 10, 'public': 5},
                    'azure': {'checked': 157, 'found': 7, 'public': 3}
                },
                'top_risks': [
                    'Public S3 buckets with sensitive data',
                    'Buckets with write permissions',
                    'Unencrypted storage containers'
                ]
            }
        
        # Render dashboard
        render_dashboard(dashboard_data, console, no_color)
        
    except FileNotFoundError:
        console.print(f"[bold red]✗ Error:[/bold red] File not found: {input_file}")
        raise click.Abort()
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")
        console.print_exception()
        raise click.Abort()


__all__ = ['dashboard']
