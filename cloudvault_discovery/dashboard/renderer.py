"""
Dashboard Renderer
Rich-based visualization of security metrics
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich.progress import BarColumn, Progress
from rich import box
from rich.text import Text
from typing import Dict, Any


def render_dashboard(data: Dict[str, Any], console: Console, no_color: bool = False):
    """
    Render security dashboard using Rich.
    
    Args:
        data: Dashboard data from generator
        console: Rich console instance
        no_color: Disable colors
    """
    # ASCII Art Header
    header = """
╔═══════════════════════════════════════════════════════════╗
║                  CloudVault Dashboard                     ║
║              Cloud Security Risk Analysis                 ║
╚═══════════════════════════════════════════════════════════╝
"""
    
    console.print(header, style="bold cyan")
    
    # Risk Score Gauge
    _render_risk_gauge(data, console, no_color)
    
    console.print()
    
    # Severity Breakdown
    _render_severity_breakdown(data, console, no_color)
    
    console.print()
    
    # Provider Statistics
    _render_provider_stats(data, console, no_color)
    
    console.print()
    
    # Top Risks
    _render_top_risks(data, console, no_color)


def _render_risk_gauge(data: Dict[str, Any], console: Console, no_color: bool):
    """Render risk score gauge"""
    risk_score = data['risk_score']
    
    # Determine color based on score
    if risk_score >= 75:
        color = "red" if not no_color else "white"
        status = "CRITICAL"
    elif risk_score >= 50:
        color = "yellow" if not no_color else "white"
        status = "HIGH"
    elif risk_score >= 25:
        color = "blue" if not no_color else "white"
        status = "MEDIUM"
    else:
        color = "green" if not no_color else "white"
        status = "LOW"
    
    # Create gauge bar
    bar_width = 50
    filled = int((risk_score / 100) * bar_width)
    bar = "█" * filled + "░" * (bar_width - filled)
    
    gauge_text = f"""
Risk Score: [{color}]{risk_score:.1f}/100[/{color}]
Status: [{color}]{status}[/{color}]

[{color}]{bar}[/{color}]
"""
    
    panel = Panel(
        gauge_text.strip(),
        title="Security Risk Score",
        border_style=color,
        box=box.DOUBLE
    )
    
    console.print(panel)


def _render_severity_breakdown(data: Dict[str, Any], console: Console, no_color: bool):
    """Render severity breakdown table"""
    severity_counts = data['severity_counts']
    total = data['total_findings']
    
    table = Table(title="Findings by Severity", box=box.ROUNDED)
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Percentage", justify="right")
    table.add_column("Visual", width=30)
    
    colors = {
        'CRITICAL': 'red',
        'HIGH': 'yellow',
        'MEDIUM': 'blue',
        'LOW': 'green',
        'INFO': 'dim'
    }
    
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        count = severity_counts.get(severity, 0)
        percentage = (count / total * 100) if total > 0 else 0
        
        # Visual bar
        bar_width = int(percentage / 100 * 20)
        bar = "█" * bar_width
        
        color = colors[severity] if not no_color else "white"
        
        table.add_row(
            f"[{color}]{severity}[/{color}]",
            f"[{color}]{count}[/{color}]",
            f"[{color}]{percentage:.1f}%[/{color}]",
            f"[{color}]{bar}[/{color}]"
        )
    
    console.print(table)


def _render_provider_stats(data: Dict[str, Any], console: Console, no_color: bool):
    """Render provider statistics"""
    provider_stats = data.get('provider_stats', {})
    
    if not provider_stats:
        return
    
    table = Table(title="Provider Statistics", box=box.ROUNDED)
    table.add_column("Provider", style="cyan")
    table.add_column("Findings", justify="right", style="yellow")
    table.add_column("Public", justify="right", style="red")
    
    for provider, stats in provider_stats.items():
        table.add_row(
            provider.upper(),
            str(stats['found']),
            str(stats['public'])
        )
    
    console.print(table)


def _render_top_risks(data: Dict[str, Any], console: Console, no_color: bool):
    """Render top risks"""
    top_risks = data.get('top_risks', [])
    
    if not top_risks:
        console.print("[dim]No risk patterns identified[/dim]")
        return
    
    console.print("[bold]Top Security Risks:[/bold]\n")
    
    for i, risk in enumerate(top_risks, 1):
        console.print(f"  [yellow]{i}.[/yellow] {risk}")
    
    console.print()
    console.print("[bold cyan]Recommendations:[/bold cyan]")
    console.print("  • Review and remediate CRITICAL and HIGH severity findings immediately")
    console.print("  • Enable encryption for all storage buckets")
    console.print("  • Implement least privilege access controls")
    console.print("  • Enable audit logging for all cloud storage")


__all__ = ['render_dashboard']
