"""
CloudVault TUI Application
Textual-based interactive terminal user interface
"""

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Static, DataTable, TabbedContent, TabPane
from textual.binding import Binding
from rich.text import Text
import json
from typing import Optional


class CloudVaultTUI(App):
    """CloudVault Terminal User Interface"""
    
    CSS = """
    Screen {
        background: $surface;
    }
    
    Header {
        background: $primary;
        color: $text;
    }
    
    Footer {
        background: $panel;
    }
    
    .stat-card {
        width: 1fr;
        height: 5;
        background: $panel;
        border: solid $primary;
        padding: 1;
        margin: 1;
    }
    
    DataTable {
        height: 1fr;
        margin: 1;
    }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("d", "show_dashboard", "Dashboard"),
        Binding("f", "show_findings", "Findings"),
        Binding("a", "show_analysis", "Analysis"),
    ]
    
    TITLE = "CloudVault - Cloud Security Scanner"
    SUB_TITLE = "Interactive Terminal Interface"
    
    def __init__(self, input_file: Optional[str] = None):
        super().__init__()
        self.input_file = input_file
        self.findings = []
        self._load_data()
    
    def _load_data(self):
        """Load findings from file"""
        if self.input_file:
            try:
                with open(self.input_file, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, dict) and 'findings' in data:
                        self.findings = data['findings']
                    elif isinstance(data, list):
                        self.findings = data
            except Exception as e:
                self.findings = []
        else:
            # Demo data
            self.findings = [
                {
                    "id": "demo1",
                    "title": "Public S3 Bucket with Sensitive Data",
                    "severity": "CRITICAL",
                    "provider": "aws",
                    "bucket_name": "company-backups",
                    "is_public": True,
                    "risk_score": 85.0
                },
                {
                    "id": "demo2",
                    "title": "Unencrypted Storage Container",
                    "severity": "HIGH",
                    "provider": "azure",
                    "bucket_name": "corp-data",
                    "is_public": False,
                    "risk_score": 67.5
                }
            ]
    
    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Header()
        
        with TabbedContent(initial="dashboard"):
            with TabPane("Dashboard", id="dashboard"):
                yield self._create_dashboard()
            
            with TabPane("Findings", id="findings"):
                yield self._create_findings_table()
            
            with TabPane("Analysis", id="analysis"):
                yield Static("Attack chain analysis coming soon...", classes="placeholder")
        
        yield Footer()
    
    def _create_dashboard(self) -> Container:
        """Create dashboard view"""
        total = len(self.findings)
        critical = sum(1 for f in self.findings if f.get('severity') == 'CRITICAL')
        high = sum(1 for f in self.findings if f.get('severity') == 'HIGH')
        public = sum(1 for f in self.findings if f.get('is_public', False))
        
        dashboard = Vertical(
            Horizontal(
                Static(f"[bold cyan]Total Findings[/]\n[bold white]{total}[/]", classes="stat-card"),
                Static(f"[bold red]Critical[/]\n[bold white]{critical}[/]", classes="stat-card"),
                Static(f"[bold yellow]High[/]\n[bold white]{high}[/]", classes="stat-card"),
                Static(f"[bold magenta]Public[/]\n[bold white]{public}[/]", classes="stat-card"),
            ),
            Static("\n[bold]Recent Findings:[/]\n"),
            Static(self._format_recent_findings()),
        )
        
        return dashboard
    
    def _create_findings_table(self) -> DataTable:
        """Create findings table"""
        table = DataTable()
        table.add_columns("Severity", "Provider", "Bucket", "Title", "Risk")
        
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        sorted_findings = sorted(
            self.findings,
            key=lambda x: severity_order.get(x.get('severity', 'INFO'), 5)
        )
        
        for finding in sorted_findings:
            severity = finding.get('severity', 'INFO')
            provider = finding.get('provider', 'unknown').upper()
            bucket = finding.get('bucket_name', 'N/A')
            title = finding.get('title', 'Unknown')[:40]
            risk = f"{finding.get('risk_score', 0):.1f}"
            
            # Color code severity
            if severity == 'CRITICAL':
                severity_text = f"[bold red]{severity}[/]"
            elif severity == 'HIGH':
                severity_text = f"[bold yellow]{severity}[/]"
            elif severity == 'MEDIUM':
                severity_text = f"[bold blue]{severity}[/]"
            else:
                severity_text = severity
            
            table.add_row(severity_text, provider, bucket, title, risk)
        
        return table
    
    def _format_recent_findings(self) -> str:
        """Format recent findings for display"""
        lines = []
        for finding in self.findings[:5]:
            severity = finding.get('severity', 'INFO')
            title = finding.get('title', 'Unknown')
            
            icon = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🔵',
                'INFO': '⚪'
            }.get(severity, '⚪')
            
            lines.append(f"{icon} [{severity}] {title}")
        
        return '\n'.join(lines) if lines else "No findings"
    
    def action_show_dashboard(self) -> None:
        """Switch to dashboard tab"""
        self.query_one(TabbedContent).active = "dashboard"
    
    def action_show_findings(self) -> None:
        """Switch to findings tab"""
        self.query_one(TabbedContent).active = "findings"
    
    def action_show_analysis(self) -> None:
        """Switch to analysis tab"""
        self.query_one(TabbedContent).active = "analysis"


__all__ = ['CloudVaultTUI']
