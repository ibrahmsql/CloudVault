"""
Alert System Test Command
Test alert notifications with sample findings
"""

import click
from rich.console import Console
import asyncio
import json

console = Console()


@click.command()
@click.option('--notify', 
              type=click.Choice(['slack', 'discord', 'email'], case_sensitive=False),
              multiple=True,
              required=True,
              help='Notification channel(s) to test')
@click.option('--slack-webhook',
              help='Slack webhook URL')
@click.option('--discord-webhook',
              help='Discord webhook URL')
@click.option('--email-to',
              help='Email recipient')
@click.option('--smtp-host',
              help='SMTP server hostname')
@click.option('--smtp-port', type=int, default=587,
              help='SMTP port')
@click.option('--smtp-user',
              help='SMTP username')
@click.option('--smtp-password',
              help='SMTP password')
@click.option('--alert-on',
              help='Severity filter (e.g., critical,high)')
def test_alerts(notify, slack_webhook, discord_webhook, email_to,
                smtp_host, smtp_port, smtp_user, smtp_password, alert_on):
    """Test alert notifications with sample findings"""
    from ...alerts import SlackNotifier, DiscordNotifier, EmailNotifier, send_alert
    from ...models import Severity
    
    console.print("[bold cyan]Testing CloudVault Alerts[/bold cyan] 🔔\n")
    
    # Sample findings
    sample_findings = [
        {
            "id": "test-1",
            "title": "Public S3 Bucket with Sensitive Data",
            "description": "Test finding",
            "severity": "CRITICAL",
            "provider": "aws",
            "bucket_name": "test-prod-backups",
            "is_public": True,
            "risk_score": 95.0
        },
        {
            "id": "test-2",
            "title": "Unencrypted Storage Container",
            "severity": "HIGH",
            "provider": "azure",
            "bucket_name": "test-data",
            "is_public": False,
            "risk_score": 75.0
        },
        {
            "id": "test-3",
            "title": "Log Files Exposed",
            "severity": "MEDIUM",
            "provider": "aws",
            "bucket_name": "test-logs",
            "is_public": True,
            "risk_score": 50.0
        }
    ]
    
    # Setup notifiers
    notifiers = []
    severity_filter = None
    if alert_on:
        severity_filter = [s.strip() for s in alert_on.split(',')]
    
    if 'slack' in notify:
        if not slack_webhook:
            console.print("[red]Error: --slack-webhook required[/red]")
            return
        notifiers.append(SlackNotifier(slack_webhook, severity_filter))
        console.print("[green]✓[/green] Slack notifier configured")
    
    if 'discord' in notify:
        if not discord_webhook:
            console.print("[red]Error: --discord-webhook required[/red]")
            return
        notifiers.append(DiscordNotifier(discord_webhook, severity_filter))
        console.print("[green]✓[/green] Discord notifier configured")
    
    if 'email' in notify:
        if not email_to or not smtp_host:
            console.print("[red]Error: --email-to and --smtp-host required[/red]")
            return
        notifiers.append(EmailNotifier(
            smtp_host=smtp_host,
            smtp_port=smtp_port,
            from_email=smtp_user or f"test@{smtp_host}",
            to_emails=[email_to],
            username=smtp_user,
            password=smtp_password,
            severity_filter=severity_filter
        ))
        console.print("[green]✓[/green] Email notifier configured")
    
    # Send test alert
    try:
        console.print(f"\n[cyan]Sending test alert to {len(notifiers)} channel(s)...[/cyan]\n")
        
        summary = {
            'total_findings': 3,
            'critical': 1,
            'high': 1,
            'medium': 1
        }
        
        asyncio.run(send_alert(sample_findings, notifiers, summary))
        
        console.print("\n[bold green]✓ Alert sent successfully![/bold green]")
        console.print("[dim]Check your notification channels[/dim]")
        
    except Exception as e:
        console.print(f"\n[bold red]✗ Error:[/bold red] {e}")
        console.print_exception()


__all__ = ['test_alerts']
