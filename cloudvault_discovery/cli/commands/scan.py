"""
Scan Command - Main scanning functionality
cloudvault scan [OPTIONS]
"""

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from typing import Optional

console = Console()


@click.command()
@click.option('-c', '--config', default='config.yaml', 
              help='Configuration file path')
@click.option('-s', '--source', type=click.Path(exists=True),
              help='Static domain list file instead of live stream')
@click.option('-p', '--permutations', type=click.Path(exists=True),
              help='Permutation patterns file')
@click.option('--keywords-file', type=click.Path(exists=True),
              help='Keywords file for interesting content detection')
@click.option('-t', '--threads', type=int,
              help='Number of worker threads per provider')
@click.option('--only-interesting', is_flag=True,
              help='Only report buckets with interesting content')
@click.option('--skip-lets-encrypt', is_flag=True, default=True,
              help='Skip Let\'s Encrypt certificates')
@click.option('-l', '--log-to-file', is_flag=True,
              help='Log found buckets to file')
@click.option('-v', '--verbose', is_flag=True,
              help='Enable verbose logging')
@click.option('--aws-only', is_flag=True,
              help='Only check AWS S3 buckets')
@click.option('--gcp-only', is_flag=True,
              help='Only check Google Cloud Storage')
@click.option('--azure-only', is_flag=True,
              help='Only check Azure Blob Storage')
@click.option('--download', is_flag=True,
              help='Download and analyze bucket contents')
@click.option('--exploit', is_flag=True,
              help='Enable credential exploitation')
@click.option('--stealth', is_flag=True,
              help='Enable stealth mode')
@click.option('--output', '-o', type=click.Path(),
              help='Output file for results (JSON)')
@click.option('--notify', 
              type=click.Choice(['slack', 'discord', 'email'], case_sensitive=False),
              multiple=True,
              help='Enable notifications (can specify multiple)')
@click.option('--slack-webhook',
              help='Slack webhook URL')
@click.option('--discord-webhook',
              help='Discord webhook URL')
@click.option('--email-to',
              help='Email recipient (comma-separated for multiple)')
@click.option('--smtp-host',
              help='SMTP server hostname')
@click.option('--smtp-port', type=int, default=587,
              help='SMTP port (default: 587)')
@click.option('--smtp-user',
              help='SMTP username')
@click.option('--smtp-password',
              help='SMTP password')
@click.option('--alert-on',
              help='Severity levels to alert on (comma-separated, e.g., critical,high)')
@click.option('--save-history', is_flag=True,
              help='Save scan results to history database')
def scan(config: str, source: Optional[str], permutations: Optional[str],
         keywords_file: Optional[str], threads: Optional[int],
         only_interesting: bool, skip_lets_encrypt: bool,
         log_to_file: bool, verbose: bool, aws_only: bool,
         gcp_only: bool, azure_only: bool, download: bool,
         exploit: bool, stealth: bool, output: Optional[str],
         notify: tuple, slack_webhook: Optional[str], discord_webhook: Optional[str],
         email_to: Optional[str], smtp_host: Optional[str], smtp_port: int,
         smtp_user: Optional[str], smtp_password: Optional[str], alert_on: Optional[str],
         save_history: bool):
    """
    Scan for exposed cloud storage buckets.
    
    This is the main scanning command that monitors certificate transparency
    logs or processes a static domain list to discover misconfigured buckets.
    """
    from ..app import CloudVaultDiscovery
    from ...core.config import load_config
    from ...alerts import SlackNotifier, DiscordNotifier, EmailNotifier, send_alert
    import logging
    import asyncio
    
    # Set up logging
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    console.print("[bold cyan]CloudVault Scanner[/bold cyan] 🔍", style="bold")
    console.print("=" * 60)
    
    # Setup notifiers
    notifiers = []
    severity_filter = None
    if alert_on:
        severity_filter = [s.strip() for s in alert_on.split(',')]
        console.print(f"[yellow]Alert filter:[/yellow] {', '.join(severity_filter)}")
    
    if 'slack' in notify:
        if not slack_webhook:
            console.print("[bold red]✗ Error:[/bold red] --slack-webhook required for Slack notifications")
            raise click.Abort()
        notifiers.append(SlackNotifier(slack_webhook, severity_filter))
        console.print("[green]✓[/green] Slack notifications enabled")
    
    if 'discord' in notify:
        if not discord_webhook:
            console.print("[bold red]✗ Error:[/bold red] --discord-webhook required for Discord notifications")
            raise click.Abort()
        notifiers.append(DiscordNotifier(discord_webhook, severity_filter))
        console.print("[green]✓[/green] Discord notifications enabled")
    
    if 'email' in notify:
        if not email_to or not smtp_host:
            console.print("[bold red]✗ Error:[/bold red] --email-to and --smtp-host required for email")
            raise click.Abort()
        to_emails = [e.strip() for e in email_to.split(',')]
        notifiers.append(EmailNotifier(
            smtp_host=smtp_host,
            smtp_port=smtp_port,
            from_email=smtp_user or f"cloudvault@{smtp_host}",
            to_emails=to_emails,
            username=smtp_user,
            password=smtp_password,
            severity_filter=severity_filter
        ))
        console.print(f"[green]✓[/green] Email notifications enabled ({len(to_emails)} recipients)")
    
    try:
        # Load configuration
        cfg = load_config(config)
        
        # Apply CLI overrides
        if only_interesting:
            cfg.only_interesting = True
        if skip_lets_encrypt:
            cfg.skip_lets_encrypt = True
        if threads:
            if hasattr(cfg, 'aws'):
                cfg.aws.max_threads = threads
            if hasattr(cfg, 'gcp'):
                cfg.gcp.max_threads = threads
            if hasattr(cfg, 'azure'):
                cfg.azure.max_threads = threads
        
        # Provider filtering
        if aws_only:
            if hasattr(cfg, 'gcp'):
                cfg.gcp.enabled = False
            if hasattr(cfg, 'azure'):
                cfg.azure.enabled = False
        elif gcp_only:
            if hasattr(cfg, 'aws'):
                cfg.aws.enabled = False
            if hasattr(cfg, 'azure'):
                cfg.azure.enabled = False
        elif azure_only:
            if hasattr(cfg, 'aws'):
                cfg.aws.enabled = False
            if hasattr(cfg, 'gcp'):
                cfg.gcp.enabled = False
        
        # Create app instance
        app = CloudVaultDiscovery()
        app.config = cfg
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Initializing scanner...", total=None)
            
            # Initialize components
            app.initialize_components(None)
            
            progress.update(task, description="[green]Scanner ready!")
            progress.stop()
        
        console.print("\n[bold green]✓[/bold green] Scan initialized successfully")
        console.print("[yellow]Press Ctrl+C to stop[/yellow]\n")
        
        # Run scan
        from ...core.certstream import CertStreamMonitor
        from ...core.domain_processor import DomainProcessor
        from ...core.scanner import BucketScanner
        from ...analysis.risk_scorer import calculate_risk_score
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
        
        # Load keywords if file provided
        keywords = set()
        if keywords_file and os.path.exists(keywords_file):
            with open(keywords_file, 'r') as f:
                keywords = {line.strip() for line in f if line.strip()}
        
        # Load permutations if file provided
        permutation_patterns = None
        if permutations and os.path.exists(permutations):
            with open(permutations, 'r') as f:
                permutation_patterns = [line.strip() for line in f if line.strip()]
        
        # Initialize components
        domain_processor = DomainProcessor(
            permutations=permutation_patterns,
            keywords=keywords
        )
        
        findings_list = []
        scan_start = asyncio.get_event_loop().time()
        
        async def process_domain(domain: str, cert_data: dict):
            """Process discovered domain"""
            # Generate bucket candidates
            candidates = domain_processor.process_domain(domain)
            
            if not candidates:
                return
            
            # Scan buckets
            async with BucketScanner(
                aws_enabled=not gcp_only and not azure_only,
                gcp_enabled=not aws_only and not azure_only,
                azure_enabled=not aws_only and not gcp_only,
                timeout=5
            ) as scanner:
                for bucket_name in candidates[:5]:  # Limit candidates per domain
                    finding = await scanner.scan_bucket(bucket_name)
                    
                    if finding and finding.get('exists'):
                        # Calculate risk score
                        finding['risk_score'] = calculate_risk_score(finding)
                        finding['title'] = f"Discovered {finding['provider'].upper()} Bucket"
                        finding['id'] = f"{finding['provider']}-{bucket_name}"
                        
                        # Only show interesting if flag set
                        if only_interesting and not finding.get('is_public'):
                            continue
                        
                        findings_list.append(finding)
                        
                        # Real-time output
                        severity = finding.get('severity', 'INFO')
                        icon = {
                            'CRITICAL': '🔴',
                            'HIGH': '🟠',
                            'MEDIUM': '🟡',
                            'LOW': '🔵',
                            'INFO': '⚪'
                        }.get(severity, '⚪')
                        
                        console.print(f"{icon} [{severity}] Found: {bucket_name} ({finding['provider'].upper()})")
        
        # Start monitoring
        if source:
            # Process static domain list
            console.print(f"[cyan]Processing domains from:[/cyan] {source}")
            
            with open(source, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
            
            console.print(f"[cyan]Loaded {len(domains)} domains[/cyan]\n")
            
            async def scan_domains():
                """Async wrapper for domain scanning"""
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    console=console
                ) as progress:
                    task = progress.add_task("[cyan]Scanning...", total=len(domains))
                    
                    for domain in domains:
                        await process_domain(domain, {})
                        progress.update(task, advance=1)
            
            asyncio.run(scan_domains())
        else:
            # Monitor certstream
            console.print("[cyan]Monitoring certificate transparency logs...[/cyan]")
            console.print("[dim]Discovering domains in real-time...[/dim]\n")
            
            async def monitor_certstream():
                """Async wrapper for certstream monitoring"""
                monitor = CertStreamMonitor(
                    callback=process_domain,
                    skip_lets_encrypt=skip_lets_encrypt,
                    keywords=keywords
                )
                
                try:
                    await monitor.connect()
                except KeyboardInterrupt:
                    console.print("\n[yellow]⚠ Stopping scan...[/yellow]")
                    monitor.stop()
            
            asyncio.run(monitor_certstream())
        
        # Scan complete
        scan_duration = asyncio.get_event_loop().time() - scan_start
        
        console.print(f"\n[bold green]✓ Scan complete![/bold green]")
        console.print(f"[cyan]Duration:[/cyan] {scan_duration:.1f}s")
        console.print(f"[cyan]Findings:[/cyan] {len(findings_list)}")
        
        # Save to history if requested
        if save_history and findings_list:
            from ...history import track_scan
            console.print("\n[cyan]Saving to history...[/cyan]")
            scan_id = asyncio.run(track_scan(findings_list, duration=scan_duration))
            console.print(f"[green]✓[/green] Saved as scan #{scan_id}")
        
        # Send alerts if notifiers configured and findings exist
        if notifiers and findings_list:
            console.print(f"\n[cyan]Sending alerts via {len(notifiers)} channel(s)...[/cyan]")
            asyncio.run(send_alert(findings_list, notifiers))
            console.print("[green]✓[/green] Alerts sent successfully")
        
        # Save output
        if output:
            import json
            with open(output, 'w') as f:
                json.dump({
                    'metadata': {
                        'version': '1.0.1',
                        'scan_duration': scan_duration,
                        'total_findings': len(findings_list)
                    },
                    'findings': findings_list
                }, f, indent=2)
            console.print(f"\n[bold]Results saved to:[/bold] {output}")
            
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Scan interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[bold red]✗ Error:[/bold red] {e}")
        if verbose:
            console.print_exception()
        raise click.Abort()


__all__ = ['scan']
