"""
EC2 Enumeration CLI Commands
CLI commands for AWS EC2 reconnaissance
"""

import click
from rich.console import Console

console = Console()


@click.command('ec2-enum')
@click.option('--access-key', '-a', help='AWS Access Key ID')
@click.option('--secret-key', '-s', help='AWS Secret Access Key')
@click.option('--session-token', '-t', help='AWS Session Token (optional)')
@click.option('--profile', '-p', help='AWS CLI profile name')
@click.option('--region', '-r', default='all',
              help='AWS region or "all" for all regions')
@click.option('--limit', '-l', type=int, default=None,
              help='Limit instances per region')
@click.option('--output', '-o', type=click.Choice(['tree', 'json', 'table']),
              default='tree', help='Output format')
@click.option('--include-snapshots', is_flag=True, default=True,
              help='Include EBS snapshot enumeration')
def ec2_enum(access_key: str, secret_key: str, session_token: str,
             profile: str, region: str, limit: int, output: str,
             include_snapshots: bool):
    """
    Enumerate AWS EC2 instances and analyze security.
    
    Discovers EC2 instances across regions, analyzes security groups,
    detects exposed services (SSH/RDP), and maps findings to MITRE ATT&CK.
    
    Examples:
    
      # Enumerate with access keys
      cloudvault recon ec2-enum -a AKIAXXXX -s XXXXXXXX
      
      # Enumerate with AWS profile
      cloudvault recon ec2-enum --profile myprofile
      
      # Specific region with limit
      cloudvault recon ec2-enum --profile prod --region us-east-1 --limit 10
      
      # JSON output
      cloudvault recon ec2-enum --profile prod --output json
    """
    from ...recon.ec2_enum import EC2Enumerator, SecurityRisk
    import json
    
    console.print("[bold cyan]🖥️  AWS EC2 Instance Enumeration[/bold cyan]\n")
    
    # Validate credentials
    if not profile and not (access_key and secret_key):
        console.print("[yellow]⚠️  No credentials specified. Using default AWS credentials.[/yellow]")
        console.print("[dim]Use --profile or --access-key/--secret-key to specify credentials[/dim]\n")
    
    # Determine regions
    if region == 'all':
        regions = None
        console.print("[cyan]Regions:[/cyan] All AWS regions")
    else:
        regions = [r.strip() for r in region.split(',')]
        console.print(f"[cyan]Regions:[/cyan] {', '.join(regions)}")
    
    if limit:
        console.print(f"[cyan]Limit:[/cyan] {limit} instances per region")
    
    console.print("")
    
    try:
        enumerator = EC2Enumerator(
            access_key=access_key,
            secret_key=secret_key,
            session_token=session_token,
            profile=profile,
            regions=regions
        )
        
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]{task.description}[/cyan]"),
            BarColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Enumerating EC2 instances...", total=None)
            
            results = enumerator.enumerate_all(
                limit=limit,
                include_snapshots=include_snapshots
            )
            
            progress.update(task, description="Analysis complete")
        
        # Display summary
        summary = results.get('summary', {})
        console.print(f"\n[green]✓[/green] Enumeration complete\n")
        console.print(f"[cyan]Total Instances:[/cyan] {summary.get('total_instances', 0)}")
        console.print(f"[cyan]Running:[/cyan] {summary.get('total_running', 0)}")
        console.print(f"[cyan]Public:[/cyan] {summary.get('total_public', 0)}")
        console.print(f"[cyan]Snapshots:[/cyan] {summary.get('total_snapshots', 0)}")
        console.print(f"[cyan]Findings:[/cyan] {summary.get('total_findings', 0)}")
        console.print("")
        
        # Output results
        if output == 'tree':
            tree_output = enumerator.format_tree(results)
            console.print(tree_output)
        elif output == 'json':
            from ...recon.ec2_enum import format_json
            json_results = format_json(results)
            console.print(json.dumps(json_results, indent=2))
        elif output == 'table':
            _display_table(results)
        
        # Show critical findings
        findings = results.get('findings', [])
        critical = [f for f in findings if f.severity == SecurityRisk.CRITICAL]
        
        if critical:
            console.print(f"\n[bold red]⚠️  {len(critical)} CRITICAL finding(s)![/bold red]")
            for finding in critical[:3]:
                console.print(f"  • {finding.title}: {finding.resource_id}")
            if len(critical) > 3:
                console.print(f"  ... and {len(critical) - 3} more")
        
    except ImportError as e:
        console.print(f"[bold red]✗ Missing dependency:[/bold red] {e}")
        console.print("[yellow]Install boto3: pip install boto3[/yellow]")
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")


def _display_table(results):
    """Display results as a table"""
    from rich.table import Table
    
    table = Table(title="EC2 Instances")
    table.add_column("Instance ID", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("State", style="green")
    table.add_column("Type", style="yellow")
    table.add_column("Public IP", style="magenta")
    table.add_column("Region", style="blue")
    table.add_column("Security", style="red")
    
    for region, data in results.get('regions', {}).items():
        for inst in data.get('instances', []):
            security_status = ""
            if inst.has_exposed_ssh:
                security_status += "⚠️ SSH "
            if inst.has_exposed_rdp:
                security_status += "⚠️ RDP"
            if not security_status:
                security_status = "✅"
            
            table.add_row(
                inst.instance_id,
                inst.name,
                inst.state,
                inst.instance_type,
                inst.public_ip or "-",
                region,
                security_status
            )
    
    console.print(table)


@click.command('ec2-ssrf')
def ec2_ssrf():
    """
    Show EC2 metadata SSRF patterns and payloads.
    
    Displays endpoints and bypass techniques for testing SSRF
    vulnerabilities that could leak EC2 metadata and IAM credentials.
    """
    from ...recon.ec2_enum import EC2Enumerator
    
    console.print("[bold cyan]🎯 EC2 Metadata SSRF Patterns[/bold cyan]\n")
    
    enumerator = EC2Enumerator()
    patterns = enumerator.get_metadata_ssrf_patterns()
    
    # IMDSv1 section
    console.print("[bold yellow]IMDSv1 Endpoints (Unprotected)[/bold yellow]")
    console.print("─" * 50)
    
    for name, url in patterns['imdsv1']['endpoints'].items():
        console.print(f"  {name}: [cyan]{url}[/cyan]")
    
    console.print(f"\n[dim]Example: {patterns['imdsv1']['example_curl']}[/dim]")
    console.print(f"[dim]SSRF: {patterns['imdsv1']['external_check']}[/dim]")
    
    # IMDSv2 section
    console.print("\n[bold yellow]IMDSv2 (Token Required)[/bold yellow]")
    console.print("─" * 50)
    console.print(f"  Token endpoint: [cyan]{patterns['imdsv2']['token_endpoint']}[/cyan]")
    console.print(f"\n[dim]Step 1: {patterns['imdsv2']['token_request']}[/dim]")
    console.print(f"[dim]Step 2: {patterns['imdsv2']['data_request']}[/dim]")
    
    # Bypasses
    console.print("\n[bold yellow]SSRF Bypasses[/bold yellow]")
    console.print("─" * 50)
    for bypass in patterns['bypasses']:
        console.print(f"  • [magenta]{bypass}[/magenta]")
    
    # High value targets
    console.print("\n[bold red]⚠️  High Value Targets[/bold red]")
    console.print("─" * 50)
    for target in patterns['high_value_targets']:
        console.print(f"  🎯 [cyan]{target}[/cyan]")
    
    console.print(f"\n[dim]Note: {patterns['note']}[/dim]")


@click.command('ec2-security')
@click.option('--access-key', '-a', help='AWS Access Key ID')
@click.option('--secret-key', '-s', help='AWS Secret Access Key')
@click.option('--profile', '-p', help='AWS CLI profile name')
@click.option('--region', '-r', default='all', help='AWS region')
def ec2_security(access_key: str, secret_key: str, profile: str, region: str):
    """
    Security-focused EC2 enumeration.
    
    Focus on security groups, exposed services, and vulnerabilities.
    Outputs only security-relevant findings with recommendations.
    """
    from ...recon.ec2_enum import EC2Enumerator, SecurityRisk
    
    console.print("[bold cyan]🔒 EC2 Security Analysis[/bold cyan]\n")
    
    # Determine regions
    if region == 'all':
        regions = None
    else:
        regions = [r.strip() for r in region.split(',')]
    
    try:
        enumerator = EC2Enumerator(
            access_key=access_key,
            secret_key=secret_key,
            profile=profile,
            regions=regions
        )
        
        from rich.progress import Progress, SpinnerColumn, TextColumn
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Analyzing security...[/cyan]"),
            console=console
        ) as progress:
            progress.add_task("", total=None)
            results = enumerator.enumerate_all(limit=None, include_snapshots=True)
        
        findings = results.get('findings', [])
        
        if not findings:
            console.print("[green]✓ No security issues found![/green]")
            return
        
        # Group by severity
        by_severity = {}
        for finding in findings:
            sev = finding.severity.value
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(finding)
        
        # Display findings
        for severity in ['critical', 'high', 'medium', 'low']:
            if severity not in by_severity:
                continue
            
            sev_findings = by_severity[severity]
            color = {'critical': 'red', 'high': 'yellow', 'medium': 'blue', 'low': 'dim'}[severity]
            
            console.print(f"\n[bold {color}]{severity.upper()} ({len(sev_findings)})[/bold {color}]")
            console.print("─" * 60)
            
            for finding in sev_findings:
                console.print(f"\n  [{color}]● {finding.title}[/{color}]")
                console.print(f"    Resource: {finding.resource_id} ({finding.resource_type})")
                console.print(f"    Region: {finding.region}")
                console.print(f"    [dim]{finding.description}[/dim]")
                console.print(f"    [green]Recommendation:[/green] {finding.recommendation}")
                
                if finding.mitre_techniques:
                    console.print(f"    [magenta]MITRE:[/magenta] {', '.join(finding.mitre_techniques)}")
        
        # Summary
        console.print(f"\n[bold]Summary[/bold]")
        console.print(f"  Critical: {len(by_severity.get('critical', []))}")
        console.print(f"  High: {len(by_severity.get('high', []))}")
        console.print(f"  Medium: {len(by_severity.get('medium', []))}")
        console.print(f"  Low: {len(by_severity.get('low', []))}")
        
    except ImportError as e:
        console.print(f"[bold red]✗ Missing dependency:[/bold red] {e}")
        console.print("[yellow]Install boto3: pip install boto3[/yellow]")
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")


# Export commands for registration
__all__ = ['ec2_enum', 'ec2_ssrf', 'ec2_security']
