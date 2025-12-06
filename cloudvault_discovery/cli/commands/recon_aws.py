"""
AWS Advanced CLI Commands
CLI commands for IAM, Lambda, RDS, S3, and EKS enumeration
"""

import click
from rich.console import Console

console = Console()


@click.command('iam-enum')
@click.option('--access-key', '-a', help='AWS Access Key ID')
@click.option('--secret-key', '-s', help='AWS Secret Access Key')
@click.option('--profile', '-p', help='AWS CLI profile name')
@click.option('--output', '-o', type=click.Choice(['tree', 'json']), default='tree')
def iam_enum(access_key: str, secret_key: str, profile: str, output: str):
    """
    Enumerate AWS IAM users, roles, and policies.
    
    Detects privilege escalation paths and shadow admins.
    """
    from ...recon.aws import IAMEnumerator, IAMRiskLevel
    import json
    
    console.print("[bold cyan]🔐 AWS IAM Enumeration[/bold cyan]\n")
    
    try:
        enumerator = IAMEnumerator(
            access_key=access_key,
            secret_key=secret_key,
            profile=profile
        )
        
        from rich.progress import Progress, SpinnerColumn, TextColumn
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]{task.description}[/cyan]"),
            console=console
        ) as progress:
            progress.add_task("Enumerating IAM...", total=None)
            results = enumerator.enumerate_all()
        
        summary = results.get('summary', {})
        console.print(f"\n[green]✓[/green] Enumeration complete\n")
        console.print(f"[cyan]Users:[/cyan] {summary.get('total_users', 0)}")
        console.print(f"[cyan]Roles:[/cyan] {summary.get('total_roles', 0)}")
        console.print(f"[cyan]Policies:[/cyan] {summary.get('total_policies', 0)}")
        console.print(f"[cyan]Groups:[/cyan] {summary.get('total_groups', 0)}")
        console.print(f"[yellow]Admins:[/yellow] {summary.get('admins', 0)}")
        console.print(f"[yellow]No MFA:[/yellow] {summary.get('users_without_mfa', 0)}")
        console.print(f"[red]Shadow Admins:[/red] {summary.get('shadow_admins', 0)}")
        console.print(f"[red]Privesc Paths:[/red] {summary.get('privilege_escalation_paths', 0)}")
        
        if output == 'json':
            console.print("\n" + json.dumps({
                'summary': summary,
                'users': [u.__dict__ for u in results.get('users', [])],
                'findings': len(results.get('findings', []))
            }, indent=2, default=str))
        else:
            findings = results.get('findings', [])
            if findings:
                console.print(f"\n[bold red]⚠️  Security Findings ({len(findings)})[/bold red]")
                for finding in findings[:10]:
                    color = 'red' if finding.severity == IAMRiskLevel.CRITICAL else 'yellow'
                    console.print(f"  [{color}]● {finding.title}[/{color}]")
                    console.print(f"    {finding.resource_id}")
                if len(findings) > 10:
                    console.print(f"  ... and {len(findings) - 10} more")
                    
    except ImportError as e:
        console.print(f"[red]✗ Missing dependency:[/red] {e}")
    except Exception as e:
        console.print(f"[red]✗ Error:[/red] {e}")


@click.command('lambda-enum')
@click.option('--access-key', '-a', help='AWS Access Key ID')
@click.option('--secret-key', '-s', help='AWS Secret Access Key')
@click.option('--profile', '-p', help='AWS CLI profile name')
@click.option('--region', '-r', default='us-east-1', help='AWS region(s), comma-separated')
def lambda_enum(access_key: str, secret_key: str, profile: str, region: str):
    """
    Enumerate AWS Lambda functions and API Gateway.
    
    Detects secrets in environment variables.
    """
    from ...recon.aws import LambdaEnumerator
    
    console.print("[bold cyan]⚡ AWS Lambda Enumeration[/bold cyan]\n")
    
    regions = [r.strip() for r in region.split(',')]
    
    try:
        enumerator = LambdaEnumerator(
            access_key=access_key,
            secret_key=secret_key,
            profile=profile,
            regions=regions
        )
        
        from rich.progress import Progress, SpinnerColumn, TextColumn
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Enumerating Lambda...[/cyan]"),
            console=console
        ) as progress:
            progress.add_task("", total=None)
            results = enumerator.enumerate_all()
        
        summary = results.get('summary', {})
        console.print(f"\n[green]✓[/green] Complete\n")
        console.print(f"[cyan]Functions:[/cyan] {summary.get('total_functions', 0)}")
        console.print(f"[cyan]API Endpoints:[/cyan] {summary.get('total_endpoints', 0)}")
        console.print(f"[yellow]Functions with Secrets:[/yellow] {summary.get('functions_with_secrets', 0)}")
        console.print(f"[red]Public Endpoints:[/red] {summary.get('public_endpoints', 0)}")
        
        findings = results.get('findings', [])
        if findings:
            console.print(f"\n[bold]Findings ({len(findings)})[/bold]")
            for f in findings[:5]:
                console.print(f"  • {f.title}: {f.resource_id}")
                
    except ImportError as e:
        console.print(f"[red]✗ Missing boto3:[/red] {e}")
    except Exception as e:
        console.print(f"[red]✗ Error:[/red] {e}")


@click.command('rds-enum')
@click.option('--access-key', '-a', help='AWS Access Key ID')
@click.option('--secret-key', '-s', help='AWS Secret Access Key')
@click.option('--profile', '-p', help='AWS CLI profile name')
@click.option('--region', '-r', default='us-east-1', help='AWS region(s)')
def rds_enum(access_key: str, secret_key: str, profile: str, region: str):
    """
    Enumerate AWS RDS databases and snapshots.
    
    Detects public instances and unencrypted snapshots.
    """
    from ...recon.aws import RDSEnumerator
    
    console.print("[bold cyan]🗄️  AWS RDS Enumeration[/bold cyan]\n")
    
    regions = [r.strip() for r in region.split(',')]
    
    try:
        enumerator = RDSEnumerator(
            access_key=access_key,
            secret_key=secret_key,
            profile=profile,
            regions=regions
        )
        
        results = enumerator.enumerate_all()
        
        summary = results.get('summary', {})
        console.print(f"[cyan]Instances:[/cyan] {summary.get('total_instances', 0)}")
        console.print(f"[cyan]Snapshots:[/cyan] {summary.get('total_snapshots', 0)}")
        console.print(f"[red]Public Instances:[/red] {summary.get('public_instances', 0)}")
        console.print(f"[red]Public Snapshots:[/red] {summary.get('public_snapshots', 0)}")
        console.print(f"[yellow]Unencrypted:[/yellow] {summary.get('unencrypted', 0)}")
        
    except Exception as e:
        console.print(f"[red]✗ Error:[/red] {e}")


@click.command('s3-deep')
@click.option('--access-key', '-a', help='AWS Access Key ID')
@click.option('--secret-key', '-s', help='AWS Secret Access Key')
@click.option('--profile', '-p', help='AWS CLI profile name')
@click.option('--scan-sensitive/--no-scan-sensitive', default=True)
def s3_analyzer(access_key: str, secret_key: str, profile: str, scan_sensitive: bool):
    """
    Deep S3 bucket analysis.
    
    Checks ACLs, policies, versioning, and sensitive files.
    """
    from ...recon.aws import S3AdvancedAnalyzer
    
    console.print("[bold cyan]📦 AWS S3 Deep Analysis[/bold cyan]\n")
    
    try:
        analyzer = S3AdvancedAnalyzer(
            access_key=access_key,
            secret_key=secret_key,
            profile=profile
        )
        
        results = analyzer.enumerate_all(scan_sensitive=scan_sensitive)
        
        summary = results.get('summary', {})
        console.print(f"[cyan]Buckets:[/cyan] {summary.get('total_buckets', 0)}")
        console.print(f"[red]Public Buckets:[/red] {summary.get('public_buckets', 0)}")
        console.print(f"[yellow]Unencrypted:[/yellow] {summary.get('unencrypted', 0)}")
        console.print(f"[yellow]Sensitive Files:[/yellow] {summary.get('sensitive_file_count', 0)}")
        console.print(f"[cyan]Recoverable Deleted:[/cyan] {summary.get('recoverable_deleted', 0)}")
        
    except Exception as e:
        console.print(f"[red]✗ Error:[/red] {e}")


@click.command('eks-enum')
@click.option('--access-key', '-a', help='AWS Access Key ID')
@click.option('--secret-key', '-s', help='AWS Secret Access Key')
@click.option('--profile', '-p', help='AWS CLI profile name')
@click.option('--region', '-r', default='us-east-1', help='AWS region(s)')
def eks_enum(access_key: str, secret_key: str, profile: str, region: str):
    """
    Enumerate AWS EKS clusters.
    
    Detects public endpoints and security misconfigurations.
    """
    from ...recon.aws import EKSEnumerator
    
    console.print("[bold cyan]☸️  AWS EKS Enumeration[/bold cyan]\n")
    
    regions = [r.strip() for r in region.split(',')]
    
    try:
        enumerator = EKSEnumerator(
            access_key=access_key,
            secret_key=secret_key,
            profile=profile,
            regions=regions
        )
        
        results = enumerator.enumerate_all()
        
        summary = results.get('summary', {})
        console.print(f"[cyan]Clusters:[/cyan] {summary.get('total_clusters', 0)}")
        console.print(f"[cyan]Node Groups:[/cyan] {summary.get('total_node_groups', 0)}")
        console.print(f"[red]Public Clusters:[/red] {summary.get('public_clusters', 0)}")
        console.print(f"[yellow]Unencrypted:[/yellow] {summary.get('unencrypted', 0)}")
        
    except Exception as e:
        console.print(f"[red]✗ Error:[/red] {e}")


@click.command('secrets-scan')
@click.argument('path', type=click.Path(exists=True), required=False)
@click.option('--text', '-t', help='Text to scan for secrets')
def secrets_scan(path: str, text: str):
    """
    Scan for secrets in files or text.
    
    Detects AWS keys, Azure secrets, private keys, etc.
    """
    from ...recon.security import SecretsScanner, scan_text
    
    console.print("[bold cyan]🔍 Secrets Scanner[/bold cyan]\n")
    
    if text:
        findings = scan_text(text, source="input")
        if findings:
            console.print(f"[red]Found {len(findings)} potential secret(s):[/red]")
            for f in findings:
                console.print(f"  • {f.secret_type.value}: {f.masked_value}")
        else:
            console.print("[green]No secrets detected[/green]")
    elif path:
        scanner = SecretsScanner()
        findings = scanner.scan_file(path)
        
        if findings:
            console.print(f"[red]Found {len(findings)} potential secret(s):[/red]")
            for f in findings:
                console.print(f"  • {f.secret_type.value} at line {f.line_number}")
                console.print(f"    {f.masked_value}")
        else:
            console.print("[green]No secrets detected[/green]")
    else:
        console.print("[yellow]Provide --text or a file path[/yellow]")


@click.command('compliance')
@click.option('--framework', '-f', 
              type=click.Choice(['aws', 'azure', 'gcp']), 
              default='aws',
              help='Compliance framework')
@click.option('--profile', '-p', help='AWS CLI profile')
def compliance(framework: str, profile: str):
    """
    Run CIS Benchmark compliance checks.
    """
    from ...recon.security import ComplianceChecker, ComplianceFramework
    
    console.print(f"[bold cyan]📋 CIS {framework.upper()} Compliance Check[/bold cyan]\n")
    
    fw_map = {
        'aws': ComplianceFramework.CIS_AWS_1_4,
        'azure': ComplianceFramework.CIS_AZURE_1_3,
        'gcp': ComplianceFramework.CIS_GCP_1_2
    }
    
    checker = ComplianceChecker(framework=fw_map[framework])
    
    console.print(f"Framework: {checker.framework.value}")
    console.print(f"Available checks: {len(checker._checks)}\n")
    
    for check_id, check in list(checker._checks.items())[:10]:
        console.print(f"  [{check['severity'].value}] {check_id}: {check['title']}")
    
    console.print(f"\n[dim]Run with cloud resources for full check[/dim]")


@click.command('attack-chain')
def attack_chain():
    """
    Show attack chain analysis capabilities.
    """
    from ...recon.security import AttackChainBuilder, MITRE_CLOUD_TECHNIQUES
    
    console.print("[bold cyan]⛓️  Attack Chain Builder[/bold cyan]\n")
    
    console.print("Supported MITRE ATT&CK Techniques:\n")
    
    by_stage = {}
    for tid, info in MITRE_CLOUD_TECHNIQUES.items():
        stage = info['stage'].value
        if stage not in by_stage:
            by_stage[stage] = []
        by_stage[stage].append(f"{tid}: {info['name']}")
    
    for stage, techniques in sorted(by_stage.items()):
        console.print(f"[cyan]{stage}[/cyan]")
        for t in techniques[:3]:
            console.print(f"  • {t}")
        if len(techniques) > 3:
            console.print(f"  ... +{len(techniques) - 3} more")
    
    console.print(f"\n[dim]Total techniques: {len(MITRE_CLOUD_TECHNIQUES)}[/dim]")


@click.command('cloudtrail')
@click.option('--access-key', '-a', help='AWS Access Key ID')
@click.option('--secret-key', '-s', help='AWS Secret Access Key')
@click.option('--profile', '-p', help='AWS CLI profile name')
@click.option('--hours', '-h', default=24, help='Hours to analyze')
@click.option('--region', '-r', default='us-east-1', help='AWS region')
def cloudtrail(access_key: str, secret_key: str, profile: str, hours: int, region: str):
    """
    Analyze CloudTrail logs for threats.
    
    Detects suspicious API calls, failed auth, and data exfiltration.
    """
    from ...recon.aws import CloudTrailAnalyzer, ThreatLevel
    
    console.print("[bold cyan]📊 AWS CloudTrail Analyzer[/bold cyan]\n")
    
    try:
        analyzer = CloudTrailAnalyzer(
            access_key=access_key,
            secret_key=secret_key,
            profile=profile,
            region=region
        )
        
        results = analyzer.analyze(hours_back=hours)
        
        summary = results.get('summary', {})
        console.print(f"[cyan]Events Analyzed:[/cyan] {results.get('events_analyzed', 0)}")
        console.print(f"[cyan]Time Range:[/cyan] Last {hours} hours\n")
        console.print(f"[red]Critical:[/red] {summary.get('critical', 0)}")
        console.print(f"[yellow]High:[/yellow] {summary.get('high', 0)}")
        console.print(f"[blue]Medium:[/blue] {summary.get('medium', 0)}")
        
        alerts = results.get('alerts', [])
        if alerts:
            console.print(f"\n[bold]Alerts ({len(alerts)}):[/bold]")
            for alert in alerts[:10]:
                color = 'red' if alert.threat_level == ThreatLevel.CRITICAL else 'yellow'
                console.print(f"  [{color}]● {alert.title}[/{color}]")
                console.print(f"    {alert.description}")
                
    except Exception as e:
        console.print(f"[red]✗ Error:[/red] {e}")


@click.command('aws-secrets')
@click.option('--access-key', '-a', help='AWS Access Key ID')
@click.option('--secret-key', '-s', help='AWS Secret Access Key')
@click.option('--profile', '-p', help='AWS CLI profile name')
@click.option('--region', '-r', default='us-east-1', help='AWS region')
def aws_secrets(access_key: str, secret_key: str, profile: str, region: str):
    """
    Scan AWS Secrets Manager and SSM Parameter Store.
    
    Checks rotation, encryption, and cross-account access.
    """
    from ...recon.aws import SecretsManagerScanner
    
    console.print("[bold cyan]🔑 AWS Secrets Scanner[/bold cyan]\n")
    
    try:
        scanner = SecretsManagerScanner(
            access_key=access_key,
            secret_key=secret_key,
            profile=profile,
            region=region
        )
        
        results = scanner.enumerate_all()
        
        summary = results.get('summary', {})
        console.print(f"[cyan]Secrets:[/cyan] {summary.get('total_secrets', 0)}")
        console.print(f"[cyan]SSM Parameters:[/cyan] {summary.get('total_parameters', 0)}")
        console.print(f"[yellow]No Rotation:[/yellow] {summary.get('secrets_without_rotation', 0)}")
        console.print(f"[yellow]Unencrypted:[/yellow] {summary.get('unencrypted_parameters', 0)}")
        console.print(f"[red]Findings:[/red] {summary.get('total_findings', 0)}")
        
        findings = results.get('findings', [])
        if findings:
            console.print(f"\n[bold]Issues:[/bold]")
            for f in findings[:5]:
                console.print(f"  • {f.title}: {f.resource_id}")
                
    except Exception as e:
        console.print(f"[red]✗ Error:[/red] {e}")


@click.command('azure-keyvault')
@click.option('--subscription', '-s', help='Azure subscription ID')
def azure_keyvault(subscription: str):
    """
    Enumerate Azure Key Vault secrets and keys.
    
    Checks access policies and purge protection.
    """
    from ...recon.azure import AzureKeyVaultEnumerator
    
    console.print("[bold cyan]🔐 Azure Key Vault Scanner[/bold cyan]\n")
    
    try:
        enumerator = AzureKeyVaultEnumerator(subscription_id=subscription)
        results = enumerator.enumerate_all()
        
        summary = results.get('summary', {})
        console.print(f"[cyan]Vaults:[/cyan] {summary.get('total_vaults', 0)}")
        console.print(f"[cyan]Secrets:[/cyan] {summary.get('total_secrets', 0)}")
        console.print(f"[yellow]Public Access:[/yellow] {summary.get('public_vaults', 0)}")
        console.print(f"[yellow]No Purge Protection:[/yellow] {summary.get('no_purge_protection', 0)}")
        console.print(f"[red]Expired Secrets:[/red] {summary.get('expired_secrets', 0)}")
        
    except Exception as e:
        console.print(f"[red]✗ Error:[/red] {e}")


@click.command('gcp-secrets')
@click.option('--project', '-p', required=True, help='GCP project ID')
def gcp_secrets(project: str):
    """
    Scan GCP Secret Manager.
    
    Checks rotation, versions, and IAM bindings.
    """
    from ...recon.gcp import GCPSecretManagerScanner
    
    console.print("[bold cyan]🔒 GCP Secret Manager Scanner[/bold cyan]\n")
    
    try:
        scanner = GCPSecretManagerScanner(project_id=project)
        results = scanner.enumerate_all()
        
        summary = results.get('summary', {})
        console.print(f"[cyan]Secrets:[/cyan] {summary.get('total_secrets', 0)}")
        console.print(f"[cyan]Versions:[/cyan] {summary.get('total_versions', 0)}")
        console.print(f"[yellow]No Rotation:[/yellow] {summary.get('without_rotation', 0)}")
        console.print(f"[red]Findings:[/red] {summary.get('total_findings', 0)}")
        
    except Exception as e:
        console.print(f"[red]✗ Error:[/red] {e}")


# Export all commands
__all__ = [
    'iam_enum', 'lambda_enum', 'rds_enum', 
    's3_analyzer', 'eks_enum', 'secrets_scan',
    'compliance', 'attack_chain',
    'cloudtrail', 'aws_secrets', 'azure_keyvault', 'gcp_secrets'
]

