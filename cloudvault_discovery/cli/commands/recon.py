"""
Recon Command - Cloud Reconnaissance
"""

import click
from rich.console import Console
import asyncio

console = Console()


@click.group()
def recon():
    """Cloud reconnaissance and fingerprinting"""
    pass


@recon.command()
@click.option('-u', '--url', required=True, multiple=True,
              help='Target URL(s) to fingerprint')
def fingerprint(url: tuple):
    """Fingerprint cloud providers, WAF, and CDN"""
    from ...recon.fingerprint import CloudFingerprinter
    
    console.print("[bold cyan]Cloud Fingerprinting[/bold cyan]\n")
    
    async def run_fingerprinting():
        results = []
        async with CloudFingerprinter() as fp:
            for target_url in url:
                result = await fp.fingerprint(target_url)
                results.append(result)
        
        return results
    
    try:
        results = asyncio.run(run_fingerprinting())
        
        # Use built-in formatter
        async def format_results():
            async with CloudFingerprinter() as fp:
                return fp.format_tree(results)
        
        tree_output = asyncio.run(format_results())
        console.print(tree_output)
        
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")


@recon.command()
@click.option('--dockerhub', help='Docker Hub namespace')
@click.option('--ecr', nargs=2, metavar='NAMESPACE REPO', help='ECR namespace and repo')
@click.option('--gcr', nargs=2, metavar='PROJECT REPO', help='GCR project and repo')
@click.option('--acr', nargs=2, metavar='REGISTRY REPO', help='ACR registry and repo')
def containers(dockerhub, ecr, gcr, acr):
    """Scan container registries"""
    from ...recon.container_registry import ContainerRegistryScanner
    
    console.print("[bold cyan]Container Registry Scan[/bold cyan]\n")
    
    async def run_scan():
        results = []
        async with ContainerRegistryScanner() as scanner:
            if dockerhub:
                result = await scanner.scan_dockerhub(dockerhub)
                if result:
                    results.append(result)
            
            if ecr:
                result = await scanner.scan_ecr_public(ecr[0], ecr[1])
                if result:
                    results.append(result)
            
            if gcr:
                result = await scanner.scan_gcr(gcr[0], gcr[1])
                if result:
                    results.append(result)
            
            if acr:
                result = await scanner.scan_acr(acr[0], acr[1])
                if result:
                    results.append(result)
        
        return results
    
    try:
        results = asyncio.run(run_scan())
        
        if not results:
            console.print("[yellow]No registries scanned. Specify at least one option.[/yellow]")
            return
        
        # Format results
        async def format_results():
            async with ContainerRegistryScanner() as scanner:
                return scanner.format_tree(results)
        
        tree_output = asyncio.run(format_results())
        console.print(tree_output)
        
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")


@recon.command()
@click.option('-u', '--url', required=True, multiple=True,
              help='Target URL(s) to check')
def services(url: tuple):
    """Discover cloud services (API Gateway, Lambda, etc.)"""
    from ...recon.cloud_services import CloudServiceDiscovery
    
    console.print("[bold cyan]Cloud Service Discovery[/bold cyan]\n")
    
    async def run_discovery():
        results = []
        async with CloudServiceDiscovery() as disco:
            for target_url in url:
                # Detect service type
                service_types = disco.detect_service_type(target_url)
                
                if 'api_gateway_aws' in service_types or 'apigee' in service_types:
                    result = await disco.check_api_gateway(target_url)
                    if result:
                        results.append(result)
                
                if 'lambda_url' in service_types:
                    result = await disco.check_lambda_url(target_url)
                    if result:
                        results.append(result)
        
        return results
    
    try:
        results = asyncio.run(run_discovery())
        
        if not results:
            console.print("[yellow]No cloud services detected in provided URLs.[/yellow]")
            return
        
        # Format results
        async def format_results():
            async with CloudServiceDiscovery() as disco:
                return disco.format_tree(results)
        
        tree_output = asyncio.run(format_results())
        console.print(tree_output)
        
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")


@recon.command()
@click.option('-u', '--url', multiple=True,
              help='Specific URL(s) to test for metadata endpoints (e.g., S3 static sites)')
def metadata(url: tuple):
    """Check cloud metadata endpoints (IMDSv1/v2)"""
    from ...recon.metadata_checker import MetadataEndpointChecker
    
    console.print("[bold cyan]Metadata Endpoint Check[/bold cyan]\n")
    
    if url:
        # Test specific URLs for metadata endpoint accessibility
        console.print(f"[cyan]Testing {len(url)} URL(s) for metadata endpoint exposure...[/cyan]\n")
        
        async def check_urls():
            results = []
            async with MetadataEndpointChecker() as checker:
                for target_url in url:
                    console.print(f"[dim]Checking: {target_url}[/dim]")
                    # Try to access metadata endpoints through the URL
                    # This is useful for SSRF testing on public endpoints
                    for endpoint_key in checker.ENDPOINTS.keys():
                        result = await checker.check_endpoint(endpoint_key)
                        if result:
                            result['tested_via'] = target_url
                            results.append(result)
            return results, checker.format_tree(results)
        
        try:
            results, tree_output = asyncio.run(check_urls())
            console.print(tree_output)
            
            accessible = [r for r in results if r.get('accessible')]
        except Exception as e:
            console.print(f"[bold red]✗ Error:[/bold red] {e}")
    else:
        # Default: Check local metadata endpoints
        async def run_check():
            async with MetadataEndpointChecker() as checker:
                results = await checker.check_all()
                return results, checker.format_tree(results)
        
        try:
            results, tree_output = asyncio.run(run_check())
            console.print(tree_output)
            
            # Warning if accessible
            accessible = [r for r in results if r.get('accessible')]
            if accessible:
                console.print(f"\n[bold red]⚠️  WARNING: {len(accessible)} metadata endpoint(s) accessible![/bold red]")
                console.print("[yellow]This could indicate a misconfigured environment or SSRF vulnerability[/yellow]")
            
        except Exception as e:
            console.print(f"[bold red]✗ Error:[/bold red] {e}")


@recon.command('s3-enum')
@click.option('-c', '--company', required=True,
              help='Company name to enumerate S3 buckets')
@click.option('--limit', type=int, default=50,
              help='Limit number of buckets to check')
def s3_enum(company: str, limit: int):
    """Enumerate S3 buckets for a company"""
    from ...recon.s3_enum import S3BucketRecon
    
    console.print(f"[bold cyan]S3 Bucket Enumeration[/bold cyan]\n")
    console.print(f"[cyan]Target:[/cyan] {company}")
    console.print(f"[dim]Generating bucket name candidates...[/dim]\n")
    
    async def run_enum():
        async with S3BucketRecon() as s3:
            buckets = await s3.enumerate_buckets(company)
            return buckets
    
    try:
        from rich.progress import Progress, SpinnerColumn, TextColumn
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Checking buckets..."),
            console=console
        ) as progress:
            progress.add_task("", total=None)
            buckets = asyncio.run(run_enum())
        
        console.print(f"\n[green]✓[/green] Found {len(buckets)} bucket(s)\n")
        
        # Format results
        async def format_results():
            async with S3BucketRecon() as s3:
                return s3.format_tree(buckets)
        
        tree_output = asyncio.run(format_results())
        console.print(tree_output)
        
        # Show summary
        accessible = [b for b in buckets if b.get('accessible')]
        if accessible:
            console.print(f"\n[bold yellow]⚠️  {len(accessible)} public bucket(s) found![/bold yellow]")
        
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")


@recon.command('gcp-enum')
@click.option('-c', '--company', required=True,
              help='Company name to enumerate GCP buckets')
def gcp_enum(company: str):
    """Enumerate GCP Cloud Storage buckets"""
    from ...recon.gcp_enum import GCPBucketRecon
    
    console.print(f"[bold cyan]GCP Bucket Enumeration[/bold cyan]\n")
    console.print(f"[cyan]Target:[/cyan] {company}")
    console.print(f"[dim]Generating bucket name candidates...[/dim]\n")
    
    async def run_enum():
        async with GCPBucketRecon() as gcp:
            buckets = await gcp.enumerate_buckets(company)
            return buckets
    
    try:
        from rich.progress import Progress, SpinnerColumn, TextColumn
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Checking GCP buckets..."),
            console=console
        ) as progress:
            progress.add_task("", total=None)
            buckets = asyncio.run(run_enum())
        
        console.print(f"\n[green]✓[/green] Found {len(buckets)} bucket(s)\n")
        
        async def format_results():
            async with GCPBucketRecon() as gcp:
                return gcp.format_tree(buckets)
        
        tree_output = asyncio.run(format_results())
        console.print(tree_output)
        
        accessible = [b for b in buckets if b.get('accessible')]
        if accessible:
            console.print(f"\n[bold yellow]⚠️  {len(accessible)} public bucket(s) found![/bold yellow]")
        
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")


@recon.command('azure-enum')
@click.option('-c', '--company', required=True,
              help='Company name to enumerate Azure storage')
def azure_enum(company: str):
    """Enumerate Azure Blob Storage accounts"""
    from ...recon.azure_enum import AzureBlobRecon
    
    console.print(f"[bold cyan]Azure Blob Enumeration[/bold cyan]\n")
    console.print(f"[cyan]Target:[/cyan] {company}")
    console.print(f"[dim]Generating storage account name candidates...[/dim]\n")
    
    async def run_enum():
        async with AzureBlobRecon() as azure:
            accounts = await azure.enumerate_storage_accounts(company)
            return accounts
    
    try:
        from rich.progress import Progress, SpinnerColumn, TextColumn
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Checking Azure storage..."),
            console=console
        ) as progress:
            progress.add_task("", total=None)
            accounts = asyncio.run(run_enum())
        
        console.print(f"\n[green]✓[/green] Found {len(accounts)} storage account(s)\n")
        
        async def format_results():
            async with AzureBlobRecon() as azure:
                return azure.format_tree(accounts)
        
        tree_output = asyncio.run(format_results())
        console.print(tree_output)
        
        accessible = [a for a in accounts if a.get('accessible')]
        if accessible:
            console.print(f"\n[bold yellow]⚠️  {len(accessible)} public storage account(s) found![/bold yellow]")
        
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")


@recon.command('subdomain-enum')
@click.option('-d', '--domain', required=True,
              help='Target domain to enumerate')
@click.option('-m', '--method', 
              type=click.Choice(['crtsh', 'dns', 'permute', 'all']),
              default='crtsh',
              help='Enumeration method')
def subdomain_enum(domain: str, method: str):
    """Enumerate subdomains using multiple techniques"""
    from ...recon.subdomain_enum import SubdomainEnumerator
    
    console.print(f"[bold cyan]Subdomain Enumeration[/bold cyan]\n")
    console.print(f"[cyan]Domain:[/cyan] {domain}")
    console.print(f"[cyan]Method:[/cyan] {method}\n")
    
    async def run_enum():
        async with SubdomainEnumerator() as enumerator:
            if method == 'crtsh' or method == 'all':
                console.print("[dim]Querying crt.sh (Certificate Transparency)...[/dim]")
                subs = await enumerator.enum_crt_sh(domain)
                return subs, 'crt.sh'
            elif method == 'dns':
                console.print("[dim]Brute-forcing DNS...[/dim]")
                subs = await enumerator.enum_dns_brute(domain)
                return subs, 'DNS Brute-force'
            elif method == 'permute':
                console.print("[dim]Generating permutations...[/dim]")
                subs = await enumerator.generate_permutations(domain)
                return subs, 'Permutations'
    
    try:
        from rich.progress import Progress, SpinnerColumn, TextColumn
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Enumerating..."),
            console=console
        ) as progress:
            progress.add_task("", total=None)
            subdomains, method_used = asyncio.run(run_enum())
        
        console.print(f"\n[green]✓[/green] Found {len(subdomains)} subdomain(s)\n")
        
        # Format results
        async def format_results():
            async with SubdomainEnumerator() as enumerator:
                return enumerator.format_tree(domain, subdomains, method_used)
        
        tree_output = asyncio.run(format_results())
        console.print(tree_output)
        
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")


@recon.command('dns-intel')
@click.option('-d', '--domain', required=True, multiple=True,
              help='Target domain(s) to analyze')
def dns_intel(domain: tuple):
    """Gather DNS intelligence and analyze certificates"""
    from ...recon.dns_intel import DNSIntelligence
    
    console.print(f"[bold cyan]DNS Intelligence Gathering[/bold cyan]\n")
    
    async def run_intel():
        results = []
        async with DNSIntelligence() as dns:
            for target in domain:
                console.print(f"[dim]Analyzing: {target}[/dim]")
                data = await dns.analyze_domain(target)
                results.append(data)
        return results
    
    try:
        from rich.progress import Progress, SpinnerColumn, TextColumn
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Gathering intelligence..."),
            console=console
        ) as progress:
            progress.add_task("", total=None)
            results = asyncio.run(run_intel())
        
        console.print("\n")
        
        # Format and display results
        async def format_all():
            results_formatted = []
            async with DNSIntelligence() as dns:
                for data in results:
                    tree_output = dns.format_tree(data)
                    results_formatted.append(tree_output)
            return results_formatted
        
        formatted = asyncio.run(format_all())
        for output in formatted:
            console.print(output)
            console.print("\n")
        
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")


@recon.command('azuread')
@click.option('-d', '--domain', required=True,
              help='Target domain for Azure AD recon')
def azuread(domain: str):
    """Azure AD tenant reconnaissance"""
    from ...recon.azure_ad import AzureADRecon
    
    console.print(f"[bold cyan]Azure AD Reconnaissance[/bold cyan]\n")
    console.print(f"[cyan]Domain:[/cyan] {domain}\n")
    
    async def run_recon():
        async with AzureADRecon() as recon:
            data = await recon.enumerate_tenant(domain)
            return data
    
    try:
        from rich.progress import Progress, SpinnerColumn, TextColumn
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Enumerating tenant..."),
            console=console
        ) as progress:
            progress.add_task("", total=None)
            data = asyncio.run(run_recon())
        
        console.print("\n")
        
        async def format_results():
            async with AzureADRecon() as recon:
                return recon.format_tree(data)
        
        tree_output = asyncio.run(format_results())
        console.print(tree_output)
        
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")


@recon.command('s3-versioning')
@click.option('-b', '--bucket', required=True,
              help='Bucket name for versioning check')
@click.option('--cloudfront', '-c', 'check_cloudfront',
              help='Also check CloudFront for this domain')
def s3_versioning(bucket: str, check_cloudfront: str):
    """Check S3 bucket versioning and CloudFront"""
    from ...recon.aws_tools import AWSTools
    
    console.print(f"[bold cyan]AWS S3 Versioning Check[/bold cyan]\n")
    
    async def run_checks():
        results = {}
        async with AWSTools() as aws:
            console.print(f"[dim]Checking S3 versioning for {bucket}...[/dim]")
            results['versioning'] = await aws.check_s3_versioning(bucket)
            
            if check_cloudfront:
                console.print(f"[dim]Checking CloudFront for {check_cloudfront}...[/dim]")
                results['cloudfront'] = await aws.enumerate_cloudfront(check_cloudfront)
        
        return results
    
    try:
        results = asyncio.run(run_checks())
        
        console.print("\n")
        
        # Format results
        async def format_all():
            outputs = []
            async with AWSTools() as aws:
                if 'versioning' in results:
                    outputs.append(aws.format_tree(results['versioning'], 'versioning'))
                
                if 'cloudfront' in results:
                    outputs.append(aws.format_tree(results['cloudfront'], 'cloudfront'))
            return outputs
        
        formatted = asyncio.run(format_all())
        for output in formatted:
            console.print(output)
            console.print("\n")
        
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")


@recon.command('gcp-functions')
@click.option('-p', '--project', required=True,
              help='GCP Project ID')
@click.option('--check-versioning', '-v', 'bucket',
              help='Also check bucket versioning')
def gcp_functions(project: str, bucket: str):
    """Enumerate GCP Cloud Functions and bucket versioning"""
    from ...recon.gcp_tools import GCPTools
    
    console.print(f"[bold cyan]GCP Cloud Functions Enumeration[/bold cyan]\n")
    
    async def run_checks():
        results = {}
        async with GCPTools() as gcp:
            console.print(f"[dim]Enumerating Cloud Functions for {project}...[/dim]")
            functions = await gcp.enumerate_cloud_functions(project)
            results['functions'] = {'functions': functions}
            
            if bucket:
                console.print(f"[dim]Checking bucket versioning for {bucket}...[/dim]")
                results['versioning'] = await gcp.check_bucket_versioning(bucket)
        
        return results
    
    try:
        results = asyncio.run(run_checks())
        
        console.print("\n")
        
        # Format results
        async def format_all():
            outputs = []
            async with GCPTools() as gcp:
                if 'functions' in results:
                    outputs.append(gcp.format_tree(results['functions'], 'functions'))
                
                if 'versioning' in results:
                    outputs.append(gcp.format_tree(results['versioning'], 'versioning'))
            return outputs
        
        formatted = asyncio.run(format_all())
        for output in formatted:
            console.print(output)
            console.print("\n")
        
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")




# Import EC2 commands from separate module
from .recon_ec2 import ec2_enum, ec2_ssrf, ec2_security

# Register EC2 commands
recon.add_command(ec2_enum)
recon.add_command(ec2_ssrf)
recon.add_command(ec2_security)

# Import new AWS and Security commands
from .recon_aws import (
    iam_enum, lambda_enum, rds_enum, 
    s3_analyzer, eks_enum, secrets_scan,
    compliance as compliance_check, attack_chain,
    cloudtrail, aws_secrets, azure_keyvault, gcp_secrets
)

# Register AWS commands
recon.add_command(iam_enum, name='iam-enum')
recon.add_command(lambda_enum, name='lambda-enum')
recon.add_command(rds_enum, name='rds-enum')
recon.add_command(s3_analyzer, name='s3-deep')
recon.add_command(eks_enum, name='eks-enum')
recon.add_command(secrets_scan, name='secrets-scan')
recon.add_command(compliance_check, name='compliance-check')
recon.add_command(attack_chain, name='attack-chain')
recon.add_command(cloudtrail, name='cloudtrail')
recon.add_command(aws_secrets, name='aws-secrets')
recon.add_command(azure_keyvault, name='azure-keyvault')
recon.add_command(gcp_secrets, name='gcp-secrets')


@recon.command('scan-config')
@click.option('--rate-limit', type=float, default=10.0,
              help='Requests per second')
@click.option('--stealth', is_flag=True,
              help='Enable stealth mode')
@click.option('--timeout', type=int, default=5,
              help='Request timeout')
def scan_config(rate_limit: float, stealth: bool, timeout: int):
    """Show scan configuration with rate limiting and stealth"""
    from ...recon.scan_config import ScanConfig
    
    config = ScanConfig(
        rate_limit=rate_limit,
        timeout=timeout,
        stealth=stealth
    )
    
    console.print("[bold cyan]Scan Configuration[/bold cyan]")
    console.print(config.get_config_summary())
    
    if stealth:
        console.print("[yellow]⚠️  Stealth Mode Enabled:[/yellow]")
        console.print("  • Random delays between requests")
        console.print("  • User agent rotation")
        console.print("  • Randomized timeouts")
        console.print("  • Legitimate-looking headers")


__all__ = ['recon']

