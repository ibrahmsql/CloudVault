"""
AWS Reconnaissance Tools
S3 versioning, CloudFront distribution, and Lambda function discovery
"""

import aiohttp
import asyncio
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class AWSTools:
    """AWS reconnaissance tools"""
    
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.session = None
        
    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(timeout=timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def check_s3_versioning(self, bucket_name: str) -> Dict[str, Any]:
        """
        Check S3 bucket versioning status.
        
        Args:
            bucket_name: Bucket name
            
        Returns:
            Versioning details
        """
        result = {
            'bucket': bucket_name,
            'versioning': None,
            'mfa_delete': None,
            'accessible': False
        }
        
        # Try to access versioning configuration
        url = f"https://{bucket_name}.s3.amazonaws.com/?versioning"
        
        try:
            async with self.session.get(url, ssl=False) as response:
                if response.status == 200:
                    result['accessible'] = True
                    xml = await response.text()
                    
                    # Parse XML response
                    if '<Status>Enabled</Status>' in xml:
                        result['versioning'] = 'Enabled'
                    elif '<Status>Suspended</Status>' in xml:
                        result['versioning'] = 'Suspended'
                    else:
                        result['versioning'] = 'Disabled'
                    
                    # MFA Delete
                    if '<MfaDelete>Enabled</MfaDelete>' in xml:
                        result['mfa_delete'] = True
                        
        except Exception as e:
            logger.debug(f"Error checking versioning for {bucket_name}: {e}")
        
        return result
    
    async def enumerate_cloudfront(self, domain: str) -> Dict[str, Any]:
        """
        Check if domain uses CloudFront.
        
        Args:
            domain: Domain to check
            
        Returns:
            CloudFront details
        """
        result = {
            'domain': domain,
            'uses_cloudfront': False,
            'distribution_domain': None,
            'headers': {}
        }
        
        try:
            url = f"https://{domain}"
            async with self.session.head(url, ssl=False, allow_redirects=True) as response:
                headers = dict(response.headers)
                result['headers'] = headers
                
                # Check for CloudFront headers
                if any(h.startswith('x-amz-cf-') for h in headers.keys()):
                    result['uses_cloudfront'] = True
                
                # Check for CloudFront domain in response
                server = headers.get('Server', '').lower()
                if 'cloudfront' in server:
                    result['uses_cloudfront'] = True
                
                # Via header often shows CloudFront
                via = headers.get('Via', '')
                if 'CloudFront' in via:
                    result['uses_cloudfront'] = True
                    # Extract distribution domain
                    if '(' in via:
                        dist = via.split('(')[1].split(')')[0]
                        result['distribution_domain'] = dist
                        
        except Exception as e:
            logger.debug(f"Error checking CloudFront for {domain}: {e}")
        
        return result
    
    async def enumerate_lambda_urls(self, region: str = 'us-east-1') -> Dict[str, Any]:
        """
        Enumerate Lambda function URLs.
        
        Lambda function URLs follow the pattern:
        https://{url-id}.lambda-url.{region}.on.aws
        
        Since URL IDs are randomly generated, enumeration requires:
        1. Source code analysis (GitHub, GitLab, etc.)
        2. DNS enumeration (*.lambda-url.*.on.aws)
        3. Web application inspection
        4. AWS API access (requires credentials)
        
        Args:
            region: AWS region to target
            
        Returns:
            Enumeration guidance and patterns
        """
        return {
            'url_pattern': f'https://{{url-id}}.lambda-url.{region}.on.aws',
            'enumeration_methods': {
                'github_search': 'Search for ".lambda-url." in code repositories',
                'dns_enum': f'Enumerate *.lambda-url.{region}.on.aws subdomains',
                'web_analysis': 'Check JavaScript/HTML for Lambda URL references',
                'aws_cli': 'aws lambda list-function-url-configs (requires auth)'
            },
            'tools': [
                'github-search',
                'subfinder',
                'httpx',
                'trufflehog'
            ],
            'note': 'Lambda URLs are unique per function and cannot be brute-forced'
        }
    
    def format_tree(self, data: Dict[str, Any], data_type: str = 'versioning') -> str:
        """Format AWS advanced results as tree"""
        lines = []
        
        if data_type == 'versioning':
            bucket = data.get('bucket', 'Unknown')
            lines.append(f"🪣 S3 Bucket Versioning: {bucket}")
            lines.append("=" * 60)
            lines.append("")
            
            if not data.get('accessible'):
                lines.append("└─ Versioning info not accessible")
                return "\n".join(lines)
            
            versioning = data.get('versioning', 'Unknown')
            if versioning == 'Enabled':
                lines.append("├─ 🔄 Versioning: ✅ Enabled")
            elif versioning == 'Suspended':
                lines.append("├─ 🔄 Versioning: ⚠️  Suspended")
            else:
                lines.append("├─ 🔄 Versioning: ❌ Disabled")
            
            mfa = data.get('mfa_delete')
            if mfa:
                lines.append("├─ 🔐 MFA Delete: ✅ Enabled")
            
            lines.append("│")
            lines.append("└─ 💡 Best Practice: Enable versioning + MFA delete")
        
        elif data_type == 'cloudfront':
            domain = data.get('domain', 'Unknown')
            lines.append(f"☁️ CloudFront Detection: {domain}")
            lines.append("=" * 60)
            lines.append("")
            
            uses_cf = data.get('uses_cloudfront', False)
            if uses_cf:
                lines.append("├─ ✅ Uses CloudFront")
                
                dist_domain = data.get('distribution_domain')
                if dist_domain:
                    lines.append(f"├─ 🌐 Distribution: {dist_domain}")
                
                # Show CF headers
                headers = data.get('headers', {})
                cf_headers = {k: v for k, v in headers.items() if 'cf-' in k.lower() or k == 'Via'}
                if cf_headers:
                    lines.append("└─ 📋 CloudFront Headers:")
                    for key, value in list(cf_headers.items())[:3]:
                        lines.append(f"   └─ {key}: {value[:50]}")
            else:
                lines.append("└─ ❌ Not using CloudFront")
        
        return "\n".join(lines)


__all__ = ['AWSTools']
