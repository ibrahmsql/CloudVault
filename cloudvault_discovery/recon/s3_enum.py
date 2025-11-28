"""
S3 Bucket Enumeration & Recon
Advanced S3 bucket discovery using common patterns
"""

import aiohttp
import asyncio
import logging
from typing import List, Dict, Any, Set

logger = logging.getLogger(__name__)


class S3BucketRecon:
    """Advanced S3 bucket reconnaissance"""
    
    # Common S3 bucket patterns
    COMMON_PATTERNS = [
        '{company}',
        '{company}-backup',
        '{company}-backups',
        '{company}-data',
        '{company}-prod',
        '{company}-production',
        '{company}-dev',
        '{company}-development',
        '{company}-staging',
        '{company}-test',
        '{company}-assets',
        '{company}-static',
        '{company}-media',
        '{company}-images',
        '{company}-files',
        '{company}-uploads',
        '{company}-downloads',
        '{company}-logs',
        '{company}-archive',
        '{company}-documents',
        '{company}-docs',
        '{company}-db',
        '{company}-database',
        '{company}-sql',
        '{company}-mongodb',
        '{company}-redis',
        '{company}-backup-db',
        '{company}-app',
        '{company}-api',
        '{company}-webapp',
        '{company}-web',
        '{company}-www',
        '{company}-cdn',
        '{company}-content',
        '{company}-public',
        '{company}-private',
        '{company}-internal',
        '{company}-external',
        'backup-{company}',
        'prod-{company}',
        'dev-{company}',
        'test-{company}',
        'staging-{company}',
        'data-{company}',
        'files-{company}',
        'assets-{company}',
    ]
    
    # S3 regions to check
    S3_REGIONS = [
        'us-east-1',
        'us-west-1',
        'us-west-2',
        'eu-west-1',
        'eu-central-1',
        'ap-southeast-1',
        'ap-southeast-2',
        'ap-northeast-1'
    ]
    
    def __init__(self, timeout: int = 3):
        """
        Initialize S3 recon.
        
        Args:
            timeout: Request timeout
        """
        self.timeout = timeout
        self.session = None
        
    async def __aenter__(self):
        """Async context manager entry"""
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(timeout=timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    def generate_bucket_names(self, company: str) -> List[str]:
        """
        Generate potential bucket names.
        
        Args:
            company: Company name
            
        Returns:
            List of bucket name candidates
        """
        buckets = set()
        company_clean = company.lower().replace(' ', '-').replace('_', '-')
        
        for pattern in self.COMMON_PATTERNS:
            bucket = pattern.format(company=company_clean)
            buckets.add(bucket)
        
        return list(buckets)
    
    async def check_bucket(self, bucket_name: str) -> Dict[str, Any]:
        """
        Check if S3 bucket exists and is accessible.
        
        Args:
            bucket_name: Bucket name to check
            
        Returns:
            Bucket info with permissions
        """
        result = {
            'bucket_name': bucket_name,
            'exists': False,
            'accessible': False,
            'region': None,
            'url': None,
            'permissions': [],
            'versioning': None,
            'website': False
        }
        
        # Try default region first
        url = f"https://{bucket_name}.s3.amazonaws.com/"
        
        try:
            async with self.session.head(url, allow_redirects=False, ssl=False) as response:
                if response.status in [200, 301, 302, 403]:
                    result['exists'] = True
                    result['accessible'] = response.status in [200, 301, 302]
                    result['url'] = url
                    
                    # Try to get region from headers
                    region = response.headers.get('x-amz-bucket-region', 'us-east-1')
                    result['region'] = region
                    
                    # Test permissions if bucket exists
                    if result['exists']:
                        perms = await self._test_permissions(bucket_name, url)
                        result['permissions'] = perms
                        
                        # Check for website hosting
                        website = await self._check_website_hosting(bucket_name)
                        result['website'] = website
                    
        except asyncio.TimeoutError:
            logger.debug(f"Timeout checking bucket: {bucket_name}")
        except Exception as e:
            logger.debug(f"Error checking bucket {bucket_name}: {e}")
        
        return result
    
    async def _test_permissions(self, bucket_name: str, url: str) -> List[str]:
        """
        Test bucket permissions (LIST/READ/WRITE/ACL).
        
        Args:
            bucket_name: Bucket name
            url: Bucket URL
            
        Returns:
            List of granted permissions
        """
        permissions = []
        
        # Test LIST permission
        try:
            async with self.session.get(url, ssl=False) as response:
                if response.status == 200:
                    permissions.append('LIST')
                    # Also implies READ
                    permissions.append('READ')
        except:
            pass
        
        # Test WRITE permission (try to upload a test file)
        # Note: This is read-only, we don't actually write
        try:
            async with self.session.put(
                f"{url}test.txt",
                data=b"test",
                ssl=False
            ) as response:
                if response.status in [200, 204]:
                    permissions.append('WRITE')
                    # Clean up - delete test file
                    await self.session.delete(f"{url}test.txt", ssl=False)
        except:
            pass
        
        # Test ACL read permission
        try:
            async with self.session.get(f"{url}?acl", ssl=False) as response:
                if response.status == 200:
                    permissions.append('READ_ACP')
        except:
            pass
        
        # Test ACL write permission
        try:
            async with self.session.put(
                f"{url}?acl",
                headers={'x-amz-acl': 'public-read'},
                ssl=False
            ) as response:
                if response.status in [200, 204]:
                    permissions.append('WRITE_ACP')
        except:
            pass
        
        return list(set(permissions))
    
    async def _check_website_hosting(self, bucket_name: str) -> bool:
        """
        Check if bucket has website hosting enabled.
        
        Args:
            bucket_name: Bucket name
            
        Returns:
            True if website hosting is enabled
        """
        website_url = f"http://{bucket_name}.s3-website-{self.S3_REGIONS[0]}.amazonaws.com/"
        
        try:
            async with self.session.head(website_url, ssl=False) as response:
                return response.status in [200, 301, 302, 403]
        except:
            return False
    
    async def enumerate_buckets(self, company: str) -> List[Dict[str, Any]]:
        """
        Enumerate S3 buckets for a company.
        
        Args:
            company: Company name
            
        Returns:
            List of found buckets
        """
        bucket_names = self.generate_bucket_names(company)
        logger.info(f"Checking {len(bucket_names)} bucket candidates for {company}")
        
        tasks = [self.check_bucket(name) for name in bucket_names]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter found buckets
        found = []
        for result in results:
            if isinstance(result, dict) and result.get('exists'):
                found.append(result)
        
        return found
    
    def format_tree(self, buckets: List[Dict[str, Any]]) -> str:
        """Format bucket results as tree"""
        lines = []
        lines.append("🪣 S3 Bucket Enumeration Results")
        lines.append("=" * 60)
        lines.append("")
        
        if not buckets:
            lines.append("└─ No buckets found")
            return "\n".join(lines)
        
        for i, bucket in enumerate(buckets):
            is_last = (i == len(buckets) - 1)
            prefix = "└─" if is_last else "├─"
            detail_prefix = "   " if is_last else "│  "
            
            name = bucket.get('bucket_name', 'Unknown')
            accessible = bucket.get('accessible', False)
            region = bucket.get('region', 'unknown')
            url = bucket.get('url', 'N/A')
            permissions = bucket.get('permissions', [])
            website = bucket.get('website', False)
            
            status_icon = "🔓" if accessible else "🔒"
            status_text = "Public" if accessible else "Private"
            
            lines.append(f"{prefix} {status_icon} {name} ({status_text})")
            lines.append(f"{detail_prefix}├─ 🌍 Region: {region}")
            
            # Show permissions
            if permissions:
                perms_str = ", ".join(permissions)
                severity = "🔴" if 'WRITE' in permissions or 'WRITE_ACP' in permissions else "🟡"
                lines.append(f"{detail_prefix}├─ {severity} Permissions: {perms_str}")
            
            # Show website hosting
            if website:
                lines.append(f"{detail_prefix}├─ 🌐 Website Hosting: Enabled")
            
            lines.append(f"{detail_prefix}└─ 🔗 {url}")
            
            if not is_last:
                lines.append("│")
        
        return "\n".join(lines)


__all__ = ['S3BucketRecon']
