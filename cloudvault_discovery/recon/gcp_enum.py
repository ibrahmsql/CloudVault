"""
GCP Bucket Enumeration
Google Cloud Storage bucket discovery
"""

import aiohttp
import asyncio
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class GCPBucketRecon:
    """GCP bucket reconnaissance"""
    
    # Common GCP bucket patterns
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
        '{company}-files',
        '{company}-uploads',
        '{company}-logs',
        '{company}-archive',
        '{company}-db',
        '{company}-database',
        '{company}-app',
        '{company}-api',
        '{company}-web',
        '{company}-cdn',
        'backup-{company}',
        'prod-{company}',
        'dev-{company}',
        'test-{company}',
        '{company}.appspot.com',
        '{company}-appengine',
    ]
    
    def __init__(self, timeout: int = 3):
        self.timeout = timeout
        self.session = None
        
    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(timeout=timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def generate_bucket_names(self, company: str) -> List[str]:
        """Generate potential GCS bucket names"""
        buckets = set()
        company_clean = company.lower().replace(' ', '-').replace('_', '-')
        
        for pattern in self.COMMON_PATTERNS:
            bucket = pattern.format(company=company_clean)
            buckets.add(bucket)
        
        return list(buckets)
    
    async def check_bucket(self, bucket_name: str) -> Dict[str, Any]:
        """Check if GCS bucket exists"""
        result = {
            'bucket_name': bucket_name,
            'exists': False,
            'accessible': False,
            'url': None,
            'permissions': []
        }
        
        url = f"https://storage.googleapis.com/{bucket_name}/"
        
        try:
            async with self.session.head(url, allow_redirects=False, ssl=False) as response:
                if response.status in [200, 301, 302, 403]:
                    result['exists'] = True
                    result['accessible'] = response.status in [200, 301, 302]
                    result['url'] = url
                    
                    # Test permissions if bucket exists
                    if result['exists']:
                        perms = await self._test_permissions(bucket_name, url)
                        result['permissions'] = perms
                    
        except asyncio.TimeoutError:
            logger.debug(f"Timeout checking GCS bucket: {bucket_name}")
        except Exception as e:
            logger.debug(f"Error checking GCS bucket {bucket_name}: {e}")
        
        return result
    
    async def _test_permissions(self, bucket_name: str, url: str) -> List[str]:
        """"Test GCS bucket permissions"""
        permissions = []
        
        # Test LIST permission
        try:
            async with self.session.get(url, ssl=False) as response:
                if response.status == 200:
                    permissions.append('LIST')
                    permissions.append('READ')
        except:
            pass
        
        # Test WRITE permission
        try:
            async with self.session.post(
                url,
                data=b"test",
                headers={'Content-Type': 'application/octet-stream'},
                ssl=False
            ) as response:
                if response.status in [200, 201, 204]:
                    permissions.append('WRITE')
        except:
            pass
        
        # Test IAM policy read
        try:
            async with self.session.get(f"{url}?iam", ssl=False) as response:
                if response.status == 200:
                    permissions.append('GET_IAM_POLICY')
        except:
            pass
        
        return list(set(permissions))
    
    async def enumerate_buckets(self, company: str) -> List[Dict[str, Any]]:
        """Enumerate GCS buckets"""
        bucket_names = self.generate_bucket_names(company)
        logger.info(f"Checking {len(bucket_names)} GCS bucket candidates")
        
        tasks = [self.check_bucket(name) for name in bucket_names]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        found = []
        for result in results:
            if isinstance(result, dict) and result.get('exists'):
                found.append(result)
        
        return found
    
    def format_tree(self, buckets: List[Dict[str, Any]]) -> str:
        """Format results as tree"""
        lines = []
        lines.append("☁️ GCP Bucket Enumeration Results")
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
            url = bucket.get('url', 'N/A')
            permissions = bucket.get('permissions', [])
            
            status_icon = "🔓" if accessible else "🔒"
            status_text = "Public" if accessible else "Private"
            
            lines.append(f"{prefix} {status_icon} {name} ({status_text})")
            
            # Show permissions
            if permissions:
                perms_str = ", ".join(permissions)
                severity = "🔴" if 'WRITE' in permissions else "🟡"
                lines.append(f"{detail_prefix}├─ {severity} Permissions: {perms_str}")
            
            lines.append(f"{detail_prefix}└─ 🔗 {url}")
            
            if not is_last:
                lines.append("│")
        
        return "\n".join(lines)


__all__ = ['GCPBucketRecon']
