"""
Metadata Endpoint Checker
Check for accessible cloud metadata endpoints
"""

import aiohttp
import asyncio
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class MetadataEndpointChecker:
    """Check cloud metadata endpoints"""
    
    ENDPOINTS = {
        'aws_imds_v1': {
            'url': 'http://169.254.169.254/latest/meta-data/',
            'provider': 'aws',
            'version': 'IMDSv1'
        },
        'aws_imds_v2_token': {
            'url': 'http://169.254.169.254/latest/api/token',
            'provider': 'aws',
            'version': 'IMDSv2',
            'method': 'PUT',
            'headers': {'X-aws-ec2-metadata-token-ttl-seconds': '21600'}
        },
        'aws_imds_v2_data': {
            'url': 'http://169.254.169.254/latest/meta-data/',
            'provider': 'aws',
            'version': 'IMDSv2',
            'requires_token': True
        },
        'gcp_metadata': {
            'url': 'http://metadata.google.internal/computeMetadata/v1/',
            'provider': 'gcp',
            'headers': {'Metadata-Flavor': 'Google'}
        },
        'azure_metadata': {
            'url': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            'provider': 'azure',
            'headers': {'Metadata': 'true'}
        },
        'oracle_metadata': {
            'url': 'http://169.254.169.254/opc/v1/instance/',
            'provider': 'oracle',
            'headers': {'Authorization': 'Bearer Oracle'}
        }
    }
    
    def __init__(self, timeout: int = 2):
        """
        Initialize checker.
        
        Args:
            timeout: Request timeout (shorter for metadata)
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
    
    async def check_endpoint(self, endpoint_key: str) -> Optional[Dict[str, Any]]:
        """
        Check a metadata endpoint.
        
        Args:
            endpoint_key: Key from ENDPOINTS dict
            
        Returns:
            Check result
        """
        endpoint = self.ENDPOINTS.get(endpoint_key)
        if not endpoint:
            return None
        
        url = endpoint['url']
        method = endpoint.get('method', 'GET')
        headers = endpoint.get('headers', {})
        
        try:
            if method == 'PUT':
                async with self.session.put(url, headers=headers) as response:
                    accessible = response.status == 200
                    token = await response.text() if accessible else None
                    
                    return {
                        'endpoint': endpoint_key,
                        'provider': endpoint['provider'],
                        'version': endpoint.get('version'),
                        'url': url,
                        'accessible': accessible,
                        'status': response.status,
                        'token': token
                    }
            else:
                async with self.session.get(url, headers=headers) as response:
                    accessible = response.status == 200
                    data = await response.text() if accessible else None
                    
                    return {
                        'endpoint': endpoint_key,
                        'provider': endpoint['provider'],
                        'version': endpoint.get('version'),
                        'url': url,
                        'accessible': accessible,
                        'status': response.status,
                        'preview': data[:200] if data else None
                    }
        except asyncio.TimeoutError:
            logger.debug(f"Timeout checking {endpoint_key}")
        except Exception as e:
            logger.debug(f"Error checking {endpoint_key}: {e}")
        
        return None
    
    async def check_all(self) -> List[Dict[str, Any]]:
        """
        Check all metadata endpoints.
        
        Returns:
            List of results
        """
        tasks = [self.check_endpoint(key) for key in self.ENDPOINTS.keys()]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return [r for r in results if isinstance(r, dict) and r]
    
    def format_tree(self, results: List[Dict[str, Any]]) -> str:
        """Format results as tree"""
        lines = []
        lines.append("🔐 Metadata Endpoint Check")
        lines.append("=" * 60)
        lines.append("")
        
        accessible = [r for r in results if r.get('accessible')]
        inaccessible = [r for r in results if not r.get('accessible')]
        
        if accessible:
            lines.append("├─ ⚠️  ACCESSIBLE Endpoints:")
            for i, result in enumerate(accessible):
                is_last = (i == len(accessible) - 1)
                prefix = "│  └─" if is_last else "│  ├─"
                detail_prefix = "│     " if is_last else "│  │  "
                
                provider = result.get('provider', 'unknown').upper()
                version = result.get('version', '')
                url = result.get('url', 'N/A')
                
                label = f"{provider} {version}".strip()
                lines.append(f"{prefix} {label}")
                lines.append(f"{detail_prefix}└─ {url}")
            
            lines.append("│")
        
        if inaccessible:
            lines.append("└─ ✅ Protected Endpoints:")
            for i, result in enumerate(inaccessible):
                is_last = (i == len(inaccessible) - 1)
                prefix = "   └─" if is_last else "   ├─"
                
                provider = result.get('provider', 'unknown').upper()
                version = result.get('version', '')
                
                label = f"{provider} {version}".strip()
                lines.append(f"{prefix} {label}")
        
        if not accessible and not inaccessible:
            lines.append("└─ No endpoints checked")
        
        return "\n".join(lines)


__all__ = ['MetadataEndpointChecker']
