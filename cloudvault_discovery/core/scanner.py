"""
Bucket Scanner
Multi-provider bucket existence and permission checking
"""

import asyncio
import aiohttp
import logging
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class BucketScanner:
    """Scan buckets across multiple cloud providers"""
    
    def __init__(self, 
                 aws_enabled: bool = True,
                 gcp_enabled: bool = True,
                 azure_enabled: bool = True,
                 timeout: int = 5):
        """
        Initialize bucket scanner.
        
        Args:
            aws_enabled: Enable AWS S3 scanning
            gcp_enabled: Enable GCP Storage scanning
            azure_enabled: Enable Azure Blob scanning
            timeout: Request timeout in seconds
        """
        self.aws_enabled = aws_enabled
        self.gcp_enabled = gcp_enabled
        self.azure_enabled = azure_enabled
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
    
    async def scan_bucket(self, bucket_name: str) -> Optional[Dict[str, Any]]:
        """
        Scan a bucket across all enabled providers.
        
        Args:
            bucket_name: Bucket name to scan
            
        Returns:
            Finding dict if bucket exists, None otherwise
        """
        tasks = []
        
        if self.aws_enabled:
            tasks.append(self._check_aws_s3(bucket_name))
        
        if self.gcp_enabled:
            tasks.append(self._check_gcp_storage(bucket_name))
        
        if self.azure_enabled:
            tasks.append(self._check_azure_blob(bucket_name))
        
        # Run all checks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Return first successful result
        for result in results:
            if isinstance(result, dict) and result.get('exists'):
                return result
        
        return None
    
    async def _check_aws_s3(self, bucket_name: str) -> Dict[str, Any]:
        """Check AWS S3 bucket"""
        url = f"https://{bucket_name}.s3.amazonaws.com/"
        
        try:
            async with self.session.head(url, allow_redirects=True) as response:
                exists = response.status in [200, 301, 302, 403]
                is_public = response.status in [200, 301, 302]
                
                if exists:
                    return {
                        'exists': True,
                        'provider': 'aws',
                        'bucket_name': bucket_name,
                        'bucket_url': url,
                        'is_public': is_public,
                        'status_code': response.status,
                        'discovered_at': datetime.utcnow().isoformat() + 'Z',
                        'permissions': ['READ'] if is_public else [],
                        'severity': 'CRITICAL' if is_public else 'INFO'
                    }
                    
        except asyncio.TimeoutError:
            logger.debug(f"Timeout checking AWS S3: {bucket_name}")
        except Exception as e:
            logger.debug(f"Error checking AWS S3 {bucket_name}: {e}")
        
        return {'exists': False}
    
    async def _check_gcp_storage(self, bucket_name: str) -> Dict[str, Any]:
        """Check GCP Storage bucket"""
        url = f"https://storage.googleapis.com/{bucket_name}/"
        
        try:
            async with self.session.head(url, allow_redirects=True) as response:
                exists = response.status in [200, 403, 404]
                is_public = response.status == 200
                
                if exists and response.status != 404:
                    return {
                        'exists': True,
                        'provider': 'gcp',
                        'bucket_name': bucket_name,
                        'bucket_url': url,
                        'is_public': is_public,
                        'status_code': response.status,
                        'discovered_at': datetime.utcnow().isoformat() + 'Z',
                        'permissions': ['READ'] if is_public else [],
                        'severity': 'CRITICAL' if is_public else 'INFO'
                    }
                    
        except asyncio.TimeoutError:
            logger.debug(f"Timeout checking GCP Storage: {bucket_name}")
        except Exception as e:
            logger.debug(f"Error checking GCP Storage {bucket_name}: {e}")
        
        return {'exists': False}
    
    async def _check_azure_blob(self, bucket_name: str) -> Dict[str, Any]:
        """Check Azure Blob Storage"""
        # Try common Azure patterns
        url = f"https://{bucket_name}.blob.core.windows.net/"
        
        try:
            async with self.session.head(url, allow_redirects=True) as response:
                exists = response.status in [200, 400, 403, 404]
                is_public = response.status == 200
                
                if exists and response.status != 404:
                    return {
                        'exists': True,
                        'provider': 'azure',
                        'bucket_name': bucket_name,
                        'bucket_url': url,
                        'is_public': is_public,
                        'status_code': response.status,
                        'discovered_at': datetime.utcnow().isoformat() + 'Z',
                        'permissions': ['READ'] if is_public else [],
                        'severity': 'CRITICAL' if is_public else 'INFO'
                    }
                    
        except asyncio.TimeoutError:
            logger.debug(f"Timeout checking Azure Blob: {bucket_name}")
        except Exception as e:
            logger.debug(f"Error checking Azure Blob {bucket_name}: {e}")
        
        return {'exists': False}


__all__ = ['BucketScanner']
