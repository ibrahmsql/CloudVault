"""
GCP Reconnaissance Tools
Service account key detection, versioning, and Cloud Functions enumeration
"""

import aiohttp
import asyncio
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class GCPTools:
    """GCP reconnaissance tools"""
    
    # Common SA key patterns in URLs/repos
    SA_KEY_PATTERNS = [
        r'"type":\s*"service_account"',
        r'"project_id":\s*"[\w-]+"',
        r'"private_key_id":\s*"[a-f0-9]+"',
        r'"client_email":\s*"[\w-]+@[\w-]+\.iam\.gserviceaccount\.com"'
    ]
    
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
    
    async def check_bucket_versioning(self, bucket_name: str) -> Dict[str, Any]:
        """
        Check GCS bucket versioning and lifecycle.
        
        Args:
            bucket_name: Bucket name
            
        Returns:
            Versioning and lifecycle info
        """
        result = {
            'bucket': bucket_name,
            'versioning': None,
            'lifecycle': None,
            'accessible': False
        }
        
        # Try to access bucket metadata
        url = f"https://storage.googleapis.com/storage/v1/b/{bucket_name}"
        
        try:
            async with self.session.get(url, ssl=False) as response:
                if response.status == 200:
                    data = await response.json()
                    result['accessible'] = True
                    
                    # Versioning
                    versioning = data.get('versioning', {})
                    result['versioning'] = versioning.get('enabled', False)
                    
                    # Lifecycle
                    lifecycle = data.get('lifecycle')
                    if lifecycle:
                        rules = lifecycle.get('rule', [])
                        result['lifecycle'] = {
                            'rules_count': len(rules),
                            'has_deletion': any(r.get('action', {}).get('type') == 'Delete' for r in rules)
                        }
                        
        except Exception as e:
            logger.debug(f"Error checking versioning for {bucket_name}: {e}")
        
        return result
    
    async def enumerate_cloud_functions(self, project_id: str, region: str = 'us-central1') -> List[Dict[str, Any]]:
        """
        Enumerate Cloud Functions.
        
        Public Cloud Functions can be discovered via:
        https://{region}-{project_id}.cloudfunctions.net/{function_name}
        
        Args:
            project_id: GCP project ID
            region: Region to check
            
        Returns:
            List of discovered functions
        """
        functions = []
        
        # Common function name patterns
        common_names = [
            'api', 'webhook', 'handler', 'process', 'upload', 'download',
            'function-1', 'http-function', 'trigger', 'callback', 'event',
            'data-processor', 'file-handler', 'notification', 'auth',
            'proxy', 'gateway', 'endpoint', 'service', 'worker'
        ]
        
        # Also check common HTTP methods as function names
        http_methods = ['get', 'post', 'put', 'delete', 'patch']
        all_names = common_names + http_methods
        
        for name in all_names[:15]:  # Limit to 15 to be respectful
            url = f"https://{region}-{project_id}.cloudfunctions.net/{name}"
            
            try:
                async with self.session.head(url, ssl=False, timeout=aiohttp.ClientTimeout(total=3)) as response:
                    # Function exists if we get any response other than connection error
                    if response.status in [200, 403, 401, 405]:
                        functions.append({
                            'name': name,
                            'url': url,
                            'status': response.status,
                            'accessible': response.status == 200,
                            'region': region
                        })
            except:
                pass
        
        return functions
    
    async def check_sa_key_exposure(self, content: str) -> Dict[str, Any]:
        """
        Check for exposed service account keys.
        
        Args:
            content: Content to scan (file, response, etc.)
            
        Returns:
            Detection results
        """
        import re
        
        result = {
            'exposed': False,
            'findings': []
        }
        
        # Check for SA key patterns
        for pattern in self.SA_KEY_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                result['exposed'] = True
                result['findings'].append({
                    'pattern': pattern,
                    'matches': len(matches)
                })
        
        # Check for full JSON structure
        if '"type": "service_account"' in content:
            result['exposed'] = True
            result['findings'].append({
                'type': 'Full service account key detected',
                'severity': 'CRITICAL'
            })
        
        return result
    
    def format_tree(self, data: Dict[str, Any], data_type: str = 'versioning') -> str:
        """Format GCP advanced results as tree"""
        lines = []
        
        if data_type == 'versioning':
            bucket = data.get('bucket', 'Unknown')
            lines.append(f"🪣 GCP Bucket Details: {bucket}")
            lines.append("=" * 60)
            lines.append("")
            
            if not data.get('accessible'):
                lines.append("└─ Bucket not accessible")
                return "\n".join(lines)
            
            # Versioning
            versioning = data.get('versioning')
            if versioning is not None:
                status = "✅ Enabled" if versioning else "❌ Disabled"
                lines.append(f"├─ 🔄 Versioning: {status}")
            
            # Lifecycle
            lifecycle = data.get('lifecycle')
            if lifecycle:
                lines.append(f"├─ ⏱️  Lifecycle Rules: {lifecycle['rules_count']}")
                if lifecycle.get('has_deletion'):
                    lines.append("│  └─ ⚠️  Auto-deletion configured")
            
            lines.append("│")
            lines.append("└─ 💡 Note: Versioning helps prevent data loss")
        
        elif data_type == 'functions':
            lines.append("☁️ GCP Cloud Functions Enumeration")
            lines.append("=" * 60)
            lines.append("")
            
            functions = data.get('functions', [])
            if not functions:
                lines.append("└─ No public functions found")
                return "\n".join(lines)
            
            for i, func in enumerate(functions):
                is_last = (i == len(functions) - 1)
                prefix = "└─" if is_last else "├─"
                
                name = func.get('name')
                url = func.get('url')
                accessible = func.get('accessible', False)
                status_icon = "🔓" if accessible else "🔒"
                
                lines.append(f"{prefix} {status_icon} {name}")
                if not is_last:
                    lines.append(f"│  └─ {url}")
                else:
                    lines.append(f"   └─ {url}")
        
        return "\n".join(lines)


__all__ = ['GCPTools']
