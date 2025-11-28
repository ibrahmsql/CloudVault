"""
Cloud Service Discovery
Discover cloud services like API gateways, Lambda URLs, etc.
"""

import aiohttp
import asyncio
import logging
import re
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class CloudServiceDiscovery:
    """Discover cloud services and endpoints"""
    
    # Service patterns
    PATTERNS = {
        'api_gateway_aws': [
            r'https://[\w-]+\.execute-api\.[\w-]+\.amazonaws\.com',
            r'\.execute-api\.'
        ],
        'lambda_url': [
            r'https://[\w-]+\.lambda-url\.[\w-]+\.on\.aws',
            r'\.lambda-url\.'
        ],
        'apigee': [
            r'\.apigee\.net',
            r'\.apigee\.com'
        ],
        'azure_functions': [
            r'\.azurewebsites\.net/api/',
            r'\.azure-api\.net'
        ],
        'gcp_functions': [
            r'\.cloudfunctions\.net',
            r'\.run\.app'
        ],
        'cloudfront': [
            r'\.cloudfront\.net'
        ]
    }
    
    def __init__(self, timeout: int = 5):
        """
        Initialize discovery.
        
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
    
    def detect_service_type(self, url: str) -> List[str]:
        """
        Detect service types from URL.
        
        Args:
            url: Target URL
            
        Returns:
            List of detected service types
        """
        detected = []
        
        for service, patterns in self.PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    detected.append(service)
                    break
        
        return detected
    
    async def check_api_gateway(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Check if URL is an API Gateway.
        
        Args:
            url: Target URL
            
        Returns:
            API Gateway info
        """
        try:
            async with self.session.get(url) as response:
                headers = dict(response.headers)
                
                # Check for API Gateway signatures
                is_apigw = False
                provider = None
                
                if 'x-amzn-requestid' in headers or 'execute-api' in url:
                    is_apigw = True
                    provider = 'aws'
                elif 'x-apigee-' in str(headers).lower():
                    is_apigw = True
                    provider = 'apigee'
                elif 'azure-api' in url or 'azurewebsites.net/api' in url:
                    is_apigw = True
                    provider = 'azure'
                
                if is_apigw:
                    return {
                        'type': 'api_gateway',
                        'provider': provider,
                        'url': url,
                        'status': response.status,
                        'accessible': response.status != 403
                    }
        except Exception as e:
            logger.debug(f"Error checking API Gateway {url}: {e}")
        
        return None
    
    async def check_lambda_url(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Check if URL is a Lambda function URL.
        
        Args:
            url: Target URL
            
        Returns:
            Lambda info
        """
        if 'lambda-url' not in url and 'cloudfunctions' not in url and 'run.app' not in url:
            return None
        
        try:
            async with self.session.get(url) as response:
                provider = 'aws' if 'lambda-url' in url else 'gcp'
                
                return {
                    'type': 'serverless_function',
                    'provider': provider,
                    'url': url,
                    'status': response.status,
                    'accessible': response.status != 403
                }
        except Exception as e:
            logger.debug(f"Error checking Lambda URL {url}: {e}")
        
        return None
    
    def format_tree(self, results: List[Dict[str, Any]]) -> str:
        """Format results as tree"""
        lines = []
        lines.append("⚡ Cloud Service Discovery")
        lines.append("=" * 60)
        lines.append("")
        
        # Group by type
        by_type = {}
        for result in results:
            if not result:
                continue
            svc_type = result.get('type', 'unknown')
            if svc_type not in by_type:
                by_type[svc_type] = []
            by_type[svc_type].append(result)
        
        for i, (svc_type, items) in enumerate(by_type.items()):
            is_last_type = (i == len(by_type) - 1)
            type_prefix = "└─" if is_last_type else "├─"
            
            type_name = svc_type.replace('_', ' ').title()
            lines.append(f"{type_prefix} {type_name} ({len(items)})")
            
            for j, item in enumerate(items):
                is_last_item = (j == len(items) - 1)
                
                if is_last_type:
                    item_prefix = "   └─"
                    detail_prefix = "      "
                else:
                    item_prefix = "│  └─" if is_last_item else "│  ├─"
                    detail_prefix = "│     " if is_last_item else "│  │  "
                
                provider = item.get('provider', 'unknown').upper()
                url = item.get('url', 'N/A')
                accessible = "✅ Accessible" if item.get('accessible') else "🔒 Restricted"
                
                lines.append(f"{item_prefix} {provider}")
                lines.append(f"{detail_prefix}├─ 🔗 {url}")
                lines.append(f"{detail_prefix}└─ {accessible}")
            
            if not is_last_type:
                lines.append("│")
        
        return "\n".join(lines)


__all__ = ['CloudServiceDiscovery']
