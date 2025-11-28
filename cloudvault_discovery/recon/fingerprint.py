"""
Cloud Provider Fingerprinting
Detect cloud providers, WAF, CDN, and infrastructure
"""

import aiohttp
import asyncio
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class CloudFingerprinter:
    """Fingerprint cloud infrastructure"""
    
    # Cloud provider signatures
    SIGNATURES = {
        'aws': {
            'headers': ['x-amz-request-id', 'x-amz-id-2', 'x-amz-cf-id'],
            'domains': ['amazonaws.com', 'cloudfront.net', 's3.amazonaws.com'],
            'servers': ['AmazonS3', 'CloudFront']
        },
        'gcp': {
            'headers': ['x-goog-', 'x-guploader-uploadid'],
            'domains': ['googleapis.com', 'googleusercontent.com', 'gcp.gvt2.com'],
            'servers': ['Google Frontend', 'gws']
        },
        'azure': {
            'headers': ['x-ms-', 'x-azure-'],
            'domains': ['windows.net', 'azure.com', 'azurewebsites.net'],
            'servers': ['Microsoft-IIS', 'Azure']
        },
        'cloudflare': {
            'headers': ['cf-ray', 'cf-cache-status', 'cf-request-id'],
            'servers': ['cloudflare']
        },
        'fastly': {
            'headers': ['x-served-by', 'x-cache', 'fastly-'],
            'servers': ['Varnish']
        },
        'akamai': {
            'headers': ['x-akamai-', 'akamai-'],
            'servers': []
        }
    }
    
    def __init__(self, timeout: int = 5):
        """
        Initialize fingerprinter.
        
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
    
    async def fingerprint(self, url: str) -> Dict[str, Any]:
        """
        Fingerprint a URL.
        
        Args:
            url: Target URL
            
        Returns:
            Fingerprint results
        """
        result = {
            'url': url,
            'providers': [],
            'waf': None,
            'cdn': None,
            'server': None,
            'headers': {},
            'ssl': {}
        }
        
        try:
            async with self.session.get(url, allow_redirects=True, ssl=False) as response:
                # Collect headers
                result['headers'] = dict(response.headers)
                result['status_code'] = response.status
                
                # Server header
                server = response.headers.get('Server', '')
                result['server'] = server
                
                # Detect providers
                detected = self._detect_providers(response.headers, url, server)
                result['providers'] = detected['providers']
                result['waf'] = detected.get('waf')
                result['cdn'] = detected.get('cdn')
                
                # SSL/TLS info
                if response.url.scheme == 'https':
                    result['ssl']['enabled'] = True
                    result['ssl']['certificate'] = self._extract_ssl_info(response)
                
        except asyncio.TimeoutError:
            logger.debug(f"Timeout fingerprinting: {url}")
        except Exception as e:
            logger.debug(f"Error fingerprinting {url}: {e}")
        
        return result
    
    def _detect_providers(self, headers: Dict, url: str, server: str) -> Dict[str, Any]:
        """Detect cloud providers and services"""
        detected = {
            'providers': [],
            'waf': None,
            'cdn': None
        }
        
        # Convert headers to lowercase for comparison
        headers_lower = {k.lower(): v for k, v in headers.items()}
        url_lower = url.lower()
        server_lower = server.lower()
        
        # Check each provider
        for provider, sigs in self.SIGNATURES.items():
            found = False
            
            # Header-based detection
            for header_sig in sigs.get('headers', []):
                for header_name in headers_lower.keys():
                    if header_sig.lower() in header_name:
                        found = True
                        if provider in ['cloudflare', 'fastly', 'akamai']:
                            detected['cdn'] = provider
                        else:
                            if provider not in detected['providers']:
                                detected['providers'].append(provider)
                        break
                if found:
                    break
            
            # Domain-based detection
            if not found:
                for domain in sigs.get('domains', []):
                    if domain.lower() in url_lower:
                        if provider not in detected['providers']:
                            detected['providers'].append(provider)
                        found = True
                        break
            
            # Server header detection
            if not found and server_lower:
                for server_sig in sigs.get('servers', []):
                    if server_sig.lower() in server_lower:
                        if provider in ['cloudflare', 'fastly']:
                            detected['cdn'] = provider
                        elif provider not in detected['providers']:
                            detected['providers'].append(provider)
                        break
        
        # WAF detection
        waf_headers = {
            'x-sucuri-id': 'Sucuri',
            'x-waf-score': 'Generic WAF',
            'x-cdn': 'CDN WAF'
        }
        
        for header, waf_name in waf_headers.items():
            if header in headers_lower:
                detected['waf'] = waf_name
                break
        
        # CloudFront detection (AWS WAF)
        if 'x-amz-cf-id' in headers_lower or 'cloudfront' in server_lower:
            if not detected['waf']:
                detected['waf'] = 'AWS WAF / CloudFront'
            detected['cdn'] = 'cloudfront'
            if 'aws' not in detected['providers']:
                detected['providers'].append('aws')
        
        return detected
    
    def _extract_ssl_info(self, response) -> Dict[str, Any]:
        """Extract SSL certificate info"""
        ssl_info = {}
        
        try:
            # Extract from response if available
            if hasattr(response, 'connection') and hasattr(response.connection, 'transport'):
                transport = response.connection.transport
                if hasattr(transport, 'get_extra_info'):
                    peercert = transport.get_extra_info('peercert')
                    if peercert:
                        ssl_info['subject'] = dict(x[0] for x in peercert.get('subject', []))
                        ssl_info['issuer'] = dict(x[0] for x in peercert.get('issuer', []))
                        ssl_info['version'] = peercert.get('version')
        except Exception as e:
            logger.debug(f"Error extracting SSL info: {e}")
        
        return ssl_info
    
    def format_tree(self, fingerprints: List[Dict[str, Any]]) -> str:
        """Format fingerprints as tree"""
        lines = []
        lines.append("🔍 Cloud Fingerprint Results")
        lines.append("=" * 60)
        lines.append("")
        
        for i, fp in enumerate(fingerprints):
            is_last = (i == len(fingerprints) - 1)
            prefix = "└─" if is_last else "├─"
            detail_prefix = "   " if is_last else "│  "
            
            url = fp.get('url', 'Unknown')
            providers = fp.get('providers', [])
            cdn = fp.get('cdn')
            waf = fp.get('waf')
            server = fp.get('server', 'Unknown')
            status = fp.get('status_code', 'N/A')
            
            lines.append(f"{prefix} {url}")
            
            # Show status code
            if status != 'N/A':
                status_color = "✅" if status == 200 else "⚠️"
                lines.append(f"{detail_prefix}├─ {status_color} Status: {status}")
            
            # Show providers
            if providers:
                provider_str = ', '.join(p.upper() for p in providers)
                lines.append(f"{detail_prefix}├─ ☁️  Providers: {provider_str}")
            
            # Show CDN
            if cdn:
                lines.append(f"{detail_prefix}├─ 🌐 CDN: {cdn.title()}")
            
            # Show WAF
            if waf:
                lines.append(f"{detail_prefix}├─ 🛡️  WAF: {waf}")
            
            # Show server (last item)
            if server and server != 'Unknown':
                lines.append(f"{detail_prefix}└─ 🖥️  Server: {server}")
            elif not providers and not cdn and not waf:
                # No details detected
                lines.append(f"{detail_prefix}└─ ⚪ No cloud signatures detected")
            
            if not is_last:
                lines.append("│")
        
        return "\n".join(lines)


__all__ = ['CloudFingerprinter']
