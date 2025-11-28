"""
DNS Intelligence & Certificate Analysis
Advanced DNS reconnaissance and SSL/TLS certificate inspection
"""

import aiohttp
import asyncio
import logging
from typing import List, Dict, Any, Optional
import socket
from datetime import datetime
import ssl as ssl_module

logger = logging.getLogger(__name__)


class DNSIntelligence:
    """DNS intelligence gathering"""
    
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
    
    async def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """
        Comprehensive DNS analysis.
        
        Args:
            domain: Target domain
            
        Returns:
            DNS intelligence data
        """
        result = {
            'domain': domain,
            'cname': [],
            'txt': [],
            'mx': [],
            'cloud_providers': [],
            'certificate': None
        }
        
        # DNS lookups (non-async, but wrapped in executor)
        loop = asyncio.get_event_loop()
        
        try:
            # CNAME records
            try:
                cname = await loop.run_in_executor(None, self._get_cname, domain)
                if cname:
                    result['cname'] = cname
                    # Detect cloud providers from CNAME
                    providers = self._detect_cloud_from_cname(cname)
                    result['cloud_providers'].extend(providers)
            except:
                pass
            
            # TXT records  
            try:
                txt = await loop.run_in_executor(None, self._get_txt, domain)
                result['txt'] = txt
            except:
                pass
            
            # MX records
            try:
                mx = await loop.run_in_executor(None, self._get_mx, domain)
                result['mx'] = mx
            except:
                pass
            
            # Certificate analysis
            try:
                cert_info = await self._analyze_certificate(domain)
                result['certificate'] = cert_info
            except:
                pass
                
        except Exception as e:
            logger.debug(f"Error analyzing {domain}: {e}")
        
        return result
    
    def _get_cname(self, domain: str) -> List[str]:
        """Get CNAME records"""
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, 'CNAME')
            return [str(rdata.target).rstrip('.') for rdata in answers]
        except:
            # Fallback without dnspython
            try:
                # Try to get IP and check for CNAME
                info = socket.getaddrinfo(domain, None)
                return []
            except:
                return []
    
    def _get_txt(self, domain: str) -> List[str]:
        """Get TXT records"""
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, 'TXT')
            return [str(rdata).strip('"') for rdata in answers]
        except:
            return []
    
    def _get_mx(self, domain: str) -> List[Dict[str, Any]]:
        """Get MX records"""
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, 'MX')
            return [
                {
                    'priority': rdata.preference,
                    'server': str(rdata.exchange).rstrip('.')
                }
                for rdata in answers
            ]
        except:
            return []
    
    def _detect_cloud_from_cname(self, cnames: List[str]) -> List[str]:
        """Detect cloud providers from CNAME"""
        providers = set()
        
        cloud_patterns = {
            'aws': ['amazonaws.com', 'cloudfront.net', 'awsdns', 'elb.amazonaws.com'],
            'gcp': ['googlehosted.com', 'googleapis.com', 'goog', 'google.com'],
            'azure': ['azurewebsites.net', 'azure.com', 'windows.net', 'cloudapp.net'],
            'cloudflare': ['cloudflare', 'cloudflare.com'],
            'fastly': ['fastly.net'],
            'akamai': ['akamai.net', 'akamaiedge.net']
        }
        
        for cname in cnames:
            cname_lower = cname.lower()
            for provider, patterns in cloud_patterns.items():
                if any(pattern in cname_lower for pattern in patterns):
                    providers.add(provider)
        
        return sorted(list(providers))
    
    async def _analyze_certificate(self, domain: str) -> Dict[str, Any]:
        """Analyze SSL/TLS certificate"""
        cert_info = {
            'valid': False,
            'issuer': None,
            'subject': None,
            'sans': [],
            'not_before': None,
            'not_after': None,
            'expired': None
        }
        
        try:
            # Get certificate
            context = ssl_module.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl_module.CERT_NONE
            
            loop = asyncio.get_event_loop()
            cert = await loop.run_in_executor(
                None,
                self._get_cert,
                domain,
                context
            )
            
            if cert:
                cert_info['valid'] = True
                
                # Issuer
                issuer = dict(x[0] for x in cert.get('issuer', []))
                cert_info['issuer'] = issuer.get('organizationName', 'Unknown')
                
                # Subject
                subject = dict(x[0] for x in cert.get('subject', []))
                cert_info['subject'] = subject.get('commonName', domain)
                
                # SANs (Subject Alternative Names)
                sans = []
                for entry in cert.get('subjectAltName', []):
                    if entry[0] == 'DNS':
                        sans.append(entry[1])
                cert_info['sans'] = sans
                
                # Validity dates
                not_before = cert.get('notBefore')
                not_after = cert.get('notAfter')
                
                if not_after:
                    cert_info['not_after'] = not_after
                    # Check if expired
                    try:
                        expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        cert_info['expired'] = expiry < datetime.now()
                    except:
                        pass
                
        except Exception as e:
            logger.debug(f"Error analyzing certificate for {domain}: {e}")
        
        return cert_info
    
    def _get_cert(self, domain: str, context) -> Optional[Dict]:
        """Get SSL certificate (blocking)"""
        try:
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    return ssock.getpeercert()
        except:
            return None
    
    def format_tree(self, dns_data: Dict[str, Any]) -> str:
        """Format DNS intelligence as tree"""
        lines = []
        domain = dns_data.get('domain', 'Unknown')
        lines.append(f"🔍 DNS Intelligence: {domain}")
        lines.append("=" * 60)
        lines.append("")
        
        # CNAME
        cnames = dns_data.get('cname', [])
        if cnames:
            lines.append("├─ 🔗 CNAME Records:")
            for cname in cnames:
                lines.append(f"│  └─ {cname}")
        
        # Cloud providers detected
        providers = dns_data.get('cloud_providers', [])
        if providers:
            providers_str = ', '.join(p.upper() for p in providers)
            lines.append(f"├─ ☁️  Cloud Providers: {providers_str}")
        
        # TXT records
        txt = dns_data.get('txt', [])
        if txt:
            lines.append("├─ 📝 TXT Records:")
            for record in txt[:3]:  # Show first 3
                preview = record[:60] + '...' if len(record) > 60 else record
                lines.append(f"│  └─ {preview}")
        
        # MX records
        mx = dns_data.get('mx', [])
        if mx:
            lines.append("├─ 📧 MX Records:")
            for record in sorted(mx, key=lambda x: x['priority']):
                lines.append(f"│  └─ [{record['priority']}] {record['server']}")
        
        # Certificate
        cert = dns_data.get('certificate')
        if cert and cert.get('valid'):
            lines.append("├─ 🔐 SSL Certificate:")
            lines.append(f"│  ├─ Issuer: {cert.get('issuer', 'Unknown')}")
            lines.append(f"│  ├─ Subject: {cert.get('subject', 'Unknown')}")
            
            sans = cert.get('sans', [])
            if sans:
                lines.append(f"│  ├─ SANs: {len(sans)} domain(s)")
                for san in sans[:3]:
                    lines.append(f"│  │  └─ {san}")
            
            expired = cert.get('expired')
            if expired is not None:
                status = "❌ Expired" if expired else "✅ Valid"
                lines.append(f"│  └─ Status: {status}")
        
        return "\n".join(lines)


__all__ = ['DNSIntelligence']
