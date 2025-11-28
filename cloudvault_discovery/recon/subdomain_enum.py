"""
Subdomain Enumeration & Certificate Transparency
Advanced subdomain discovery using multiple techniques
"""

import aiohttp
import asyncio
import logging
from typing import List, Dict, Any, Set
import re

logger = logging.getLogger(__name__)


class SubdomainEnumerator:
    """Advanced subdomain enumeration"""
    
    def __init__(self, timeout: int = 10):
        """
        Initialize subdomain enumerator.
        
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
    
    async def enum_crt_sh(self, domain: str) -> List[str]:
        """
        Enumerate subdomains via crt.sh (Certificate Transparency).
        
        Args:
            domain: Target domain
            
        Returns:
            List of discovered subdomains
        """
        subdomains = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        try:
            async with self.session.get(url, ssl=False) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        # Split by newlines (crt.sh returns multiple SANs)
                        for subdomain in name_value.split('\n'):
                            subdomain = subdomain.strip().lower()
                            # Remove wildcards
                            subdomain = subdomain.replace('*.', '')
                            # Only keep valid subdomains
                            if subdomain and domain in subdomain:
                                subdomains.add(subdomain)
        except Exception as e:
            logger.debug(f"Error querying crt.sh for {domain}: {e}")
        
        return sorted(list(subdomains))
    
    async def enum_dns_brute(self, domain: str, wordlist: List[str] = None) -> List[str]:
        """
        Brute-force subdomains via DNS.
        
        Args:
            domain: Target domain
            wordlist: List of subdomain prefixes to try
            
        Returns:
            List of valid subdomains
        """
        if not wordlist:
            # Default common subdomain list
            wordlist = [
                'www', 'mail', 'ftp', 'api', 'dev', 'staging', 'test',
                'admin', 'portal', 'app', 'cdn', 'static', 'assets',
                'blog', 'shop', 'store', 'vpn', 'remote', 'ssh',
                'git', 'gitlab', 'jenkins', 'ci', 'prod', 'production',
                'backup', 'db', 'database', 'mysql', 'postgres', 'redis',
                's3', 'storage', 'files', 'upload', 'download', 'media'
            ]
        
        valid_subdomains = []
        
        # Limit to prevent overwhelming DNS
        tasks = []
        for prefix in wordlist[:50]:  # Limit to 50 to be respectful
            subdomain = f"{prefix}.{domain}"
            tasks.append(self._check_dns(subdomain))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, result in enumerate(results):
            if result is True:
                valid_subdomains.append(f"{wordlist[i]}.{domain}")
        
        return sorted(valid_subdomains)
    
    async def _check_dns(self, subdomain: str) -> bool:
        """Check if subdomain resolves"""
        try:
            # Try to connect to see if it resolves
            async with self.session.head(f"http://{subdomain}", ssl=False, timeout=aiohttp.ClientTimeout(total=3)) as response:
                return True
        except:
            return False
    
    async def generate_permutations(self, domain: str, known_subs: List[str] = None) -> List[str]:
        """
        Generate subdomain permutations.
        
        Args:
            domain: Base domain
            known_subs: Known subdomains to permute
            
        Returns:
            List of permutation candidates
        """
        if not known_subs:
            known_subs = ['api', 'dev', 'test', 'staging']
        
        permutations = set()
        base = domain.split('.')[0]
        
        # Common patterns
        patterns = [
            '{sub}-{env}',
            '{env}-{sub}',
            '{sub}{env}',
            '{sub}.{env}',
            '{sub}-backup',
            '{sub}-old',
            '{sub}2',
            '{sub}-v2',
            'new-{sub}',
            '{sub}-new'
        ]
        
        environments = ['prod', 'dev', 'test', 'staging', 'qa', 'uat']
        
        for sub in known_subs:
            for env in environments:
                for pattern in patterns:
                    perm = pattern.format(sub=sub, env=env)
                    permutations.add(f"{perm}.{domain}")
        
        return sorted(list(permutations))[:100]  # Limit to 100
    
    def format_tree(self, domain: str, subdomains: List[str], method: str = "") -> str:
        """Format subdomain results as tree"""
        lines = []
        lines.append(f"🔍 Subdomain Enumeration: {domain}")
        if method:
            lines.append(f"   Method: {method}")
        lines.append("=" * 60)
        lines.append("")
        
        if not subdomains:
            lines.append("└─ No subdomains found")
            return "\n".join(lines)
        
        lines.append(f"Found {len(subdomains)} subdomain(s):")
        lines.append("")
        
        for i, subdomain in enumerate(subdomains[:20]):  # Show first 20
            is_last = (i == len(subdomains[:20]) - 1)
            prefix = "└─" if is_last else "├─"
            lines.append(f"{prefix} {subdomain}")
        
        if len(subdomains) > 20:
            lines.append(f"\n... and {len(subdomains) - 20} more")
        
        return "\n".join(lines)


__all__ = ['SubdomainEnumerator']
