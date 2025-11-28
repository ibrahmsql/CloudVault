"""
Azure AD Reconnaissance
Advanced Azure Active Directory enumeration and analysis
"""

import aiohttp
import asyncio
import logging
from typing import List, Dict, Any, Optional
import json

logger = logging.getLogger(__name__)


class AzureADRecon:
    """Azure AD reconnaissance and enumeration"""
    
    # Common tenant discovery endpoints
    TENANT_ENDPOINTS = [
        'https://login.microsoftonline.com/{domain}/.well-known/openid-configuration',
        'https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration'
    ]
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = None
        
    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(timeout=timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def enumerate_tenant(self, domain: str) -> Dict[str, Any]:
        """
        Enumerate Azure AD tenant information.
        
        Args:
            domain: Target domain
            
        Returns:
            Tenant details
        """
        result = {
            'domain': domain,
            'tenant_id': None,
            'tenant_name': None,
            'exists': False,
            'federation': None,
            'endpoints': {}
        }
        
        # Try OpenID configuration endpoint
        config_url = self.TENANT_ENDPOINTS[0].format(domain=domain)
        
        try:
            async with self.session.get(config_url, ssl=False) as response:
                if response.status == 200:
                    data = await response.json()
                    result['exists'] = True
                    
                    # Extract tenant ID from issuer
                    issuer = data.get('issuer', '')
                    if 'https://sts.windows.net/' in issuer:
                        tenant_id = issuer.split('/')[-2]
                        result['tenant_id'] = tenant_id
                    
                    # Store endpoints
                    result['endpoints'] = {
                        'authorization': data.get('authorization_endpoint'),
                        'token': data.get('token_endpoint'),
                        'userinfo': data.get('userinfo_endpoint')
                    }
                    
        except Exception as e:
            logger.debug(f"Error enumerating tenant {domain}: {e}")
        
        # Check for federation (ADFS/third-party)
        try:
            fed_url = f"https://login.microsoftonline.com/getuserrealm.srf?login=user@{domain}&json=1"
            async with self.session.get(fed_url, ssl=False) as response:
                if response.status == 200:
                    data = await response.json()
                    result['federation'] = {
                        'type': data.get('NameSpaceType'),
                        'domain_name': data.get('DomainName'),
                        'federation_brand': data.get('FederationBrandName')
                    }
        except:
            pass
        
        return result
    
    async def enumerate_users(self, domain: str, wordlist: List[str] = None) -> List[str]:
        """
        Enumerate valid users (username enumeration).
        
        Args:
            domain: Target domain
            wordlist: List of usernames to try
            
        Returns:
            List of valid usernames
        """
        if not wordlist:
            wordlist = ['admin', 'administrator', 'root', 'test', 'user']
        
        valid_users = []
        
        # Use timing-based user enumeration
        base_url = "https://login.microsoftonline.com/common/GetCredentialType"
        
        for username in wordlist[:20]:  # Limit to prevent abuse
            email = f"{username}@{domain}"
            
            try:
                payload = {
                    "username": email,
                    "isOtherIdpSupported": True,
                    "checkPhones": False,
                    "isRemoteNGCSupported": True,
                    "isCookieBannerShown": False,
                    "isFidoSupported": False,
                    "originalRequest": ""
                }
                
                async with self.session.post(
                    base_url,
                    json=payload,
                    ssl=False
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        # IfExistsResult: 0 = exists, 1 = doesn't exist
                        if data.get('IfExistsResult') == 0:
                            valid_users.append(email)
                
                # Rate limiting
                await asyncio.sleep(0.5)
                
            except Exception as e:
                logger.debug(f"Error checking user {email}: {e}")
        
        return valid_users
    
    async def enumerate_service_principals(self, tenant_id: str) -> List[Dict[str, Any]]:
        """
        Enumerate service principals (requires authentication).
        
        This method provides guidance on service principal enumeration.
        Actual enumeration requires one of the following:
        - Azure AD Admin credentials
        - Service Principal with Directory.Read.All permission
        - Global Reader role
        
        Args:
            tenant_id: Azure AD tenant ID
            
        Returns:
            Guidance for service principal enumeration
        """
        return [{
            'tenant_id': tenant_id,
            'enumeration_methods': {
                'graph_api': 'az ad sp list --all',
                'powershell': 'Get-AzADServicePrincipal',
                'rest_api': f'https://graph.microsoft.com/v1.0/servicePrincipals'
            },
            'required_permissions': [
                'Application.Read.All',
                'Directory.Read.All'
            ],
            'note': 'Run AzureHound or ROADtools for comprehensive enumeration'
        }]
    
    def format_tree(self, recon_data: Dict[str, Any]) -> str:
        """Format Azure AD recon results as tree"""
        lines = []
        domain = recon_data.get('domain', 'Unknown')
        lines.append(f"🔷 Azure AD Reconnaissance: {domain}")
        lines.append("=" * 60)
        lines.append("")
        
        exists = recon_data.get('exists', False)
        if not exists:
            lines.append("└─ Tenant not found or not using Azure AD")
            return "\n".join(lines)
        
        # Tenant info
        tenant_id = recon_data.get('tenant_id')
        if tenant_id:
            lines.append(f"├─ 🆔 Tenant ID: {tenant_id}")
        
        # Federation
        fed = recon_data.get('federation')
        if fed:
            fed_type = fed.get('type', 'Unknown')
            lines.append(f"├─ 🔐 Federation: {fed_type}")
            if fed.get('federation_brand'):
                lines.append(f"│  └─ Brand: {fed['federation_brand']}")
        
        # Endpoints
        endpoints = recon_data.get('endpoints', {})
        if endpoints:
            lines.append("├─ 🔗 Endpoints:")
            if endpoints.get('authorization'):
                lines.append(f"│  ├─ Authorization: {endpoints['authorization'][:50]}...")
            if endpoints.get('token'):
                lines.append(f"│  └─ Token: {endpoints['token'][:50]}...")
        
        # Note about BloodHound
        lines.append("│")
        lines.append("├─ 🐕 BloodHound Integration:")
        lines.append("│  └─ Run AzureHound for graph collection (requires auth)")
        
        # Note about Graph API
        lines.append("│")
        lines.append("└─ 📊 Graph API Enumeration:")
        lines.append("   └─ Requires authentication token")
        
        return "\n".join(lines)


__all__ = ['AzureADRecon']
