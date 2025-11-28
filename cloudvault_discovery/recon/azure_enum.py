"""
Azure Blob Enumeration
Azure Storage account and blob discovery
"""

import aiohttp
import asyncio
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class AzureBlobRecon:
    """Azure blob storage reconnaissance"""
    
    # Common Azure storage patterns
    COMMON_PATTERNS = [
        '{company}',
        '{company}backup',
        '{company}data',
        '{company}prod',
        '{company}dev',
        '{company}test',
        '{company}assets',
        '{company}static',
        '{company}media',
        '{company}files',
        '{company}logs',
        '{company}storage',
        '{company}blob',
        '{company}sa',  # storage account
        '{company}stg',
        'backup{company}',
        'prod{company}',
        'dev{company}',
        'test{company}',
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
    
    def generate_storage_names(self, company: str) -> List[str]:
        """Generate potential Azure storage account names"""
        accounts = set()
        # Azure storage names: lowercase, no hyphens, 3-24 chars
        company_clean = company.lower().replace(' ', '').replace('-', '').replace('_', '')
        
        for pattern in self.COMMON_PATTERNS:
            account = pattern.format(company=company_clean)
            # Azure storage name restrictions
            if 3 <= len(account) <= 24 and account.isalnum():
                accounts.add(account)
        
        return list(accounts)
    
    async def check_storage_account(self, account_name: str) -> Dict[str, Any]:
        """Check if Azure storage account exists"""
        result = {
            'account_name': account_name,
            'exists': False,
            'accessible': False,
            'url': None,
            'permissions': [],
            'containers': []
        }
        
        url = f"https://{account_name}.blob.core.windows.net/"
        
        try:
            async with self.session.head(url, allow_redirects=False, ssl=False) as response:
                if response.status in [200, 400, 403]:  # 400 = exists but no container
                    result['exists'] = True
                    result['accessible'] = response.status == 200
                    result['url'] = url
                    
                    # Test permissions if exists
                    if result['exists']:
                        perms = await self._test_permissions(account_name, url)
                        result['permissions'] = perms
                        
                        # Try to list containers if accessible
                        if result['accessible']:
                            containers = await self._list_containers(account_name, url)
                            result['containers'] = containers
                    
        except asyncio.TimeoutError:
            logger.debug(f"Timeout checking Azure storage: {account_name}")
        except Exception as e:
            logger.debug(f"Error checking Azure storage {account_name}: {e}")
        
        return result
    
    async def _test_permissions(self, account_name: str, url: str) -> List[str]:
        """Test Azure storage permissions"""
        permissions = []
        
        # Test LIST containers
        try:
            async with self.session.get(f"{url}?comp=list", ssl=False) as response:
                if response.status == 200:
                    permissions.append('LIST_CONTAINERS')
                    permissions.append('READ')
        except:
            pass
        
        # Test READ blob
        try:
            async with self.session.get(url, ssl=False) as response:
                if response.status == 200:
                    if 'READ' not in permissions:
                        permissions.append('READ')
        except:
            pass
        
        # Test WRITE (check if we can create container)
        try:
            test_container = f"{url}test-container?restype=container"
            async with self.session.put(test_container, ssl=False) as response:
                if response.status in [200, 201, 409]:  # 409 = already exists
                    permissions.append('WRITE')
        except:
            pass
        
        return list(set(permissions))
    
    async def _list_containers(self, account_name: str, url: str) -> List[str]:
        """List containers in storage account"""
        containers = []
        
        try:
            async with self.session.get(f"{url}?comp=list", ssl=False) as response:
                if response.status == 200:
                    # Parse XML response to get container names
                    text = await response.text()
                    # Simple regex to extract container names
                    import re
                    matches = re.findall(r'<Name>(.*?)</Name>', text)
                    containers = matches[:5]  # Limit to first 5
        except:
            pass
        
        return containers
    
    async def enumerate_storage_accounts(self, company: str) -> List[Dict[str, Any]]:
        """Enumerate Azure storage accounts"""
        account_names = self.generate_storage_names(company)
        logger.info(f"Checking {len(account_names)} Azure storage candidates")
        
        tasks = [self.check_storage_account(name) for name in account_names]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        found = []
        for result in results:
            if isinstance(result, dict) and result.get('exists'):
                found.append(result)
        
        return found
    
    def format_tree(self, accounts: List[Dict[str, Any]]) -> str:
        """Format results as tree"""
        lines = []
        lines.append("🔷 Azure Blob Enumeration Results")
        lines.append("=" * 60)
        lines.append("")
        
        if not accounts:
            lines.append("└─ No storage accounts found")
            return "\n".join(lines)
        
        for i, account in enumerate(accounts):
            is_last = (i == len(accounts) - 1)
            prefix = "└─" if is_last else "├─"
            detail_prefix = "   " if is_last else "│  "
            
            name = account.get('account_name', 'Unknown')
            accessible = account.get('accessible', False)
            url = account.get('url', 'N/A')
            permissions = account.get('permissions', [])
            containers = account.get('containers', [])
            
            status_icon = "🔓" if accessible else "🔒"
            status_text = "Public" if accessible else "Private"
            
            lines.append(f"{prefix} {status_icon} {name} ({status_text})")
            
            # Show permissions
            if permissions:
                perms_str = ", ".join(permissions)
                severity = "🔴" if 'WRITE' in permissions else "🟡"
                lines.append(f"{detail_prefix}├─ {severity} Permissions: {perms_str}")
            
            # Show containers
            if containers:
                container_str = ", ".join(containers)
                lines.append(f"{detail_prefix}├─ 📦 Containers: {container_str}")
            
            lines.append(f"{detail_prefix}└─ 🔗 {url}")
            
            if not is_last:
                lines.append("│")
        
        return "\n".join(lines)


__all__ = ['AzureBlobRecon']
