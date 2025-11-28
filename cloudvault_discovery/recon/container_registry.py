"""
Container Registry Discovery
Scan for exposed container images
"""

import aiohttp
import asyncio
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class ContainerRegistryScanner:
    """Scan container registries for exposed images"""
    
    REGISTRIES = {
        'dockerhub': {
            'url': 'https://hub.docker.com/v2/repositories/{namespace}/',
            'public_url': 'https://hub.docker.com/v2/repositories/{namespace}/{repo}/tags'
        },
        'ecr_public': {
            'url': 'https://public.ecr.aws/v2/{namespace}/{repo}/tags/list'
        },
        'gcr': {
            'url': 'https://gcr.io/v2/{project}/{repo}/tags/list'
        },
        'acr': {
            'url': 'https://{registry}.azurecr.io/v2/{repo}/tags/list'
        }
    }
    
    def __init__(self, timeout: int = 5):
        """
        Initialize scanner.
        
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
    
    async def scan_dockerhub(self, namespace: str) -> Optional[Dict[str, Any]]:
        """
        Scan Docker Hub namespace.
        
        Args:
            namespace: Docker Hub namespace/username
            
        Returns:
            Found repositories
        """
        url = self.REGISTRIES['dockerhub']['url'].format(namespace=namespace)
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    repos = data.get('results', [])
                    
                    return {
                        'registry': 'dockerhub',
                        'namespace': namespace,
                        'repositories': [r.get('name') for r in repos],
                        'count': len(repos),
                        'url': f"https://hub.docker.com/u/{namespace}"
                    }
        except Exception as e:
            logger.debug(f"Error scanning Docker Hub {namespace}: {e}")
        
        return None
    
    async def scan_ecr_public(self, namespace: str, repo: str) -> Optional[Dict[str, Any]]:
        """
        Scan AWS ECR Public.
        
        Args:
            namespace: ECR namespace
            repo: Repository name
            
        Returns:
            Found images
        """
        url = self.REGISTRIES['ecr_public']['url'].format(namespace=namespace, repo=repo)
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    tags = data.get('tags', [])
                    
                    return {
                        'registry': 'ecr_public',
                        'namespace': namespace,
                        'repository': repo,
                        'tags': tags,
                        'count': len(tags),
                        'url': f"https://gallery.ecr.aws/{namespace}/{repo}"
                    }
        except Exception as e:
            logger.debug(f"Error scanning ECR Public {namespace}/{repo}: {e}")
        
        return None
    
    async def scan_gcr(self, project: str, repo: str) -> Optional[Dict[str, Any]]:
        """
        Scan Google Container Registry.
        
        Args:
            project: GCP project ID
            repo: Repository name
            
        Returns:
            Found images
        """
        url = self.REGISTRIES['gcr']['url'].format(project=project, repo=repo)
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    tags = data.get('tags', [])
                    
                    return {
                        'registry': 'gcr',
                        'project': project,
                        'repository': repo,
                        'tags': tags,
                        'count': len(tags),
                        'url': f"gcr.io/{project}/{repo}"
                    }
        except Exception as e:
            logger.debug(f"Error scanning GCR {project}/{repo}: {e}")
        
        return None
    
    async def scan_acr(self, registry: str, repo: str) -> Optional[Dict[str, Any]]:
        """
        Scan Azure Container Registry.
        
        Args:
            registry: ACR registry name
            repo: Repository name
            
        Returns:
            Found images
        """
        url = self.REGISTRIES['acr']['url'].format(registry=registry, repo=repo)
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    tags = data.get('tags', [])
                    
                    return {
                        'registry': 'acr',
                        'registry_name': registry,
                        'repository': repo,
                        'tags': tags,
                        'count': len(tags),
                        'url': f"{registry}.azurecr.io/{repo}"
                    }
        except Exception as e:
            logger.debug(f"Error scanning ACR {registry}/{repo}: {e}")
        
        return None
    
    def format_tree(self, results: List[Dict[str, Any]]) -> str:
        """Format results as tree"""
        lines = []
        lines.append("🐳 Container Registry Scan Results")
        lines.append("=" * 60)
        lines.append("")
        
        for i, result in enumerate(results):
            if not result:
                continue
            
            is_last = (i == len(results) - 1)
            prefix = "└─" if is_last else "├─"
            detail_prefix = "   " if is_last else "│  "
            
            registry = result.get('registry', 'unknown').upper()
            count = result.get('count', 0)
            url = result.get('url', 'N/A')
            
            lines.append(f"{prefix} {registry}: {count} images/repos")
            lines.append(f"{detail_prefix}└─ 🔗 {url}")
            
            if not is_last:
                lines.append("│")
        
        return "\n".join(lines)


__all__ = ['ContainerRegistryScanner']
