"""
Domain Processor
Extract and process domains for bucket candidates
"""

import re
import logging
from typing import List, Set, Optional

logger = logging.getLogger(__name__)


class DomainProcessor:
    """Process domains to extract bucket candidates"""
    
    def __init__(self, 
                 permutations: Optional[List[str]] = None,
                 keywords: Optional[Set[str]] = None):
        """
        Initialize domain processor.
        
        Args:
            permutations: List of permutation patterns
            keywords: Set of keywords to filter
        """
        self.permutations = permutations or self._default_permutations()
        self.keywords = keywords or set()
        
    def _default_permutations(self) -> List[str]:
        """Default bucket name permutations"""
        return [
            '{domain}',
            '{domain}-backup',
            '{domain}-backups',
            '{domain}-data',
            '{domain}-prod',
            '{domain}-production',
            '{domain}-dev',
            '{domain}-staging',
            '{domain}-test',
            '{domain}-assets',
            '{domain}-static',
            '{domain}-media',
            '{domain}-images',
            '{domain}-files',
            '{domain}-uploads',
            '{domain}-logs',
            '{domain}-archive',
            'backup-{domain}',
            'backups-{domain}',
            'prod-{domain}',
            'dev-{domain}',
            '{company}',
            '{company}-backup',
            '{company}-prod',
        ]
    
    def process_domain(self, domain: str) -> List[str]:
        """
        Process domain and generate bucket candidates.
        
        Args:
            domain: Domain name
            
        Returns:
            List of bucket name candidates
        """
        candidates = set()
        
        # Clean domain
        domain = domain.lower().strip()
        domain = domain.replace('*.', '')  # Remove wildcard
        
        # Extract company name (remove TLD)
        parts = domain.split('.')
        if len(parts) >= 2:
            company = parts[0]
        else:
            company = domain
        
        # Generate bucket names
        for pattern in self.permutations:
            try:
                bucket_name = pattern.format(
                    domain=domain.replace('.', '-'),
                    company=company
                )
                
                # Validate bucket name
                if self._is_valid_bucket_name(bucket_name):
                    candidates.add(bucket_name)
                    
            except Exception as e:
                logger.debug(f"Error applying pattern {pattern}: {e}")
        
        return list(candidates)
    
    def _is_valid_bucket_name(self, name: str) -> bool:
        """Validate bucket name format"""
        # S3 bucket name rules (most restrictive)
        if len(name) < 3 or len(name) > 63:
            return False
        
        # Must start with letter or number
        if not name[0].isalnum():
            return False
        
        # Only lowercase letters, numbers, hyphens, dots
        if not re.match(r'^[a-z0-9][a-z0-9\-\.]*[a-z0-9]$', name):
            return False
        
        # No consecutive dots or dot-dash combinations
        if '..' in name or '.-' in name or '-.' in name:
            return False
        
        return True


__all__ = ['DomainProcessor']
