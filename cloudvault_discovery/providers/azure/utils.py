"""
Azure Storage utility functions
Helper functions for container validation, content extraction, etc.
"""
import logging
from typing import Tuple, List

logger = logging.getLogger(__name__)


def get_container_contents(container_client, keywords: List[str], 
                           limit: int = 100) -> Tuple[List[str], int, List[str]]:
    """
    Get container contents using Azure SDK
    
    Args:
        container_client: Azure ContainerClient object
        keywords: Keywords for interesting content detection
        limit: Maximum number of blobs to retrieve
        
    Returns:
        Tuple of (sample_blobs, blob_count, interesting_blobs)
    """
    try:
        blob_list = []
        for blob in container_client.list_blobs(results_per_page=limit):
            blob_list.append(blob.name)
            if len(blob_list) >= limit:
                break
        
        sample_blobs = blob_list[:10]
        blob_count = len(blob_list)
        
        # Check for interesting content
        interesting_blobs = []
        if keywords and blob_list:
            for blob in blob_list:
                blob_lower = blob.lower()
                if any(keyword.lower() in blob_lower for keyword in keywords):
                    interesting_blobs.append(blob)
        
        return sample_blobs, blob_count, interesting_blobs
        
    except Exception as e:
        logger.debug(f"Error listing blobs: {e}")
        return [], 0, []


def validate_container_access(http_session, container_url: str) -> bool:
    """
    Validate if container is actually accessible (reduce false positives)
    
    Args:
        http_session: Requests session
        container_url: Container URL
        
    Returns:
        True if container is valid, False if likely false positive
    """
    try:
        # Try to access container via HTTP
        response = http_session.head(container_url, timeout=5)
        
        if response.status_code in [200, 403, 401]:
            return True
        elif response.status_code == 404:
            return False
        
        return True
        
    except Exception as e:
        logger.debug(f"Validation error: {e}")
        return True  # Assume valid if we can't validate


def extract_account_from_url(url: str) -> str:
    """
    Extract storage account name from Azure URL
    
    Args:
        url: Azure container URL
        
    Returns:
        Account name or 'unknown'
    """
    try:
        # Format: https://{account}.blob.core.windows.net/{container}
        if '.blob.core.windows.net' in url:
            parts = url.split('.')
            if len(parts) > 0:
                account = parts[0].replace('https://', '').replace('http://', '')
                return account
        
        return 'unknown'
    
    except Exception as e:
        logger.debug(f"Error extracting account: {e}")
        return 'unknown'


def get_blob_properties(blob_client) -> dict:
    """
    Get comprehensive blob properties
    
    Args:
        blob_client: Azure BlobClient object
        
    Returns:
        Dictionary with blob properties
    """
    properties = {
        'content_type': None,
        'content_length': 0,
        'last_modified': None,
        'etag': None,
        'metadata': {},
        'tier': None
    }
    
    try:
        blob_properties = blob_client.get_blob_properties()
        
        if hasattr(blob_properties, 'content_type'):
            properties['content_type'] = blob_properties.content_type
        
        if hasattr(blob_properties, 'size'):
            properties['content_length'] = blob_properties.size
        
        if hasattr(blob_properties, 'last_modified'):
            properties['last_modified'] = str(blob_properties.last_modified)
        
        if hasattr(blob_properties, 'etag'):
            properties['etag'] = blob_properties.etag
        
        if hasattr(blob_properties, 'metadata'):
            properties['metadata'] = blob_properties.metadata
        
        if hasattr(blob_properties, 'blob_tier'):
            properties['tier'] = str(blob_properties.blob_tier)
    
    except Exception as e:
        logger.debug(f"Error getting blob properties: {e}")
    
    return properties
