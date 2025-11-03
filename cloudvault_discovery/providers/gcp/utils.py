"""
GCP Storage utility functions
Helper functions for bucket validation, content extraction, etc.
"""
import logging
from typing import Tuple, List

logger = logging.getLogger(__name__)


def get_bucket_contents(bucket, keywords: List[str], limit: int = 100) -> Tuple[List[str], int, List[str]]:
    """
    Get bucket contents using GCS SDK
    
    Args:
        bucket: GCS bucket object
        keywords: Keywords for interesting content detection
        limit: Maximum number of objects to retrieve
        
    Returns:
        Tuple of (sample_objects, object_count, interesting_objects)
    """
    try:
        blobs = list(bucket.list_blobs(max_results=limit))
        objects = [blob.name for blob in blobs]
        
        sample_objects = objects[:10]
        object_count = len(objects)
        
        # Check for interesting content
        interesting_objects = []
        if keywords and objects:
            for obj in objects:
                obj_lower = obj.lower()
                if any(keyword.lower() in obj_lower for keyword in keywords):
                    interesting_objects.append(obj)
        
        return sample_objects, object_count, interesting_objects
        
    except Exception as e:
        logger.debug(f"Error listing objects in {bucket.name}: {e}")
        return [], 0, []


def validate_bucket_access(http_session, bucket_name: str, bucket_url: str) -> bool:
    """
    Validate if bucket is actually accessible (reduce false positives)
    
    Args:
        http_session: Requests session
        bucket_name: Name of the bucket
        bucket_url: Bucket URL
        
    Returns:
        True if bucket is valid, False if likely false positive
    """
    try:
        # Try to access bucket via HTTP
        response = http_session.head(bucket_url, timeout=5)
        
        if response.status_code in [200, 403]:
            return True
        elif response.status_code == 404:
            return False
        
        return True
        
    except Exception as e:
        logger.debug(f"Validation error for {bucket_name}: {e}")
        return True  # Assume valid if we can't validate


def extract_project_from_bucket(bucket) -> str:
    """
    Extract GCP project ID from bucket
    
    Args:
        bucket: GCS bucket object
        
    Returns:
        Project ID or 'unknown'
    """
    try:
        if hasattr(bucket, 'project_number'):
            return str(bucket.project_number)
        
        if hasattr(bucket, '_client') and hasattr(bucket._client, 'project'):
            return bucket._client.project
        
        return 'unknown'
    
    except Exception as e:
        logger.debug(f"Error extracting project: {e}")
        return 'unknown'


def get_bucket_metadata(bucket) -> dict:
    """
    Get comprehensive bucket metadata
    
    Args:
        bucket: GCS bucket object
        
    Returns:
        Dictionary with metadata
    """
    metadata = {
        'location': None,
        'storage_class': None,
        'versioning_enabled': False,
        'lifecycle_rules': 0,
        'cors_enabled': False,
        'encryption': None
    }
    
    try:
        if hasattr(bucket, 'location'):
            metadata['location'] = bucket.location
        
        if hasattr(bucket, 'storage_class'):
            metadata['storage_class'] = bucket.storage_class
        
        if hasattr(bucket, 'versioning_enabled'):
            metadata['versioning_enabled'] = bucket.versioning_enabled
        
        if hasattr(bucket, 'lifecycle_rules'):
            metadata['lifecycle_rules'] = len(list(bucket.lifecycle_rules))
        
        if hasattr(bucket, 'cors'):
            metadata['cors_enabled'] = len(bucket.cors) > 0
        
        if hasattr(bucket, 'default_kms_key_name') and bucket.default_kms_key_name:
            metadata['encryption'] = 'Customer-managed'
        else:
            metadata['encryption'] = 'Google-managed'
    
    except Exception as e:
        logger.debug(f"Error getting bucket metadata: {e}")
    
    return metadata
