"""
GCP Storage HTTP-based bucket checker
Handles unauthenticated bucket checking using HTTP requests
"""
import logging
import requests
import xml.etree.ElementTree as ET
from ...core.worker import WorkerResult, AccessLevel

logger = logging.getLogger(__name__)


def check_bucket_with_http(http_session, bucket_name: str, bucket_url: str,
                           keywords: list, timeout: int) -> WorkerResult:
    """
    Check GCS bucket using HTTP requests (unauthenticated method)
    
    Args:
        http_session: Requests session object
        bucket_name: Name of the bucket to check
        bucket_url: Base URL of the bucket
        keywords: Keywords for interesting content detection
        timeout: Request timeout in seconds
        
    Returns:
        WorkerResult object
    """
    try:
        # Try to list bucket contents
        response = http_session.get(bucket_url, timeout=timeout)
        
        if response.status_code == 200:
            # Bucket is publicly readable
            return _handle_public_bucket(bucket_name, bucket_url, response, keywords)
        
        elif response.status_code == 403:
            # Bucket exists but is private
            return WorkerResult(
                bucket_name=bucket_name,
                provider="gcp",
                found=True,
                access_level=AccessLevel.PRIVATE,
                bucket_url=bucket_url,
                error_message="Access forbidden"
            )
        
        elif response.status_code == 404:
            # Bucket does not exist
            return WorkerResult(
                bucket_name=bucket_name,
                provider="gcp",
                found=False,
                access_level=AccessLevel.UNKNOWN,
                bucket_url=bucket_url,
                error_message="Bucket not found"
            )
        
        elif response.status_code == 429:
            raise Exception("GCP rate limit exceeded")
        
        else:
            return WorkerResult(
                bucket_name=bucket_name,
                provider="gcp",
                found=False,
                access_level=AccessLevel.UNKNOWN,
                bucket_url=bucket_url,
                error_message=f"HTTP {response.status_code}"
            )
    
    except requests.exceptions.Timeout:
        logger.debug(f"Timeout checking bucket {bucket_name}")
        return _create_timeout_result(bucket_name, bucket_url, "Timeout")
    
    except requests.exceptions.ConnectionError as ce:
        logger.debug(f"Connection error checking bucket {bucket_name}: {ce}")
        return _create_timeout_result(bucket_name, bucket_url, "Connection error")
    
    except Exception as e:
        logger.debug(f"Error checking bucket {bucket_name}: {e}")
        raise


def _handle_public_bucket(bucket_name: str, bucket_url: str, response, 
                          keywords: list) -> WorkerResult:
    """
    Handle publicly accessible bucket
    
    Args:
        bucket_name: Name of the bucket
        bucket_url: Bucket URL
        response: HTTP response object
        keywords: Keywords for interesting content
        
    Returns:
        WorkerResult with bucket contents
    """
    result = WorkerResult(
        bucket_name=bucket_name,
        provider="gcp",
        found=True,
        access_level=AccessLevel.PUBLIC_READ,
        bucket_url=bucket_url
    )
    
    # Parse XML response to extract objects
    try:
        objects = _extract_objects_from_xml(response.text)
        result.sample_objects = objects[:10]  # First 10 objects
        result.object_count = len(objects)
        
        # Check for interesting content
        if keywords:
            interesting = []
            for obj in objects:
                obj_lower = obj.lower()
                if any(keyword.lower() in obj_lower for keyword in keywords):
                    interesting.append(obj)
            result.interesting_objects = interesting
    
    except Exception as e:
        logger.debug(f"Error parsing bucket contents for {bucket_name}: {e}")
    
    return result


def _extract_objects_from_xml(xml_content: str) -> list:
    """
    Extract object keys from GCS XML response
    GCS uses its own XML format, not S3!
    
    Args:
        xml_content: XML response content
        
    Returns:
        List of object keys with metadata
    """
    objects = []
    
    try:
        root = ET.fromstring(xml_content)
        
        # GCS XML format - without namespace or with GCS namespace
        # Try multiple formats for compatibility
        
        # Format 1: Direct Contents elements
        for content in root.findall('.//Contents'):
            key_elem = content.find('Key')
            if key_elem is not None and key_elem.text:
                objects.append(key_elem.text)
        
        # Format 2: GCS-specific ListBucketResult
        if not objects:
            for item in root.findall('.//Item'):
                name_elem = item.find('Name')
                if name_elem is not None and name_elem.text:
                    objects.append(name_elem.text)
        
        # Format 3: JSON-style response embedded in XML
        if not objects:
            for entry in root.iter():
                if entry.tag in ['Name', 'Key', 'name', 'key']:
                    if entry.text and '/' not in entry.text:  # Filter out bucket name
                        objects.append(entry.text)
    
    except Exception as e:
        logger.debug(f"Error parsing GCS XML: {e}")
    
    return objects


def _create_timeout_result(bucket_name: str, bucket_url: str, 
                           error_message: str) -> WorkerResult:
    """
    Create a WorkerResult for timeout/connection errors
    
    Args:
        bucket_name: Name of the bucket
        bucket_url: Bucket URL
        error_message: Error message to include
        
    Returns:
        WorkerResult indicating bucket not found due to error
    """
    return WorkerResult(
        bucket_name=bucket_name,
        provider="gcp",
        found=False,
        access_level=AccessLevel.UNKNOWN,
        bucket_url=bucket_url,
        error_message=error_message
    )
