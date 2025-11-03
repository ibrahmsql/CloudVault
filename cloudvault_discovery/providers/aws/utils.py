"""
AWS S3 utility functions
Helper functions for bucket validation, owner extraction, etc.
"""
import logging
import xml.etree.ElementTree as ET
from typing import Optional, List
import re
import requests
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def extract_owner_from_http(http_session, bucket_name: str, bucket_url: str, timeout: int) -> Optional[str]:
    """
    Extract bucket owner from HTTP response headers and XML
    
    Args:
        http_session: Requests session object
        bucket_name: Name of the bucket
        bucket_url: URL of the bucket
        timeout: Request timeout in seconds
        
    Returns:
        Owner name or None if not found
    """
    try:
        response = http_session.head(bucket_url, timeout=timeout)
        
        server_header = response.headers.get('Server', '').lower()
        if 'amazon' in server_header or 'aws' in server_header:
            return f"AWS-{bucket_name}"
        
        response = http_session.get(bucket_url, timeout=timeout)
        if response.status_code == 200:
            try:
                root = ET.fromstring(response.content)
                
                for elem in root.iter():
                    if elem.tag.endswith('Owner'):
                        owner_id = elem.find('.//{*}ID')
                        display_name = elem.find('.//{*}DisplayName')
                        
                        if display_name is not None and display_name.text:
                            return display_name.text
                        elif owner_id is not None and owner_id.text:
                            return f"AWS-{owner_id.text[:12]}"
                
                return f"AWS-{bucket_name}"
                
            except Exception as e:
                logger.debug(f"XML parsing error for {bucket_name}: {e}")
                return f"AWS-{bucket_name}"
        
    except Exception as e:
        logger.debug(f"HTTP owner extraction failed for {bucket_name}: {e}")
    
    return None


def validate_bucket_access(s3_client, http_session, bucket_name: str, access_level) -> bool:
    """
    Validate if bucket is actually accessible (reduce false positives)
    
    Args:
        s3_client: Boto3 S3 client
        http_session: Requests session
        bucket_name: Name of the bucket
        access_level: AccessLevel enum value
        
    Returns:
        True if bucket is valid, False if likely false positive
    """
    try:
        # Import here to avoid circular dependency
        from ...core.worker import AccessLevel
        
        if access_level in [AccessLevel.PUBLIC_READ, AccessLevel.PUBLIC_READ_WRITE]:
            test_url = f"https://{bucket_name}.s3.amazonaws.com/"
            response = http_session.head(test_url, timeout=(5, 10))
            if response.status_code in [200, 403]:
                return True
            elif response.status_code == 404:
                return False
        
        try:
            s3_client.get_bucket_location(Bucket=bucket_name)
            return True
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchBucket':
                return False
            elif error_code == 'AccessDenied':
                return True
                
    except Exception as e:
        logger.debug(f"Validation error for {bucket_name}: {e}")
        return True
        
    return True


def is_real_bucket_access_denied(http_session, bucket_name: str) -> bool:
    """
    Check if AccessDenied error is from a real bucket or false positive
    
    Args:
        http_session: Requests session
        bucket_name: Name of the bucket
        
    Returns:
        True if real bucket, False if likely false positive
    """
    try:
        test_urls = [
            f"https://{bucket_name}.s3.amazonaws.com/",
            f"https://s3.amazonaws.com/{bucket_name}/",
        ]
        
        for url in test_urls:
            try:
                response = http_session.head(url, timeout=(3, 5))
                if response.status_code == 403:
                    return True
                elif response.status_code == 404:
                    return False
            except:
                continue
                
        return True
        
    except Exception:
        return True


def extract_objects_from_xml(xml_content: str) -> List[str]:
    """
    Extract object keys from S3 XML response
    
    Args:
        xml_content: XML response content
        
    Returns:
        List of object keys
    """
    pattern = r'<Key>(.*?)</Key>'
    matches = re.findall(pattern, xml_content)
    return matches


def get_bucket_contents(s3_resource, bucket_name: str, keywords: List[str], limit: int = 100) -> tuple:
    """
    Get bucket contents using boto3 resource
    
    Args:
        s3_resource: Boto3 S3 resource
        bucket_name: Name of the bucket
        keywords: Keywords for interesting content detection
        limit: Maximum number of objects to retrieve
        
    Returns:
        Tuple of (sample_objects, object_count, interesting_objects)
    """
    try:
        bucket = s3_resource.Bucket(bucket_name)
        objects = []
        for obj in bucket.objects.limit(limit):
            objects.append(obj.key)
        
        sample_objects = objects[:10]
        object_count = len(objects)
        
        # Check for interesting content
        interesting_objects = []
        if keywords and objects:
            objects_text = ' '.join(objects).lower()
            for obj in objects:
                obj_lower = obj.lower()
                if any(keyword.lower() in obj_lower for keyword in keywords):
                    interesting_objects.append(obj)
        
        return sample_objects, object_count, interesting_objects
        
    except ClientError as e:
        logger.debug(f"Error listing objects in {bucket_name}: {e}")
        return [], 0, []
