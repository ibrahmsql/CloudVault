"""
AWS S3 HTTP-based bucket checker
Handles unauthenticated bucket checking using HTTP requests
"""
import logging
import requests
from ...core.worker import WorkerResult, AccessLevel
from .utils import extract_objects_from_xml

logger = logging.getLogger(__name__)


def check_bucket_with_http(http_session, bucket_name: str, bucket_url: str, 
                           keywords: list, connect_timeout: int, read_timeout: int):
    """
    Check S3 bucket using HTTP requests (unauthenticated method)
    
    Args:
        http_session: Requests session object
        bucket_name: Name of the bucket to check
        bucket_url: Base URL of the bucket
        keywords: Keywords for interesting content detection
        connect_timeout: Connection timeout in seconds
        read_timeout: Read timeout in seconds
        
    Returns:
        WorkerResult object
    """
    try:
        s3_url = "http://s3-1-w.amazonaws.com"
        timeout_tuple = (connect_timeout, read_timeout)
        
        # Send HEAD request with custom Host header
        response = http_session.head(
            s3_url,
            headers={"Host": bucket_url.replace("https://", "").replace("http://", "")},
            timeout=timeout_tuple
        )
        
        # Handle different response codes
        if response.status_code == 307:
            return _handle_redirect_response(http_session, response, bucket_name, 
                                             bucket_url, keywords, timeout_tuple)
        
        elif response.status_code == 404:
            return WorkerResult(
                bucket_name=bucket_name,
                provider="aws",
                found=False,
                access_level=AccessLevel.UNKNOWN,
                bucket_url=bucket_url
            )
        
        elif response.status_code == 503 and response.reason == "Slow Down":
            raise Exception("AWS rate limit exceeded")
        
        else:
            return WorkerResult(
                bucket_name=bucket_name,
                provider="aws",
                found=False,
                access_level=AccessLevel.UNKNOWN,
                bucket_url=bucket_url,
                error_message=f"HTTP {response.status_code}"
            )
    
    except requests.exceptions.ConnectTimeout:
        logger.debug(f"Connection timeout checking bucket {bucket_name}")
        return _create_timeout_result(bucket_name, bucket_url, "Connection timeout")
    
    except requests.exceptions.ReadTimeout:
        logger.debug(f"Read timeout checking bucket {bucket_name}")
        return _create_timeout_result(bucket_name, bucket_url, "Read timeout")
    
    except requests.exceptions.Timeout:
        logger.debug(f"General timeout checking bucket {bucket_name}")
        return _create_timeout_result(bucket_name, bucket_url, "Timeout")
    
    except requests.exceptions.ConnectionError as ce:
        logger.debug(f"Connection error checking bucket {bucket_name}: {ce}")
        return _create_timeout_result(bucket_name, bucket_url, "Connection error")
    
    except Exception as e:
        logger.debug(f"Error checking bucket {bucket_name}: {e}")
        raise


def _handle_redirect_response(http_session, response, bucket_name: str, bucket_url: str, 
                              keywords: list, timeout_tuple: tuple) -> WorkerResult:
    """
    Handle 307 redirect response from S3
    
    Args:
        http_session: Requests session
        response: Response object from initial request
        bucket_name: Name of the bucket
        bucket_url: Original bucket URL
        keywords: Keywords for interesting content
        timeout_tuple: (connect_timeout, read_timeout)
        
    Returns:
        WorkerResult object
    """
    location = response.headers.get('Location', bucket_url)
    
    result = WorkerResult(
        bucket_name=bucket_name,
        provider="aws",
        found=True,
        access_level=AccessLevel.UNKNOWN,
        bucket_url=location
    )
    
    # Try to list bucket contents
    try:
        list_response = http_session.get(location, timeout=timeout_tuple)
        
        if list_response.status_code == 200:
            # Bucket is publicly readable
            result.access_level = AccessLevel.PUBLIC_READ
            content = list_response.text
            
            # Extract objects from XML
            if '<Key>' in content:
                objects = extract_objects_from_xml(content)
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
        
        elif list_response.status_code == 403:
            # Bucket exists but is private
            result.access_level = AccessLevel.PRIVATE
        
        else:
            result.error_message = f"List response: HTTP {list_response.status_code}"
    
    except requests.exceptions.Timeout as te:
        logger.debug(f"Timeout checking bucket contents for {bucket_name}: {te}")
        result.error_message = "Content check timeout"
    
    except Exception as e:
        logger.debug(f"Error checking bucket contents for {bucket_name}: {e}")
        result.error_message = f"Content check error: {str(e)}"
    
    return result


def _create_timeout_result(bucket_name: str, bucket_url: str, error_message: str) -> WorkerResult:
    """
    Create a WorkerResult for timeout errors
    
    Args:
        bucket_name: Name of the bucket
        bucket_url: Bucket URL
        error_message: Error message to include
        
    Returns:
        WorkerResult indicating bucket not found due to timeout
    """
    return WorkerResult(
        bucket_name=bucket_name,
        provider="aws",
        found=False,
        access_level=AccessLevel.UNKNOWN,
        bucket_url=bucket_url,
        error_message=error_message
    )


def is_rate_limit_error_http(error: Exception) -> bool:
    """
    Check if HTTP error is due to rate limiting
    
    Args:
        error: Exception that occurred
        
    Returns:
        True if error is rate limit related
    """
    error_str = str(error).lower()
    
    if 'rate limit' in error_str or 'slow down' in error_str:
        return True
    
    if hasattr(error, 'response') and hasattr(error.response, 'status_code'):
        if error.response.status_code == 503:
            return True
    
    return False
