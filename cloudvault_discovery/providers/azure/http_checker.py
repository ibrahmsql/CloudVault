"""
Azure Blob HTTP-based container checker
Handles unauthenticated container checking using HTTP requests
"""
import logging
import requests
import xml.etree.ElementTree as ET
from ...core.worker import WorkerResult, AccessLevel

logger = logging.getLogger(__name__)


def check_container_with_http(http_session, account_name: str, container_name: str,
                              container_url: str, keywords: list, timeout: int) -> WorkerResult:
    """
    Check Azure container using HTTP requests (unauthenticated method)
    
    Args:
        http_session: Requests session object
        account_name: Azure storage account name
        container_name: Name of the container to check
        container_url: Base URL of the container
        keywords: Keywords for interesting content detection
        timeout: Request timeout in seconds
        
    Returns:
        WorkerResult object
    """
    try:
        # Try to list container blobs
        list_url = f"{container_url}?restype=container&comp=list"
        response = http_session.get(list_url, timeout=timeout)
        
        if response.status_code == 200:
            # Container is publicly readable
            return _handle_public_container(
                account_name, container_name, container_url, response, keywords
            )
        
        elif response.status_code == 403 or response.status_code == 401:
            # Container exists but is private
            return WorkerResult(
                bucket_name=f"{account_name}/{container_name}",
                provider="azure",
                found=True,
                access_level=AccessLevel.PRIVATE,
                bucket_url=container_url,
                owner=f"Azure-{account_name}",
                error_message="Access forbidden"
            )
        
        elif response.status_code == 404:
            # Container or account does not exist
            return WorkerResult(
                bucket_name=f"{account_name}/{container_name}",
                provider="azure",
                found=False,
                access_level=AccessLevel.UNKNOWN,
                bucket_url=container_url,
                error_message="Container not found"
            )
        
        elif response.status_code == 429:
            raise Exception("Azure rate limit exceeded")
        
        else:
            return WorkerResult(
                bucket_name=f"{account_name}/{container_name}",
                provider="azure",
                found=False,
                access_level=AccessLevel.UNKNOWN,
                bucket_url=container_url,
                error_message=f"HTTP {response.status_code}"
            )
    
    except requests.exceptions.Timeout:
        logger.debug(f"Timeout checking container {container_name}")
        return _create_timeout_result(account_name, container_name, container_url, "Timeout")
    
    except requests.exceptions.ConnectionError as ce:
        logger.debug(f"Connection error checking container {container_name}: {ce}")
        return _create_timeout_result(account_name, container_name, container_url, "Connection error")
    
    except Exception as e:
        logger.debug(f"Error checking container {container_name}: {e}")
        raise


def _handle_public_container(account_name: str, container_name: str, container_url: str,
                             response, keywords: list) -> WorkerResult:
    """Handle publicly accessible container"""
    result = WorkerResult(
        bucket_name=f"{account_name}/{container_name}",
        provider="azure",
        found=True,
        access_level=AccessLevel.PUBLIC_READ,
        bucket_url=container_url,
        owner=f"Azure-{account_name}"
    )
    
    # Parse XML response to extract blobs
    try:
        blobs = _extract_blobs_from_xml(response.text)
        result.sample_objects = blobs[:10]  # First 10 blobs
        result.object_count = len(blobs)
        
        # Check for interesting content
        if keywords:
            interesting = []
            for blob in blobs:
                blob_lower = blob.lower()
                if any(keyword.lower() in blob_lower for keyword in keywords):
                    interesting.append(blob)
            result.interesting_objects = interesting
    
    except Exception as e:
        logger.debug(f"Error parsing container contents for {container_name}: {e}")
    
    return result


def _extract_blobs_from_xml(xml_content: str) -> list:
    """Extract blob names from Azure XML response"""
    blobs = []
    
    try:
        root = ET.fromstring(xml_content)
        
        # Azure uses EnumerationResults with Blobs/Blob elements
        for blob in root.findall('.//Blob'):
            name_elem = blob.find('Name')
            if name_elem is not None and name_elem.text:
                blobs.append(name_elem.text)
    
    except Exception as e:
        logger.debug(f"Error parsing XML: {e}")
    
    return blobs


def _create_timeout_result(account_name: str, container_name: str,
                           container_url: str, error_message: str) -> WorkerResult:
    """Create a WorkerResult for timeout/connection errors"""
    return WorkerResult(
        bucket_name=f"{account_name}/{container_name}",
        provider="azure",
        found=False,
        access_level=AccessLevel.UNKNOWN,
        bucket_url=container_url,
        error_message=error_message
    )
