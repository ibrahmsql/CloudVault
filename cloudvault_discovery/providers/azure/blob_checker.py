"""
Azure Blob authenticated container checker
Handles container checking using Azure Storage SDK
"""
import logging
from azure.core.exceptions import ResourceNotFoundError, HttpResponseError
from ...core.worker import WorkerResult, AccessLevel
from .container_analyzer import analyze_container_permissions, get_container_metadata
from .utils import get_container_contents, validate_container_access

logger = logging.getLogger(__name__)


def check_container_with_azure(blob_service_client, http_session, account_name: str,
                               container_name: str, container_url: str, keywords: list,
                               config, only_interesting: bool) -> WorkerResult:
    """
    Check Azure container using Azure Storage SDK (authenticated method)
    
    Args:
        blob_service_client: Azure BlobServiceClient
        http_session: Requests session for HTTP fallback
        account_name: Azure storage account name
        container_name: Name of the container to check
        container_url: Base URL of the container
        keywords: Keywords for interesting content detection
        config: Azure configuration
        only_interesting: Only report interesting containers
        
    Returns:
        WorkerResult object
    """
    try:
        container_client = blob_service_client.get_container_client(container_name)
        
        # Check if container exists
        try:
            container_client.get_container_properties()
        except ResourceNotFoundError:
            return WorkerResult(
                bucket_name=f"{account_name}/{container_name}",
                provider="azure",
                found=False,
                access_level=AccessLevel.UNKNOWN,
                bucket_url=container_url,
                error_message="Container does not exist"
            )
        
        # Container exists, create base result
        result = WorkerResult(
            bucket_name=f"{account_name}/{container_name}",
            provider="azure",
            found=True,
            access_level=AccessLevel.PRIVATE,
            bucket_url=container_url
        )
        
        # Get container metadata
        result = _get_container_metadata(container_client, result)
        
        # Analyze permissions
        result = _analyze_permissions(container_client, account_name, result)
        
        # Validate access
        if not validate_container_access(http_session, container_url):
            logger.debug(f"Container {container_name} validation failed - marking as false positive")
            result.found = False
            result.error_message = "Validation failed - possible false positive"
            return result
        
        # Get container contents if public or not filtering
        if result.is_public or not only_interesting:
            sample, count, interesting = get_container_contents(container_client, keywords)
            result.sample_objects = sample
            result.object_count = count
            result.interesting_objects = interesting
        
        return result
        
    except HttpResponseError as e:
        return _handle_http_error(e, account_name, container_name, container_url)
    
    except Exception as e:
        logger.error(f"Unexpected error checking container {container_name}: {e}")
        raise


def _get_container_metadata(container_client, result: WorkerResult) -> WorkerResult:
    """Get container metadata"""
    try:
        metadata = get_container_metadata(container_client)
        result.acl_info = metadata
        
        # Extract owner/account info
        if 'account_name' in metadata:
            result.owner = f"Azure-{metadata['account_name']}"
    
    except Exception as e:
        logger.debug(f"Error getting metadata: {e}")
    
    return result


def _analyze_permissions(container_client, account_name: str, result: WorkerResult) -> WorkerResult:
    """Analyze container permissions"""
    try:
        access_level, perm_analysis = analyze_container_permissions(container_client)
        result.access_level = access_level
        result.permission_analysis = perm_analysis
        
        # Set owner
        if not result.owner:
            result.owner = f"Azure-{account_name}"
    
    except Exception as e:
        logger.warning(f"Error analyzing permissions: {e}")
        result.access_level = AccessLevel.PRIVATE
        result.owner = f"Azure-{account_name}"
    
    return result


def _handle_http_error(error: HttpResponseError, account_name: str,
                      container_name: str, container_url: str) -> WorkerResult:
    """Handle Azure HTTP errors"""
    status_code = error.status_code if hasattr(error, 'status_code') else 0
    
    if status_code == 404:
        return WorkerResult(
            bucket_name=f"{account_name}/{container_name}",
            provider="azure",
            found=False,
            access_level=AccessLevel.UNKNOWN,
            bucket_url=container_url,
            error_message="Container not found"
        )
    
    elif status_code == 403:
        return WorkerResult(
            bucket_name=f"{account_name}/{container_name}",
            provider="azure",
            found=True,
            access_level=AccessLevel.PRIVATE,
            bucket_url=container_url,
            owner=f"Azure-{account_name} (access denied)",
            error_message="Access forbidden"
        )
    
    else:
        raise error
