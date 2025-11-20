"""
GCP Storage authenticated bucket checker
Handles bucket checking using Google Cloud Storage SDK
"""
import logging
from google.cloud.exceptions import NotFound, Forbidden
from ...core.worker import WorkerResult, AccessLevel
from .permission_analyzer import analyze_iam_policy, get_bucket_acl_info
from .utils import get_bucket_contents, validate_bucket_access

logger = logging.getLogger(__name__)


def check_bucket_with_gcs(gcs_client, http_session, bucket_name: str, bucket_url: str,
                          keywords: list, config, only_interesting: bool) -> WorkerResult:
    """
    Check GCS bucket using Google Cloud SDK (authenticated method)
    
    Args:
        gcs_client: Google Cloud Storage client
        http_session: Requests session for HTTP fallback
        bucket_name: Name of the bucket to check
        bucket_url: Base URL of the bucket
        keywords: Keywords for interesting content detection
        config: GCP configuration
        only_interesting: Only report interesting buckets
        
    Returns:
        WorkerResult object
    """
    try:
        bucket = gcs_client.bucket(bucket_name)
        
        # Check if bucket exists
        if not bucket.exists():
            return WorkerResult(
                bucket_name=bucket_name,
                provider="gcp",
                found=False,
                access_level=AccessLevel.UNKNOWN,
                bucket_url=bucket_url
            )
        
        # Bucket exists, create base result
        result = WorkerResult(
            bucket_name=bucket_name,
            provider="gcp",
            found=True,
            access_level=AccessLevel.PRIVATE,
            bucket_url=bucket_url
        )
        
        # Get bucket metadata
        result = _get_bucket_metadata(bucket, result)
        
        # Get IAM policy and analyze permissions
        result = _analyze_bucket_permissions(bucket, result)
        
        # Validate access
        if not validate_bucket_access(http_session, bucket_name, bucket_url):
            logger.debug(f"Bucket {bucket_name} validation failed - marking as false positive")
            result.found = False
            result.error_message = "Validation failed - possible false positive"
            return result
        
        # Get bucket contents if public or not filtering
        if result.is_public or not only_interesting:
            sample, count, interesting = get_bucket_contents(bucket, keywords)
            result.sample_objects = sample
            result.object_count = count
            result.interesting_objects = interesting
        
        return result
        
    except NotFound:
        return WorkerResult(
            bucket_name=bucket_name,
            provider="gcp",
            found=False,
            access_level=AccessLevel.UNKNOWN,
            bucket_url=bucket_url,
            error_message="Bucket does not exist"
        )
    
    except Forbidden:
        # Bucket exists but access denied
        result = WorkerResult(
            bucket_name=bucket_name,
            provider="gcp",
            found=True,
            access_level=AccessLevel.PRIVATE,
            bucket_url=bucket_url,
            owner='(access denied)',
            error_message="Access denied"
        )
        return result
    
    except Exception as e:
        logger.error(f"Unexpected error checking bucket {bucket_name}: {e}")
        raise


def _get_bucket_metadata(bucket, result: WorkerResult) -> WorkerResult:
    """Get basic bucket metadata"""
    try:
        result.region = bucket.location
        
        # Get storage class
        if hasattr(bucket, 'storage_class'):
            result.acl_info = result.acl_info or {}
            result.acl_info['storage_class'] = bucket.storage_class
        
        # Get creation time
        if hasattr(bucket, 'time_created'):
            result.acl_info = result.acl_info or {}
            result.acl_info['created'] = str(bucket.time_created)
    
    except Exception as e:
        logger.debug(f"Error getting metadata for {bucket.name}: {e}")
    
    return result


def _analyze_bucket_permissions(bucket, result: WorkerResult) -> WorkerResult:
    """Analyze bucket IAM policy and ACLs"""
    try:
        # Get IAM policy
        iam_policy = bucket.get_iam_policy()
        
        # Analyze permissions
        access_level, perm_analysis = analyze_iam_policy(iam_policy)
        result.access_level = access_level
        result.permission_analysis = perm_analysis
        
        # Get ACL info
        acl_info = get_bucket_acl_info(bucket)
        result.acl_info = acl_info
        
        # Extract owner
        if acl_info and 'owner' in acl_info:
            owner = acl_info['owner']
            if owner and owner not in ['(unknown)', '(error)']:
                result.owner = owner
        
    except Forbidden:
        result.access_level = AccessLevel.PRIVATE
        result.acl_info = {'error': 'Access denied to IAM policy'}
        result.owner = '(access denied)'
    
    except Exception as e:
        logger.warning(f"Error analyzing permissions for {bucket.name}: {e}")
        result.owner = '(unknown)'
    
    return result
