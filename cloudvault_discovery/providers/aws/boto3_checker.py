"""
AWS S3 Boto3-based bucket checker
Handles authenticated bucket checking using boto3
"""
import logging
from botocore.exceptions import ClientError
from ...core.worker import WorkerResult, AccessLevel
from .acl_analyzer import determine_access_level_from_acl, format_acl_info, enhance_permission_analysis
from .utils import extract_owner_from_http, validate_bucket_access, get_bucket_contents

logger = logging.getLogger(__name__)


def check_bucket_with_boto3(s3_client, s3_resource, http_session, bucket_name: str, 
                            bucket_url: str, keywords: list, config, only_interesting: bool):
    """
    Check S3 bucket using boto3 (authenticated method)
    
    Args:
        s3_client: Boto3 S3 client
        s3_resource: Boto3 S3 resource
        http_session: Requests session for HTTP fallback
        bucket_name: Name of the bucket to check
        bucket_url: Base URL of the bucket
        keywords: Keywords for interesting content detection
        config: AWS configuration
        only_interesting: Only report interesting buckets
        
    Returns:
        WorkerResult object
    """
    try:
        # Check if bucket exists
        s3_client.head_bucket(Bucket=bucket_name)
        
        # Bucket exists, create base result
        result = WorkerResult(
            bucket_name=bucket_name,
            provider="aws",
            found=True,
            access_level=AccessLevel.PRIVATE,
            bucket_url=bucket_url
        )
        
        # Get bucket region
        result = _get_bucket_region(s3_client, bucket_name, result, bucket_url)
        
        # Get ACL information
        result = _get_acl_information(s3_client, http_session, bucket_name, bucket_url, result)
        
        # Validate bucket access
        if not validate_bucket_access(s3_client, http_session, bucket_name, result.access_level):
            logger.debug(f"Bucket {bucket_name} validation failed - marking as false positive")
            result.found = False
            result.error_message = "Validation failed - possible false positive"
            return result
        
        # Get bucket contents if public or not filtering
        if result.is_public or not only_interesting:
            sample, count, interesting = get_bucket_contents(s3_resource, bucket_name, keywords)
            result.sample_objects = sample
            result.object_count = count
            result.interesting_objects = interesting
        
        return result
        
    except ClientError as e:
        return _handle_boto3_error(e, s3_client, http_session, bucket_name, bucket_url)
    except Exception as e:
        logger.error(f"Unexpected error checking bucket {bucket_name}: {e}")
        raise


def _get_bucket_region(s3_client, bucket_name: str, result: WorkerResult, default_url: str) -> WorkerResult:
    """Get and set bucket region"""
    try:
        location = s3_client.get_bucket_location(Bucket=bucket_name)
        region = location.get('LocationConstraint') or 'us-east-1'
        result.region = region
        
        if region == 'us-east-1':
            result.bucket_url = f"https://{bucket_name}.s3.amazonaws.com"
        else:
            result.bucket_url = f"https://{bucket_name}.s3.{region}.amazonaws.com"
    except ClientError:
        result.region = 'unknown'
        result.bucket_url = default_url
    
    return result


def _get_acl_information(s3_client, http_session, bucket_name: str, bucket_url: str, 
                         result: WorkerResult) -> WorkerResult:
    """Get and analyze bucket ACL"""
    try:
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        owner_info = acl.get('Owner', {})
        
        # Extract owner information
        display_name = owner_info.get('DisplayName', '')
        owner_id = owner_info.get('ID', '')
        
        if display_name and display_name.strip() != '':
            result.owner = display_name.strip()
        elif owner_id and len(owner_id) > 10:
            short_id = owner_id[:12]
            result.owner = f"AWS-{short_id}"
        else:
            result.owner = '(unknown)'
        
        result.owner_id = owner_id
        
        # Determine access level
        result.access_level = determine_access_level_from_acl(acl)
        
        # Format ACL info
        result.acl_info = format_acl_info(acl)
        
        # Enhanced permission analysis
        result.permission_analysis = enhance_permission_analysis(acl, bucket_name)
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        
        if error_code == 'AccessDenied':
            result.access_level = AccessLevel.PRIVATE
            result.acl_info = {'error': 'Access denied to ACL'}
            result.owner = '(access denied)'
            
            # Try HTTP method for owner extraction
            try:
                http_owner = extract_owner_from_http(http_session, bucket_name, result.bucket_url, 10)
                if http_owner and http_owner != '(unknown)':
                    result.owner = http_owner
            except Exception as http_e:
                logger.debug(f"HTTP owner extraction failed for {bucket_name}: {http_e}")
        else:
            logger.warning(f"Error getting ACL for {bucket_name}: {e}")
            result.owner = '(unknown)'
            
            # Try HTTP fallback
            try:
                http_owner = extract_owner_from_http(http_session, bucket_name, result.bucket_url, 10)
                if http_owner and http_owner != '(unknown)':
                    result.owner = http_owner
            except Exception as http_e:
                logger.debug(f"HTTP owner extraction failed for {bucket_name}: {http_e}")
    
    return result


def _handle_boto3_error(error: ClientError, s3_client, http_session, bucket_name: str, 
                        bucket_url: str) -> WorkerResult:
    """Handle boto3 ClientError responses"""
    error_code = error.response['Error']['Code']
    
    if error_code == 'NoSuchBucket':
        return WorkerResult(
            bucket_name=bucket_name,
            provider="aws",
            found=False,
            access_level=AccessLevel.UNKNOWN,
            bucket_url=bucket_url,
            error_message="Bucket does not exist"
        )
    
    elif error_code == 'AccessDenied':
        # Import here to avoid circular dependency
        from .utils import is_real_bucket_access_denied
        
        if is_real_bucket_access_denied(http_session, bucket_name):
            result = WorkerResult(
                bucket_name=bucket_name,
                provider="aws",
                found=True,
                access_level=AccessLevel.PRIVATE,
                bucket_url=bucket_url,
                owner='(access denied)',
                error_message="Access denied"
            )
            
            # Try to get owner via HTTP
            try:
                http_owner = extract_owner_from_http(http_session, bucket_name, bucket_url, 10)
                if http_owner and http_owner != '(unknown)':
                    result.owner = http_owner
            except Exception as http_e:
                logger.debug(f"HTTP owner extraction failed for {bucket_name}: {http_e}")
            
            return result
        else:
            return WorkerResult(
                bucket_name=bucket_name,
                provider="aws",
                found=False,
                access_level=AccessLevel.UNKNOWN,
                bucket_url=bucket_url,
                error_message="False positive - bucket does not exist"
            )
    
    else:
        # Re-raise unknown errors
        raise error
