"""
AWS S3 Worker - Main worker class for AWS S3 bucket discovery
Coordinates boto3 and HTTP checking methods
"""
import logging
import requests
from typing import List
from botocore.exceptions import ClientError
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import boto3
    from boto3.session import Session
    from botocore.config import Config as BotoConfig
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

from ...core.worker import BaseWorker, WorkerResult
from ...core.queue_manager import ProviderType
from .boto3_checker import check_bucket_with_boto3
from .http_checker import check_bucket_with_http, is_rate_limit_error_http

logger = logging.getLogger(__name__)


class AWSS3Worker(BaseWorker):
    """
    AWS S3 worker for bucket discovery
    Supports both authenticated (via AWS credentials) and unauthenticated methods.
    Authenticated mode provides better rate limits, ACL checking, and owner identification.
    """
    
    def __init__(self, config, queue_manager, result_handler, keywords=None, *args, **kwargs):
        """
        Initialize AWS S3 worker
        
        Args:
            config: Configuration object with AWS settings
            queue_manager: Queue manager instance
            result_handler: Function to handle found buckets
            keywords: List of keywords for interesting content detection
        """
        super().__init__("aws", config, queue_manager, result_handler, keywords, *args, **kwargs)
        self.aws_config = config.aws
        self.use_boto3 = BOTO3_AVAILABLE and self.aws_config.is_authenticated()
        
        if self.use_boto3:
            self._init_boto3_session()
        else:
            self._init_http_session()
        
        logger.info(f"AWS S3 worker initialized (authenticated: {self.use_boto3})")
    
    def _init_boto3_session(self):
        """Initialize boto3 session with credentials"""
        try:
            self.session = Session(
                aws_access_key_id=self.aws_config.access_key,
                aws_secret_access_key=self.aws_config.secret_key,
                region_name=self.aws_config.region
            )
            
            boto_config = BotoConfig(
                max_pool_connections=50,
                retries={'max_attempts': 3, 'mode': 'adaptive'},
                read_timeout=self.aws_config.timeout,
                connect_timeout=self.aws_config.timeout
            )
            
            self.s3_client = self.session.client('s3', config=boto_config)
            self.s3_resource = self.session.resource('s3', config=boto_config)
            
            # Validate credentials
            try:
                self.s3_client.list_buckets(MaxKeys=1)
                logger.info("AWS credentials validated successfully")
            except ClientError as e:
                if e.response['Error']['Code'] in ['InvalidAccessKeyId', 'SignatureDoesNotMatch']:
                    logger.warning("Invalid AWS credentials, falling back to HTTP mode")
                    raise
                else:
                    logger.info("AWS credentials valid but limited permissions")
        
        except Exception as e:
            logger.warning(f"Failed to initialize boto3 session, falling back to HTTP: {e}")
            self.use_boto3 = False
            self._init_http_session()
    
    def _init_http_session(self):
        """Initialize HTTP session for unauthenticated checking"""
        self.http_session = requests.Session()
        
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
            backoff_factor=2,
            raise_on_status=False
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=15,
            pool_maxsize=100,
            pool_block=False
        )
        
        self.http_session.mount("http://", adapter)
        self.http_session.mount("https://", adapter)
        
        # Set timeouts
        self.connect_timeout = min(self.aws_config.timeout // 3, 10)
        self.read_timeout = self.aws_config.timeout - self.connect_timeout
        self.http_session.timeout = self.aws_config.timeout
    
    def get_provider_type(self):
        """Return provider type for queue management"""
        return ProviderType.AWS
    
    def check_target(self, target) -> WorkerResult:
        """
        Check if an S3 bucket exists and get its properties
        
        Args:
            target: BucketTarget to check
            
        Returns:
            WorkerResult: Result of the bucket check
        """
        bucket_name = target.name
        bucket_url = f"https://{bucket_name}.s3.amazonaws.com"
        
        if self.use_boto3:
            return check_bucket_with_boto3(
                self.s3_client,
                self.s3_resource,
                self.http_session,
                bucket_name,
                bucket_url,
                self.keywords,
                self.aws_config,
                self.config.only_interesting
            )
        else:
            return check_bucket_with_http(
                self.http_session,
                bucket_name,
                bucket_url,
                self.keywords,
                self.connect_timeout,
                self.read_timeout
            )
    
    def is_rate_limit_error(self, error: Exception) -> bool:
        """
        Check if an error indicates rate limiting
        
        Args:
            error: Exception that occurred
            
        Returns:
            bool: True if this is a rate limit error
        """
        error_str = str(error).lower()
        
        # Check error message
        if 'rate limit' in error_str or 'slow down' in error_str:
            return True
        
        # Check boto3 ClientError
        if isinstance(error, ClientError):
            error_code = error.response.get('Error', {}).get('Code', '')
            if error_code in ['SlowDown', 'RequestLimitExceeded', 'Throttling']:
                return True
        
        # Check HTTP error
        if is_rate_limit_error_http(error):
            return True
        
        return False
