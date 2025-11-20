"""
GCP Storage Worker - Main worker class for Google Cloud Storage bucket discovery
Coordinates authenticated and HTTP checking methods
"""
import logging
import requests
from typing import List
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from google.cloud import storage
    from google.cloud.exceptions import NotFound, Forbidden
    from google.auth.exceptions import DefaultCredentialsError
    GCS_AVAILABLE = True
except ImportError:
    GCS_AVAILABLE = False

from ...core.worker import BaseWorker, WorkerResult
from ...core.queue_manager import ProviderType
from .gcs_checker import check_bucket_with_gcs
from .http_checker import check_bucket_with_http
from .permission_analyzer import analyze_bucket_iam

logger = logging.getLogger(__name__)


class GCPStorageWorker(BaseWorker):
    """
    Google Cloud Storage worker for bucket discovery
    Supports both authenticated (via service account) and unauthenticated methods
    """
    
    def __init__(self, config, queue_manager, result_handler, keywords=None, *args, **kwargs):
        """
        Initialize GCP Storage worker
        
        Args:
            config: Configuration object with GCP settings
            queue_manager: Queue manager instance
            result_handler: Function to handle found buckets
            keywords: List of keywords for interesting content detection
        """
        super().__init__("gcp", config, queue_manager, result_handler, keywords, *args, **kwargs)
        self.gcp_config = config.gcp
        self.use_gcs = GCS_AVAILABLE and self.gcp_config.is_authenticated()
        
        if self.use_gcs:
            self._init_gcs_client()
        else:
            self._init_http_session()
        
        logger.info(f"GCP Storage worker initialized (authenticated: {self.use_gcs})")
    
    def _init_gcs_client(self):
        """Initialize Google Cloud Storage client with credentials"""
        try:
            if self.gcp_config.service_account_path:
                self.gcs_client = storage.Client.from_service_account_json(
                    self.gcp_config.service_account_path,
                    project=self.gcp_config.project_id
                )
            else:
                self.gcs_client = storage.Client(project=self.gcp_config.project_id)
            
            # Validate credentials
            try:
                list(self.gcs_client.list_buckets(max_results=1))
                logger.info("GCP credentials validated successfully")
            except Exception as e:
                logger.warning(f"GCP credentials validation failed: {e}")
                raise
        
        except (DefaultCredentialsError, Exception) as e:
            logger.warning(f"Failed to initialize GCS client, falling back to HTTP: {e}")
            self.use_gcs = False
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
        
        self.timeout = self.gcp_config.timeout
    
    def get_provider_type(self):
        """Return provider type for queue management"""
        return ProviderType.GCP
    
    def check_target(self, target) -> WorkerResult:
        """
        Check if a GCS bucket exists and get its properties
        
        Args:
            target: BucketTarget to check
            
        Returns:
            WorkerResult: Result of the bucket check
        """
        bucket_name = target.name
        bucket_url = f"https://storage.googleapis.com/{bucket_name}"
        
        if self.use_gcs:
            return check_bucket_with_gcs(
                self.gcs_client,
                self.http_session,
                bucket_name,
                bucket_url,
                self.keywords,
                self.gcp_config,
                self.config.only_interesting
            )
        else:
            return check_bucket_with_http(
                self.http_session,
                bucket_name,
                bucket_url,
                self.keywords,
                self.timeout
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
        
        if 'rate limit' in error_str or 'quota' in error_str:
            return True
        
        if hasattr(error, 'code') and error.code == 429:
            return True
        
        if hasattr(error, 'response') and hasattr(error.response, 'status_code'):
            if error.response.status_code == 429:
                return True
        
        return False
