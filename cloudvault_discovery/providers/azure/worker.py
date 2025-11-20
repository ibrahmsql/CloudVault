"""
Azure Blob Worker - Main worker class for Azure Blob Storage container discovery
Coordinates authenticated and HTTP checking methods
"""
import logging
import requests
from typing import List
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from azure.storage.blob import BlobServiceClient
    from azure.core.exceptions import ResourceNotFoundError, HttpResponseError
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

from ...core.worker import BaseWorker, WorkerResult
from ...core.queue_manager import ProviderType
from .blob_checker import check_container_with_azure
from .http_checker import check_container_with_http

logger = logging.getLogger(__name__)


class AzureBlobWorker(BaseWorker):
    """
    Azure Blob Storage worker for container discovery
    Supports both authenticated (via storage account) and unauthenticated methods
    """
    
    def __init__(self, config, queue_manager, result_handler, keywords=None, *args, **kwargs):
        """
        Initialize Azure Blob worker
        
        Args:
            config: Configuration object with Azure settings
            queue_manager: Queue manager instance
            result_handler: Function to handle found containers
            keywords: List of keywords for interesting content detection
        """
        super().__init__("azure", config, queue_manager, result_handler, keywords, *args, **kwargs)
        self.azure_config = config.azure
        self.use_azure_sdk = AZURE_AVAILABLE and self.azure_config.is_authenticated()
        
        if self.use_azure_sdk:
            self._init_azure_client()
        else:
            self._init_http_session()
        
        logger.info(f"Azure Blob worker initialized (authenticated: {self.use_azure_sdk})")
    
    def _init_azure_client(self):
        """Initialize Azure Blob Service client with credentials"""
        try:
            if self.azure_config.connection_string:
                self.blob_service_client = BlobServiceClient.from_connection_string(
                    self.azure_config.connection_string
                )
            elif self.azure_config.account_name and self.azure_config.account_key:
                account_url = f"https://{self.azure_config.account_name}.blob.core.windows.net"
                self.blob_service_client = BlobServiceClient(
                    account_url=account_url,
                    credential=self.azure_config.account_key
                )
            else:
                raise ValueError("No valid Azure credentials provided")
            
            # Validate credentials
            try:
                list(self.blob_service_client.list_containers(results_per_page=1))
                logger.info("Azure credentials validated successfully")
            except Exception as e:
                logger.warning(f"Azure credentials validation failed: {e}")
                raise
        
        except Exception as e:
            logger.warning(f"Failed to initialize Azure client, falling back to HTTP: {e}")
            self.use_azure_sdk = False
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
        
        self.timeout = self.azure_config.timeout
    
    def get_provider_type(self):
        """Return provider type for queue management"""
        return ProviderType.AZURE
    
    def check_target(self, target) -> WorkerResult:
        """
        Check if an Azure container exists and get its properties
        
        Args:
            target: BucketTarget to check
            
        Returns:
            WorkerResult: Result of the container check
        """
        # Azure container naming: account_name/container_name
        parts = target.name.split('/', 1)
        
        if len(parts) == 2:
            account_name, container_name = parts
        else:
            # Assume default account if not specified
            account_name = self.azure_config.account_name or 'unknown'
            container_name = target.name
        
        container_url = f"https://{account_name}.blob.core.windows.net/{container_name}"
        
        if self.use_azure_sdk:
            return check_container_with_azure(
                self.blob_service_client,
                self.http_session,
                account_name,
                container_name,
                container_url,
                self.keywords,
                self.azure_config,
                self.config.only_interesting
            )
        else:
            return check_container_with_http(
                self.http_session,
                account_name,
                container_name,
                container_url,
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
        
        if 'rate limit' in error_str or 'throttl' in error_str:
            return True
        
        if hasattr(error, 'status_code') and error.status_code == 429:
            return True
        
        if hasattr(error, 'response') and hasattr(error.response, 'status_code'):
            if error.response.status_code == 429:
                return True
        
        return False
