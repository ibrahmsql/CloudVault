"""Core Worker Module - Base classes for all workers"""
from enum import Enum
from typing import Dict, Any, Optional
from dataclasses import dataclass

class AccessLevel(Enum):
    """Bucket access level"""
    PRIVATE = "PRIVATE"
    PUBLIC_READ = "PUBLIC_READ"
    PUBLIC_WRITE = "PUBLIC_WRITE"
    PUBLIC_READ_WRITE = "PUBLIC_READ_WRITE"

@dataclass
class WorkerResult:
    """Worker result data class"""
    bucket_url: str
    provider: str
    is_public: bool = False
    access_level: AccessLevel = AccessLevel.PRIVATE
    has_interesting_content: bool = False
    risk_level: str = "LOW"
    metadata: Dict[str, Any] = None

class BaseWorker:
    """Base worker class for all providers"""
    
    def __init__(self, provider_name, config, queue_manager, result_handler, keywords=None, *args, **kwargs):
        self.provider_name = provider_name
        self.config = config
        self.queue_manager = queue_manager
        self.result_handler = result_handler
        self.keywords = keywords or []
    
    def run(self):
        """Run the worker"""
        pass
    
    def check_bucket(self, bucket_name: str) -> Optional[WorkerResult]:
        """Check a single bucket"""
        return None
