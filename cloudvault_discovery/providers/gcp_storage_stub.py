"""
GCP Storage Stub - Fallback when google-cloud-storage is not installed
"""
import logging

logger = logging.getLogger(__name__)

class GCPStorageWorkerStub:
    """Stub implementation when google-cloud-storage is not available"""
    
    def __init__(self, *args, **kwargs):
        logger.warning("GCP Storage Worker running in stub mode - google-cloud-storage not installed")
        logger.info("Install google-cloud-storage for full GCP functionality")
    
    def run(self):
        """Stub run method"""
        logger.warning("GCP Storage scanning disabled - google-cloud-storage not installed")
        return []

# Try to import real implementation, fallback to stub
try:
    from .gcp import GCPStorageWorker
except ImportError:
    GCPStorageWorker = GCPStorageWorkerStub
    logger.info("Using GCP Storage stub - install google-cloud-storage for full functionality")

__all__ = ['GCPStorageWorker']
