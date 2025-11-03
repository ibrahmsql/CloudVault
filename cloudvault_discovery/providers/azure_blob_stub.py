"""
Azure Blob Stub - Fallback when azure-storage-blob is not installed
"""
import logging

logger = logging.getLogger(__name__)

class AzureBlobWorkerStub:
    """Stub implementation when azure-storage-blob is not available"""
    
    def __init__(self, *args, **kwargs):
        logger.warning("Azure Blob Worker running in stub mode - azure-storage-blob not installed")
        logger.info("Install azure-storage-blob for full Azure functionality")
    
    def run(self):
        """Stub run method"""
        logger.warning("Azure Blob scanning disabled - azure-storage-blob not installed")
        return []

# Try to import real implementation, fallback to stub
try:
    from .azure import AzureBlobWorker
except ImportError:
    AzureBlobWorker = AzureBlobWorkerStub
    logger.info("Using Azure Blob stub - install azure-storage-blob for full functionality")

__all__ = ['AzureBlobWorker']
