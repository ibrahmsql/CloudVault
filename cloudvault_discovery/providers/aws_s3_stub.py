"""
AWS S3 Stub - Fallback when boto3 is not installed
"""
import logging

logger = logging.getLogger(__name__)

class AWSS3WorkerStub:
    """Stub implementation when boto3 is not available"""
    
    def __init__(self, *args, **kwargs):
        logger.warning("AWS S3 Worker running in stub mode - boto3 not installed")
        logger.info("Install boto3 for full AWS functionality: pip install boto3")
    
    def run(self):
        """Stub run method"""
        logger.warning("AWS S3 scanning disabled - boto3 not installed")
        return []

# Try to import real implementation, fallback to stub
try:
    from .aws import AWSS3Worker
except ImportError:
    AWSS3Worker = AWSS3WorkerStub
    logger.info("Using AWS S3 stub - install boto3 for full functionality")

__all__ = ['AWSS3Worker']
