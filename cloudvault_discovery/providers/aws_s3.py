"""
AWS S3 Provider - Legacy Compatibility Wrapper
This file imports from the new modular aws package structure

New modular structure:
- aws/worker.py - Main AWSS3Worker class
- aws/boto3_checker.py - Authenticated bucket checking with boto3
- aws/http_checker.py - Unauthenticated bucket checking with HTTP
- aws/acl_analyzer.py - ACL analysis and permission detection
- aws/utils.py - Utility functions for validation and extraction
"""

# Import from new modular structure
from .aws import AWSS3Worker

__all__ = ['AWSS3Worker']
