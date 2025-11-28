"""
CloudVault - Multi-Cloud Storage Bucket Discovery Tool
A modern, modular Python security research tool that monitors certificate transparency logs
to discover publicly accessible cloud storage across multiple providers (AWS S3, Google Cloud Storage, Azure Blob Storage).
"""
__version__ = "1.0.1"
__author__ = "ibrahim"
__description__ = """
CloudVault - Multi-cloud storage bucket discovery via certificate transparency

A powerful security scanner for discovering exposed AWS S3, Google Cloud Storage,
and Azure Blob Storage containers through real-time certificate transparency monitoring.
"""

# Export main CLI entry point
from .cli import main

__all__ = [
    'main',
    '__version__',
    '__author__'
]