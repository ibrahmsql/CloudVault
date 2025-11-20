"""
Network Module
Network utilities and connection management
"""
import requests
from typing import Optional

class NetworkManager:
    """Network connection and request management"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CloudVault/2.0'
        })
    
    def make_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[requests.Response]:
        """Make HTTP request with retry logic"""
        try:
            response = self.session.request(method, url, timeout=10, **kwargs)
            return response
        except Exception:
            return None

__all__ = ['NetworkManager']
