"""
Certificate Transparency Stream Monitor
Real-time monitoring of certificate transparency logs
"""

import asyncio
import json
import logging
from typing import Callable, Optional, Set
from datetime import datetime

logger = logging.getLogger(__name__)


class CertStreamMonitor:
    """Monitor certificate transparency logs via WebSocket"""
    
    def __init__(self, 
                 callback: Callable,
                 skip_lets_encrypt: bool = True,
                 keywords: Optional[Set[str]] = None):
        """
        Initialize certstream monitor.
        
        Args:
            callback: Function to call for each certificate
            skip_lets_encrypt: Skip Let's Encrypt certificates
            keywords: Set of keywords to filter domains
        """
        self.callback = callback
        self.skip_lets_encrypt = skip_lets_encrypt
        self.keywords = keywords or set()
        self.running = False
        self.processed_count = 0
        
    async def connect(self, url: str = "wss://certstream.calidog.io"):
        """Connect to certstream and process certificates"""
        try:
            import websockets
        except ImportError:
            logger.error("websockets library not installed")
            raise
        
        self.running = True
        logger.info(f"Connecting to certstream: {url}")
        
        retry_count = 0
        max_retries = 5
        
        while self.running and retry_count < max_retries:
            try:
                async with websockets.connect(url, ping_interval=15, ping_timeout=10) as websocket:
                    logger.info("Connected to certstream")
                    retry_count = 0  # Reset on successful connection
                    
                    while self.running:
                        try:
                            message = await asyncio.wait_for(
                                websocket.recv(),
                                timeout=30.0
                            )
                            
                            await self._process_message(message)
                            
                        except asyncio.TimeoutError:
                            logger.warning("WebSocket receive timeout")
                            continue
                        except Exception as e:
                            logger.error(f"Error processing message: {e}")
                            continue
                            
            except Exception as e:
                retry_count += 1
                logger.error(f"Connection error (attempt {retry_count}/{max_retries}): {e}")
                
                if retry_count < max_retries:
                    wait_time = min(2 ** retry_count, 60)  # Exponential backoff
                    logger.info(f"Reconnecting in {wait_time}s...")
                    await asyncio.sleep(wait_time)
                else:
                    logger.error("Max retries reached, stopping")
                    break
    
    async def _process_message(self, message: str):
        """Process a single certificate message"""
        try:
            data = json.loads(message)
            
            if data.get('message_type') != 'certificate_update':
                return
            
            cert_data = data.get('data', {})
            leaf_cert = cert_data.get('leaf_cert', {})
            
            # Skip Let's Encrypt if requested
            if self.skip_lets_encrypt:
                issuer = leaf_cert.get('issuer', {})
                if 'Let\'s Encrypt' in str(issuer):
                    return
            
            # Extract domains
            all_domains = leaf_cert.get('all_domains', [])
            
            for domain in all_domains:
                domain = domain.lower().strip()
                
                # Apply keyword filter
                if self.keywords:
                    if not any(kw in domain for kw in self.keywords):
                        continue
                
                # Call callback with domain
                await self.callback(domain, cert_data)
                self.processed_count += 1
                
        except json.JSONDecodeError:
            logger.debug("Invalid JSON message")
        except Exception as e:
            logger.error(f"Error processing certificate: {e}")
    
    def stop(self):
        """Stop monitoring"""
        logger.info(f"Stopping certstream (processed {self.processed_count} certificates)")
        self.running = False


__all__ = ['CertStreamMonitor']
