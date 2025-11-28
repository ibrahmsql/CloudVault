"""
General Advanced Features
Wordlist management, rate limiting, and stealth mode
"""

import asyncio
import time
import random
from typing import List, Optional
from pathlib import Path


class WordlistManager:
    """Custom wordlist management"""
    
    # Default wordlists for different purposes
    DEFAULT_WORDLISTS = {
        'subdomains': [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'api', 'dev', 'stage',
            'staging', 'test', 'admin', 'portal', 'app', 'cdn', 'static', 'assets', 'blog',
            'shop', 'store', 'vpn', 'remote', 'ssh', 'git', 'gitlab', 'jenkins', 'ci', 'cd',
            'prod', 'production', 'backup', 'db', 'database', 'mysql', 'postgres', 'redis',
            's3', 'storage', 'files', 'upload', 'download', 'media', 'images', 'video',
            'demo', 'beta', 'alpha', 'internal', 'intranet', 'extranet', 'secure', 'private'
        ],
        'buckets': [
            '{company}', '{company}-backup', '{company}-backups', '{company}-data',
            '{company}-prod', '{company}-production', '{company}-dev', '{company}-development',
            '{company}-staging', '{company}-test', '{company}-assets', '{company}-static',
            '{company}-media', '{company}-images', '{company}-files', '{company}-uploads',
            '{company}-downloads', '{company}-logs', '{company}-archive', '{company}-documents',
            '{company}-docs', '{company}-db', '{company}-database', '{company}-app',
            '{company}-api', '{company}-webapp', '{company}-web', '{company}-www',
            'backup-{company}', 'prod-{company}', 'dev-{company}', 'test-{company}'
        ],
        'users': [
            'admin', 'administrator', 'root', 'test', 'user', 'demo', 'guest', 'support',
            'info', 'contact', 'sales', 'marketing', 'hr', 'finance', 'it', 'helpdesk',
            'webmaster', 'postmaster', 'manager', 'director', 'ceo', 'cto', 'cfo'
        ]
    }
    
    def __init__(self):
        self.custom_wordlists = {}
    
    def load_wordlist(self, filepath: str) -> List[str]:
        """
        Load wordlist from file.
        
        Args:
            filepath: Path to wordlist file
            
        Returns:
            List of words
        """
        try:
            path = Path(filepath)
            if path.exists():
                with open(path, 'r') as f:
                    words = [line.strip() for line in f if line.strip()]
                return words
        except Exception as e:
            print(f"Error loading wordlist {filepath}: {e}")
        
        return []
    
    def get_wordlist(self, wordlist_type: str, custom_file: Optional[str] = None) -> List[str]:
        """
        Get wordlist by type.
        
        Args:
            wordlist_type: Type of wordlist (subdomains, buckets, users)
            custom_file: Optional custom wordlist file
            
        Returns:
            Wordlist
        """
        if custom_file:
            custom = self.load_wordlist(custom_file)
            if custom:
                return custom
        
        return self.DEFAULT_WORDLISTS.get(wordlist_type, [])
    
    def merge_wordlists(self, *wordlists: List[str]) -> List[str]:
        """Merge multiple wordlists and remove duplicates"""
        merged = set()
        for wl in wordlists:
            merged.update(wl)
        return sorted(list(merged))


class RateLimiter:
    """Rate limiting for requests"""
    
    def __init__(self, requests_per_second: float = 5.0):
        """
        Initialize rate limiter.
        
        Args:
            requests_per_second: Maximum requests per second
        """
        self.requests_per_second = requests_per_second
        self.min_interval = 1.0 / requests_per_second if requests_per_second > 0 else 0
        self.last_request_time = 0
    
    async def wait(self):
        """Wait if necessary to respect rate limit"""
        if self.min_interval > 0:
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            
            if time_since_last < self.min_interval:
                wait_time = self.min_interval - time_since_last
                await asyncio.sleep(wait_time)
            
            self.last_request_time = time.time()


class StealthMode:
    """Stealth mode features to avoid detection"""
    
    def __init__(
        self,
        enabled: bool = False,
        random_delay: bool = True,
        user_agent_rotation: bool = True,
        delay_range: tuple = (1.0, 3.0)
    ):
        """
        Initialize stealth mode.
        
        Args:
            enabled: Enable stealth mode
            random_delay: Random delays between requests
            user_agent_rotation: Rotate user agents
            delay_range: Min and max delay in seconds
        """
        self.enabled = enabled
        self.random_delay = random_delay
        self.user_agent_rotation = user_agent_rotation
        self.delay_range = delay_range
        
        # Common user agents
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15'
        ]
    
    async def apply_delay(self):
        """Apply random delay if stealth mode is enabled"""
        if self.enabled and self.random_delay:
            delay = random.uniform(*self.delay_range)
            await asyncio.sleep(delay)
    
    def get_headers(self) -> dict:
        """Get headers with random user agent"""
        headers = {}
        
        if self.enabled and self.user_agent_rotation:
            headers['User-Agent'] = random.choice(self.user_agents)
        
        # Add common headers to look more legitimate
        if self.enabled:
            headers.update({
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            })
        
        return headers
    
    def get_timeout(self, base_timeout: int = 5) -> int:
        """Get randomized timeout to avoid fingerprinting"""
        if self.enabled:
            # Add ±20% random variation
            variation = random.uniform(0.8, 1.2)
            return int(base_timeout * variation)
        return base_timeout


class ScanConfig:
    """Configurable scan settings"""
    
    def __init__(
        self,
        rate_limit: float = 10.0,
        timeout: int = 5,
        retries: int = 2,
        stealth: bool = False,
        concurrent_tasks: int = 10,
        custom_wordlist: Optional[str] = None
    ):
        """
        Initialize scan configuration.
        
        Args:
            rate_limit: Requests per second
            timeout: Request timeout
            retries: Number of retries
            stealth: Enable stealth mode
            concurrent_tasks: Max concurrent tasks
            custom_wordlist: Path to custom wordlist
        """
        self.rate_limiter = RateLimiter(rate_limit)
        self.timeout = timeout
        self.retries = retries
        self.stealth_mode = StealthMode(enabled=stealth)
        self.concurrent_tasks = concurrent_tasks
        self.wordlist_manager = WordlistManager()
        self.custom_wordlist = custom_wordlist
    
    def get_config_summary(self) -> str:
        """Get configuration summary"""
        return f"""
Scan Configuration:
  Rate Limit: {self.rate_limiter.requests_per_second} req/s
  Timeout: {self.timeout}s
  Retries: {self.retries}
  Stealth Mode: {'Enabled' if self.stealth_mode.enabled else 'Disabled'}
  Concurrent Tasks: {self.concurrent_tasks}
  Custom Wordlist: {self.custom_wordlist or 'None'}
"""


__all__ = ['WordlistManager', 'RateLimiter', 'StealthMode', 'ScanConfig']
