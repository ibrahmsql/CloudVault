"""
Stealth Module
Evasion and stealth techniques for scanning
"""
import time
import random
from typing import Optional

class StealthManager:
    """Manage stealth scanning techniques"""
    
    def __init__(self, profile: str = 'normal'):
        self.profile = profile
        self.delay_range = self._get_delay_range(profile)
    
    def _get_delay_range(self, profile: str) -> tuple:
        """Get delay range for profile"""
        profiles = {
            'aggressive': (0.1, 0.5),
            'normal': (0.5, 2.0),
            'stealth': (2.0, 5.0),
            'paranoid': (5.0, 10.0)
        }
        return profiles.get(profile, (0.5, 2.0))
    
    def apply_delay(self):
        """Apply random delay based on profile"""
        min_delay, max_delay = self.delay_range
        delay = random.uniform(min_delay, max_delay)
        time.sleep(delay)
    
    def get_random_user_agent(self) -> str:
        """Get random user agent"""
        agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]
        return random.choice(agents)

__all__ = ['StealthManager']
