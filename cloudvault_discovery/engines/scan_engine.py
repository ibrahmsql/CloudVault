"""
Advanced Scan Engine
Provides intelligent scanning strategies, adaptive rate limiting, and optimization
"""
import logging
import time
from enum import Enum
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass
from collections import deque

logger = logging.getLogger(__name__)


class ScanStrategy(Enum):
    """Scanning strategy options"""
    BREADTH_FIRST = "breadth_first"  # Wide scan, all providers equally
    DEPTH_FIRST = "depth_first"  # Deep scan, one provider at a time
    ADAPTIVE = "adaptive"  # Adjusts based on success rate
    BURST = "burst"  # Fast bursts with cooldowns
    STEALTH = "stealth"  # Slow, randomized timing
    AGGRESSIVE = "aggressive"  # Maximum speed


@dataclass
class ScanMetrics:
    """Metrics for scan performance"""
    total_checked: int = 0
    total_found: int = 0
    success_rate: float = 0.0
    avg_response_time: float = 0.0
    rate_limits_hit: int = 0
    errors: int = 0


class ScanEngine:
    """
    Advanced scanning engine with multiple strategies and optimizations
    """
    
    def __init__(self, strategy: ScanStrategy = ScanStrategy.ADAPTIVE):
        """
        Initialize scan engine
        
        Args:
            strategy: Scanning strategy to use
        """
        self.strategy = strategy
        self.metrics = ScanMetrics()
        self.response_times = deque(maxlen=100)
        self.success_history = deque(maxlen=50)
        self.rate_limit_backoff = {}
        
        logger.info(f"Scan engine initialized with strategy: {strategy.value}")
    
    def optimize_scan_rate(self, provider: str, current_rate: float) -> float:
        """
        Optimize scan rate based on strategy and performance
        
        Args:
            provider: Cloud provider name
            current_rate: Current requests per second
            
        Returns:
            Optimized rate
        """
        if self.strategy == ScanStrategy.AGGRESSIVE:
            return self._aggressive_rate(provider, current_rate)
        
        elif self.strategy == ScanStrategy.STEALTH:
            return self._stealth_rate(provider, current_rate)
        
        elif self.strategy == ScanStrategy.ADAPTIVE:
            return self._adaptive_rate(provider, current_rate)
        
        elif self.strategy == ScanStrategy.BURST:
            return self._burst_rate(provider, current_rate)
        
        return current_rate
    
    def _aggressive_rate(self, provider: str, current_rate: float) -> float:
        """Maximum speed scanning"""
        # Check if we're being rate limited
        if provider in self.rate_limit_backoff:
            backoff_until = self.rate_limit_backoff[provider]
            if time.time() < backoff_until:
                return 0.1  # Minimal rate during backoff
        
        # Increase to maximum
        return min(current_rate * 2.0, 100.0)
    
    def _stealth_rate(self, provider: str, current_rate: float) -> float:
        """Slow, stealthy scanning"""
        # Keep rate low and randomized
        import random
        base_rate = 0.5  # 0.5 req/sec
        randomization = random.uniform(0.8, 1.2)
        return base_rate * randomization
    
    def _adaptive_rate(self, provider: str, current_rate: float) -> float:
        """Adapt based on success rate and response times"""
        if len(self.success_history) < 10:
            return current_rate
        
        # Calculate recent success rate
        recent_success = sum(self.success_history) / len(self.success_history)
        
        # Calculate average response time
        if self.response_times:
            avg_response = sum(self.response_times) / len(self.response_times)
        else:
            avg_response = 1.0
        
        # Adjust rate based on performance
        if recent_success > 0.7 and avg_response < 2.0:
            # Good performance, increase rate
            return min(current_rate * 1.5, 50.0)
        
        elif recent_success < 0.3 or avg_response > 5.0:
            # Poor performance, decrease rate
            return max(current_rate * 0.5, 1.0)
        
        return current_rate
    
    def _burst_rate(self, provider: str, current_rate: float) -> float:
        """Burst scanning with cooldown periods"""
        # Implement burst pattern: fast for 30s, slow for 30s
        cycle_position = int(time.time() % 60)
        
        if cycle_position < 30:
            # Burst phase
            return min(current_rate * 3.0, 80.0)
        else:
            # Cooldown phase
            return max(current_rate * 0.2, 0.5)
    
    def record_scan_result(self, success: bool, response_time: float):
        """
        Record scan result for metrics
        
        Args:
            success: Whether scan was successful
            response_time: Response time in seconds
        """
        self.metrics.total_checked += 1
        
        if success:
            self.metrics.total_found += 1
            self.success_history.append(1)
        else:
            self.success_history.append(0)
        
        self.response_times.append(response_time)
        
        # Update metrics
        if self.metrics.total_checked > 0:
            self.metrics.success_rate = self.metrics.total_found / self.metrics.total_checked
        
        if self.response_times:
            self.metrics.avg_response_time = sum(self.response_times) / len(self.response_times)
    
    def record_rate_limit(self, provider: str, backoff_seconds: int = 60):
        """
        Record rate limit hit
        
        Args:
            provider: Provider that was rate limited
            backoff_seconds: How long to back off
        """
        self.metrics.rate_limits_hit += 1
        self.rate_limit_backoff[provider] = time.time() + backoff_seconds
        logger.warning(f"Rate limit hit for {provider}, backing off for {backoff_seconds}s")
    
    def should_scan_target(self, target_priority: int) -> bool:
        """
        Determine if target should be scanned based on strategy
        
        Args:
            target_priority: Priority score (0-100)
            
        Returns:
            True if should scan
        """
        if self.strategy == ScanStrategy.AGGRESSIVE:
            return True  # Scan everything
        
        elif self.strategy == ScanStrategy.STEALTH:
            # Only scan high-priority targets
            return target_priority > 70
        
        elif self.strategy == ScanStrategy.ADAPTIVE:
            # Adjust threshold based on success rate
            threshold = 50 - (self.metrics.success_rate * 30)
            return target_priority > threshold
        
        return True
    
    def get_metrics(self) -> Dict:
        """Get current scan metrics"""
        return {
            'total_checked': self.metrics.total_checked,
            'total_found': self.metrics.total_found,
            'success_rate': round(self.metrics.success_rate * 100, 2),
            'avg_response_time': round(self.metrics.avg_response_time, 2),
            'rate_limits_hit': self.metrics.rate_limits_hit,
            'errors': self.metrics.errors,
            'strategy': self.strategy.value
        }
    
    def reset_metrics(self):
        """Reset all metrics"""
        self.metrics = ScanMetrics()
        self.response_times.clear()
        self.success_history.clear()
        self.rate_limit_backoff.clear()
