"""
CloudVault Data Models
Core data structures for findings, attack chains, and security analysis
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any


class Severity(Enum):
    """Finding severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    
    def __str__(self):
        return self.value
    
    @property
    def color(self) -> str:
        """Get Rich color for severity"""
        colors = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "dim"
        }
        return colors.get(self.value, "white")
    
    @property
    def numeric_value(self) -> int:
        """Get numeric value for sorting/scoring"""
        values = {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "INFO": 1
        }
        return values.get(self.value, 0)


__all__ = ['Severity']
