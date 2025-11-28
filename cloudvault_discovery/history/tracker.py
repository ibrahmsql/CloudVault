"""
History Tracker
Track scans and compare results
"""

from typing import List, Dict, Any
from .database import save_scan, get_scan_history


async def track_scan(findings: List[Dict[str, Any]], 
                     config: Dict = None,
                     duration: float = 0) -> int:
    """Track a scan in history"""
    return await save_scan(findings, config, duration)


async def compare_scans(scan_id_1: int, scan_id_2: int) -> Dict[str, Any]:
    """
    Compare two scans and return delta.
    
    Returns:
        Dictionary with new, fixed, and common findings
    """
    # This is a placeholder - full implementation would load both scans
    # and compute set differences
    return {
        'new_findings': [],
        'fixed_findings': [],
        'common_findings': [],
        'risk_score_change': 0.0
    }


__all__ = ['track_scan', 'compare_scans']
