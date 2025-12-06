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
    history = await get_scan_history(limit=100)
    
    scan_1 = None
    scan_2 = None
    for scan in history:
        if scan.get('id') == scan_id_1:
            scan_1 = scan
        if scan.get('id') == scan_id_2:
            scan_2 = scan
    
    if not scan_1 or not scan_2:
        return {
            'error': 'Scan not found',
            'new_findings': [],
            'fixed_findings': [],
            'common_findings': [],
            'risk_score_change': 0.0
        }
    
    findings_1 = set(f.get('resource_id', '') for f in scan_1.get('findings', []))
    findings_2 = set(f.get('resource_id', '') for f in scan_2.get('findings', []))
    
    new_findings = list(findings_2 - findings_1)
    fixed_findings = list(findings_1 - findings_2)
    common_findings = list(findings_1 & findings_2)
    
    risk_1 = scan_1.get('risk_score', 0)
    risk_2 = scan_2.get('risk_score', 0)
    
    return {
        'new_findings': new_findings,
        'fixed_findings': fixed_findings,
        'common_findings': common_findings,
        'risk_score_change': risk_2 - risk_1,
        'scan_1_timestamp': scan_1.get('timestamp'),
        'scan_2_timestamp': scan_2.get('timestamp')
    }


__all__ = ['track_scan', 'compare_scans']
