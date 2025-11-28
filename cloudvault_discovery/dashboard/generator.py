"""
Dashboard Generator
Aggregates scan data and calculates risk metrics
"""

from typing import Dict, Any, List
from ..models import Severity


def generate_dashboard_data(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate dashboard data from findings.
    
    Args:
        findings: List of finding dictionaries
        
    Returns:
        Dictionary with dashboard metrics
    """
    if not findings:
        return {
            'risk_score': 0.0,
            'total_findings': 0,
            'severity_counts': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0,
                'INFO': 0
            },
            'provider_stats': {},
            'top_risks': []
        }
    
    # Count severities
    severity_counts = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0,
        'INFO': 0
    }
    
    for finding in findings:
        sev = finding.get('severity', 'INFO').upper()
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    # Calculate risk score (weighted by severity)
    weights = {
        'CRITICAL': 10.0,
        'HIGH': 5.0,
        'MEDIUM': 2.0,
        'LOW': 0.5,
        'INFO': 0.1
    }
    
    total_weight = sum(
        severity_counts[sev] * weights[sev]
        for sev in severity_counts
    )
    
    # Normalize to 0-100 scale (cap at 100)
    max_possible = len(findings) * weights['CRITICAL']
    risk_score = min(100.0, (total_weight / max_possible * 100) if max_possible > 0 else 0)
    
    # Provider stats
    provider_stats = {}
    for finding in findings:
        provider = finding.get('provider', 'unknown')
        if provider not in provider_stats:
            provider_stats[provider] = {
                'checked': 0,
                'found': 0,
                'public': 0
            }
        provider_stats[provider]['found'] += 1
        if finding.get('is_public', False):
            provider_stats[provider]['public'] += 1
    
    # Top risks (most common issues)
    risk_patterns = {}
    for finding in findings:
        for pattern in finding.get('attack_patterns', []):
            risk_patterns[pattern] = risk_patterns.get(pattern, 0) + 1
    
    top_risks = sorted(risk_patterns.items(), key=lambda x: x[1], reverse=True)[:5]
    top_risks = [risk[0] for risk in top_risks]
    
    return {
        'risk_score': risk_score,
        'total_findings': len(findings),
        'severity_counts': severity_counts,
        'provider_stats': provider_stats,
        'top_risks': top_risks
    }


__all__ = ['generate_dashboard_data']
