"""
Risk Scorer
Calculate risk scores for findings based on multiple factors
"""

from typing import Dict, Any, List


def calculate_risk_scores(findings: List[Dict[str, Any]]) -> Dict[str, float]:
    """
    Calculate risk scores (0-100) for all findings.
    
    Args:
        findings: List of finding dictionaries
        
    Returns:
        Dictionary mapping finding IDs to risk scores
    """
    scores = {}
    
    for finding in findings:
        finding_id = finding.get('id', finding.get('bucket_name', 'unknown'))
        scores[finding_id] = calculate_risk_score(finding)
    
    return scores


def calculate_risk_score(finding: Dict[str, Any]) -> float:
    """
    Calculate risk score for a single finding.
    
    Factors:
    - Severity (0-30 points)
    - Exposure (public access) (0-25 points)
    - Sensitivity (data classification) (0-25 points)
    - Exploitability (ease of exploitation) (0-20 points)
    
    Args:
        finding: Finding dictionary
        
    Returns:
        Risk score (0-100)
    """
    score = 0.0
    
    # Severity component (0-30 points)
    severity_scores = {
        'CRITICAL': 30,
        'HIGH': 22,
        'MEDIUM': 15,
        'LOW': 7,
        'INFO': 2
    }
    severity = finding.get('severity', 'INFO').upper()
    score += severity_scores.get(severity, 2)
    
    # Exposure component (0-25 points)
    if finding.get('is_public', False):
        score += 25
    elif 'READ' in finding.get('permissions', []):
        score += 15
    
    # Sensitivity component (0-25 points)
    sensitive_data = finding.get('sensitive_data', [])
    interesting_files = finding.get('interesting_files', [])
    
    if len(sensitive_data) > 0:
        score += min(25, len(sensitive_data) * 5)
    elif len(interesting_files) > 0:
        score += min(15, len(interesting_files) * 2)
    
    # Check for high-value data types
    if any('.env' in f or 'credentials' in f or '.key' in f 
           for f in interesting_files):
        score += 10  # Credential exposure bonus
    
    # Exploitability component (0-20 points)
    permissions = finding.get('permissions', [])
    if 'WRITE' in permissions or 'FULL_CONTROL' in permissions:
        score += 20  # Write access is highly exploitable
    elif 'LIST' in permissions:
        score += 10
    elif finding.get('is_public', False):
        score += 15  # Public read-only is still exploitable
    
    return min(100.0, score)


__all__ = ['calculate_risk_scores', 'calculate_risk_score']
