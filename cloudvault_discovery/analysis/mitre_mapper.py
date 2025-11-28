"""
MITRE ATT&CK Mapper
Maps findings to MITRE ATT&CK framework
"""

from typing import Dict, List, Optional


# MITRE ATT&CK Technique Database (Cloud-focused)
MITRE_TECHNIQUES = {
    "T1530": {
        "name": "Data from Cloud Storage Object",
        "tactic": "Collection",
        "description": "Adversaries may access data objects from cloud storage.",
        "url": "https://attack.mitre.org/techniques/T1530/"
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "description": "Adversaries may obtain credentials to access cloud resources.",
        "url": "https://attack.mitre.org/techniques/T1078/"
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "description": "Adversaries may search compromised systems for credentials.",
        "url": "https://attack.mitre.org/techniques/T1552/"
    },
    "T1552.001": {
        "name": "Credentials In Files",
        "tactic": "Credential Access",
        "description": "Adversaries may search files for unsecured credentials.",
        "url": "https://attack.mitre.org/techniques/T1552/001/"
    },
    "T1485": {
        "name": "Data Destruction",
        "tactic": "Impact",
        "description": "Adversaries may destroy data to interrupt availability.",
        "url": "https://attack.mitre.org/techniques/T1485/"
    },
    "T1565": {
        "name": "Data Manipulation",
        "tactic": "Impact",
        "description": "Adversaries may manipulate data to impact business processes.",
        "url": "https://attack.mitre.org/techniques/T1565/"
    },
    "T1098": {
        "name": "Account Manipulation",
        "tactic": "Persistence",
        "description": "Adversaries may manipulate accounts to maintain access.",
        "url": "https://attack.mitre.org/techniques/T1098/"
    },
    "T1199": {
        "name": "Trusted Relationship",
        "tactic": "Initial Access",
        "description": "Adversaries may breach via trusted third parties.",
        "url": "https://attack.mitre.org/techniques/T1199/"
    },
    "T1005": {
        "name": "Data from Local System",
        "tactic": "Collection",
        "description": "Adversaries may search local systems for data.",
        "url": "https://attack.mitre.org/techniques/T1005/"
    },
    "T1213": {
        "name": "Data from Information Repositories",
        "tactic": "Collection",
        "description": "Adversaries may access information repositories.",
        "url": "https://attack.mitre.org/techniques/T1213/"
    },
    "T1537": {
        "name": "Transfer Data to Cloud Account",
        "tactic": "Exfiltration",
        "description": "Adversaries may exfiltrate data to cloud storage.",
        "url": "https://attack.mitre.org/techniques/T1537/"
    },
}


def get_mitre_technique(technique_id: str) -> Optional[Dict[str, str]]:
    """
    Get MITRE ATT&CK technique details.
    
    Args:
        technique_id: MITRE technique ID (e.g., "T1530")
        
    Returns:
        Technique details or None if not found
    """
    return MITRE_TECHNIQUES.get(technique_id)


def get_techniques_by_tactic(tactic: str) -> List[Dict[str, str]]:
    """
    Get all techniques for a specific tactic.
    
    Args:
        tactic: MITRE tactic name (e.g., "Collection")
        
    Returns:
        List of technique dictionaries
    """
    return [
        {"id": tid, **details}
        for tid, details in MITRE_TECHNIQUES.items()
        if details["tactic"] == tactic
    ]


def map_finding_to_mitre(finding: Dict) -> List[str]:
    """
    Map a finding to MITRE ATT&CK techniques.
    
    Args:
        finding: Finding dictionary
        
    Returns:
        List of applicable technique IDs
    """
    techniques = []
    
    # Check if already has MITRE mappings
    if finding.get('mitre_techniques'):
        return finding['mitre_techniques']
    
    # Heuristic mapping based on finding characteristics
    is_public = finding.get('is_public', False)
    sensitive_data = finding.get('sensitive_data', [])
    interesting_files = finding.get('interesting_files', [])
    permissions = finding.get('permissions', [])
    
    # Data from cloud storage
    if is_public and (sensitive_data or interesting_files):
        techniques.append("T1530")
    
    # Credentials in files
    if any('.env' in f or 'credentials' in f or '.key' in f 
           for f in interesting_files):
        techniques.extend(["T1552", "T1552.001"])
    
    # Write permissions = potential data destruction/manipulation
    if 'WRITE' in permissions or 'FULL_CONTROL' in permissions:
        techniques.extend(["T1485", "T1565"])
    
    # Database dumps
    if any('.sql' in f or '.db' in f for f in interesting_files):
        techniques.append("T1213")
    
    # Source code/configs
    if any(('.git' in f or '.svn' in f or '.config' in f) 
           for f in interesting_files):
        techniques.append("T1213")
    
    return list(set(techniques))  # Remove duplicates


__all__ = [
    'get_mitre_technique',
    'get_techniques_by_tactic',
    'map_finding_to_mitre',
    'MITRE_TECHNIQUES'
]
