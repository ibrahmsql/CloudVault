"""
Baseline Manager
Manage scan baselines and delta reporting
"""

import json
import yaml
from typing import List, Dict, Any
from pathlib import Path
from datetime import datetime


def create_baseline(findings: List[Dict[str, Any]], output_path: str):
    """
    Create a baseline from findings.
    
    Args:
        findings: List of finding dictionaries
        output_path: Path to baseline file (.cloudvault-ignore)
    """
    baseline = {
        "version": "1.0",
        "created_at": datetime.utcnow().isoformat() + "Z",
        "total_findings": len(findings),
        "findings": [
            {
                "id": f.get('id', f.get('bucket_name', 'unknown')),
                "bucket_name": f.get('bucket_name', ''),
                "severity": f.get('severity', 'INFO'),
                "title": f.get('title', '')
            }
            for f in findings
        ],
        "ignore_patterns": []
    }
    
    with open(output_path, 'w') as f:
        yaml.safe_dump(baseline, f, default_flow_style=False)


def compare_with_baseline(
    current_findings: List[Dict[str, Any]],
    baseline_path: str
) -> List[Dict[str, Any]]:
    """
    Compare current findings with baseline.
    
    Returns only new findings not in baseline.
    
    Args:
        current_findings: Current scan findings
        baseline_path: Path to baseline file
        
    Returns:
        List of new findings
    """
    # Load baseline
    with open(baseline_path, 'r') as f:
        baseline = yaml.safe_load(f)
    
    # Extract baseline finding IDs and patterns
    baseline_ids = {
        f['id'] for f in baseline.get('findings', [])
    }
    
    ignore_patterns = baseline.get('ignore_patterns', [])
    
    # Filter new findings
    new_findings = []
    for finding in current_findings:
        finding_id = finding.get('id', finding.get('bucket_name', 'unknown'))
        bucket_name = finding.get('bucket_name', '')
        
        # Check if in baseline
        if finding_id in baseline_ids:
            continue
        
        # Check against ignore patterns
        if _matches_ignore_pattern(bucket_name, ignore_patterns):
            continue
        
        new_findings.append(finding)
    
    return new_findings


def add_ignore_pattern(baseline_path: str, pattern: str):
    """
    Add an ignore pattern to baseline.
    
    Args:
        baseline_path: Path to baseline file
        pattern: Pattern to ignore (glob or regex)
    """
    # Load or create baseline
    if Path(baseline_path).exists():
        with open(baseline_path, 'r') as f:
            baseline = yaml.safe_load(f) or {}
    else:
        baseline = {
            "version": "1.0",
            "created_at": datetime.utcnow().isoformat() + "Z",
            "findings": [],
            "ignore_patterns": []
        }
    
    # Add pattern if not already present
    if pattern not in baseline.get('ignore_patterns', []):
        if 'ignore_patterns' not in baseline:
            baseline['ignore_patterns'] = []
        baseline['ignore_patterns'].append(pattern)
        baseline['updated_at'] = datetime.utcnow().isoformat() + "Z"
    
    # Save
    with open(baseline_path, 'w') as f:
        yaml.safe_dump(baseline, f, default_flow_style=False)


def _matches_ignore_pattern(bucket_name: str, patterns: List[str]) -> bool:
    """Check if bucket name matches any ignore pattern"""
    import fnmatch
    
    for pattern in patterns:
        if fnmatch.fnmatch(bucket_name, pattern):
            return True
    return False


__all__ = ['create_baseline', 'compare_with_baseline', 'add_ignore_pattern']
