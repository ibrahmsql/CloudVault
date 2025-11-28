"""
CSV Export Format
Excel/Google Sheets compatible CSV output
"""

import csv
from typing import List, Dict, Any


def export_csv(findings: List[Dict[str, Any]], output_path: str):
    """
    Export findings as CSV file.
    
    Args:
        findings: List of finding dictionaries
        output_path: Path to output CSV file
    """
    if not findings:
        with open(output_path, 'w') as f:
            f.write("No findings to export\n")
        return
    
    # Define CSV columns
    fieldnames = [
        'ID',
        'Severity',
        'Risk Score',
        'Title',
        'Description',
        'Provider',
        'Bucket Name',
        'Bucket URL',
        'Is Public',
        'Permissions',
        'Sensitive Files',
        'MITRE Techniques',
        'Attack Patterns',
        'Discovered At',
        'Remediation'
    ]
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for finding in findings:
            row = {
                'ID': finding.get('id', ''),
                'Severity': finding.get('severity', 'UNKNOWN'),
                'Risk Score': f"{finding.get('risk_score', 0):.1f}",
                'Title': finding.get('title', ''),
                'Description': finding.get('description', ''),
                'Provider': finding.get('provider', '').upper(),
                'Bucket Name': finding.get('bucket_name', ''),
                'Bucket URL': finding.get('bucket_url', ''),
                'Is Public': 'Yes' if finding.get('is_public', False) else 'No',
                'Permissions': ', '.join(finding.get('permissions', [])),
                'Sensitive Files': len(finding.get('sensitive_data', [])),
                'MITRE Techniques': ', '.join(finding.get('mitre_techniques', [])),
                'Attack Patterns': ', '.join(finding.get('attack_patterns', [])),
                'Discovered At': finding.get('discovered_at', ''),
                'Remediation': finding.get('remediation', '')
            }
            writer.writerow(row)


__all__ = ['export_csv']
