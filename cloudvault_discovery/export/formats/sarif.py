"""
SARIF Format Exporter
Static Analysis Results Interchange Format (SARIF 2.1.0)
Compatible with GitHub Security Code Scanning
"""

import json
from typing import List, Dict, Any
from datetime import datetime


def export_sarif(findings: List[Dict[str, Any]], output_path: str):
    """
    Export findings in SARIF 2.1.0 format.
    
    Args:
        findings: List of finding dictionaries
        output_path: Path to output SARIF file
    """
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CloudVault",
                        "version": "1.0.1",
                        "informationUri": "https://github.com/ibrahmsql/CloudVault",
                        "rules": _generate_rules(findings)
                    }
                },
                "results": _generate_results(findings),
                "properties": {
                    "scanTime": datetime.utcnow().isoformat() + "Z"
                }
            }
        ]
    }
    
    with open(output_path, 'w') as f:
        json.dump(sarif, f, indent=2)


def _generate_rules(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate SARIF rules from findings"""
    rules_map = {}
    
    for finding in findings:
        for pattern in finding.get('attack_patterns', []):
            if pattern not in rules_map:
                rules_map[pattern] = {
                    "id": pattern,
                    "name": pattern.replace('_', ' ').title(),
                    "shortDescription": {
                        "text": f"Cloud storage misconfiguration: {pattern}"
                    },
                    "fullDescription": {
                        "text": finding.get('description', '')
                    },
                    "help": {
                        "text": finding.get('remediation', 'Review and remediate finding')
                    },
                    "properties": {
                        "security-severity": _get_severity_score(finding.get('severity', 'MEDIUM'))
                    }
                }
    
    return list(rules_map.values())


def _generate_results(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate SARIF results from findings"""
    results = []
    
    for finding in findings:
        pattern = finding.get('attack_patterns', ['Unknown'])[0] if finding.get('attack_patterns') else 'Unknown'
        
        result = {
            "ruleId": pattern,
            "level": _get_sarif_level(finding.get('severity', 'MEDIUM')),
            "message": {
                "text": finding.get('title', 'Cloud storage finding')
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.get('bucket_url', ''),
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": 1
                        }
                    },
                    "logicalLocations": [
                        {
                            "name": finding.get('bucket_name', 'unknown'),
                            "fullyQualifiedName": finding.get('bucket_url', '')
                        }
                    ]
                }
            ],
            "properties": {
                "provider": finding.get('provider', 'unknown'),
                "risk_score": finding.get('risk_score', 0),
                "is_public": finding.get('is_public', False),
                "mitre_techniques": finding.get('mitre_techniques', [])
            }
        }
        
        results.append(result)
    
    return results


def _get_sarif_level(severity: str) -> str:
    """Convert severity to SARIF level"""
    mapping = {
        'CRITICAL': 'error',
        'HIGH': 'error',
        'MEDIUM': 'warning',
        'LOW': 'note',
        'INFO': 'note'
    }
    return mapping.get(severity.upper(), 'warning')


def _get_severity_score(severity: str) -> str:
    """Get numeric severity score for SARIF"""
    scores = {
        'CRITICAL': '9.0',
        'HIGH': '7.0',
        'MEDIUM': '5.0',
        'LOW': '3.0',
        'INFO': '1.0'
    }
    return scores.get(severity.upper(), '5.0')


__all__ = ['export_sarif']
