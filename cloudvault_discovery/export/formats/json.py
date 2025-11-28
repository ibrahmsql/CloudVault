"""
JSON Export Format
Structured JSON output for CI/CD pipelines
"""

import json
from typing import List, Dict, Any


def export_json(findings: List[Dict[str, Any]], output_path: str, pretty: bool = True):
    """
    Export findings as JSON file.
    
    Args:
        findings: List of finding dictionaries
        output_path: Path to output JSON file
        pretty: Pretty-print JSON (default: True)
    """
    output = {
        "metadata": {
            "version": "1.0.1",
            "tool": "CloudVault",
            "total_findings": len(findings)
        },
        "findings": findings
    }
    
    with open(output_path, 'w') as f:
        if pretty:
            json.dump(output, f, indent=2, default=str)
        else:
            json.dump(output, f, default=str)


__all__ = ['export_json']
