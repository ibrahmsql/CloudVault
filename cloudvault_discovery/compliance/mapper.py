"""
Compliance Framework Mapper
CIS Benchmarks and PCI-DSS mapping
"""

from typing import List, Dict, Any


CIS_CONTROLS = {
    'CIS-2.1.5': {
        'title': 'Ensure S3 buckets are not publicly accessible',
        'severity': 'HIGH'
    },
    'CIS-2.1.1': {
        'title': 'Ensure S3 bucket access logging is enabled',
        'severity': 'MEDIUM'
    }
}


def map_to_compliance(findings: List[Dict[str, Any]], framework: str = 'CIS') -> Dict[str, Any]:
    """Map findings to compliance controls"""
    mapped = []
    
    for finding in findings:
        if finding.get('is_public'):
            mapped.append({
                'finding': finding,
                'control': 'CIS-2.1.5',
                'status': 'FAIL'
            })
    
    return {
        'framework': framework,
        'total_controls': len(CIS_CONTROLS),
        'passed': 0,
        'failed': len(mapped),
        'mappings': mapped
    }


def render_compliance_tree(compliance_data: Dict[str, Any]) -> str:
    """Render compliance report as tree"""
    lines = []
    fw = compliance_data['framework']
    lines.append(f"📋 {fw} Compliance Report")
    lines.append("=" * 60)
    lines.append("")
    
    total = compliance_data['total_controls']
    passed = compliance_data['passed']
    failed = compliance_data['failed']
    
    lines.append(f"├─ Total Controls: {total}")
    lines.append(f"├─ ✓ Passed: {passed}")
    lines.append(f"└─ ✗ Failed: {failed}")
    lines.append("")
    
    for i, mapping in enumerate(compliance_data['mappings'][:5]):
        is_last = (i == len(compliance_data['mappings'][:5]) - 1)
        prefix = "└─" if is_last else "├─"
        
        control = mapping['control']
        finding = mapping['finding']
        bucket = finding.get('bucket_name', 'N/A')
        
        lines.append(f"{prefix} {control}: {CIS_CONTROLS.get(control, {}).get('title', 'Unknown')}")
        lines.append(f"   └─ ✗ {bucket}")
    
    return "\n".join(lines)


__all__ = ['map_to_compliance', 'render_compliance_tree', 'CIS_CONTROLS']
