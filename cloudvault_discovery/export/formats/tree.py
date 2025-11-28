"""
Tree Export Format
ASCII tree visualization of attack chains
"""

from typing import List, Dict, Any


def export_tree(findings: List[Dict[str, Any]], output_path: str):
    """
    Export findings as ASCII tree.
    
    Args:
        findings: List of finding dictionaries
        output_path: Path to output text file
    """
    lines = []
    lines.append("CloudVault Security Findings Tree")
    lines.append("=" * 60)
    lines.append("")
    
    # Group by provider
    by_provider = {}
    for finding in findings:
        provider = finding.get('provider', 'unknown').upper()
        if provider not in by_provider:
            by_provider[provider] = []
        by_provider[provider].append(finding)
    
    # Render tree
    for i, (provider, provider_findings) in enumerate(by_provider.items()):
        is_last_provider = (i == len(by_provider) - 1)
        provider_prefix = "└─" if is_last_provider else "├─"
        
        lines.append(f"{provider_prefix} {provider} ({len(provider_findings)} findings)")
        
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        provider_findings.sort(
            key=lambda x: severity_order.get(x.get('severity', 'INFO').upper(), 5)
        )
        
        for j, finding in enumerate(provider_findings):
            is_last_finding = (j == len(provider_findings) - 1)
            
            if is_last_provider:
                finding_prefix = "   └─"
                detail_prefix = "      "
            else:
                finding_prefix = "│  └─" if is_last_finding else "│  ├─"
                detail_prefix = "│     " if is_last_finding else "│  │  "
            
            severity = finding.get('severity', 'INFO')
            severity_icon = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🔵',
                'INFO': '⚪'
            }.get(severity.upper(), '⚪')
            
            lines.append(f"{finding_prefix} {severity_icon} [{severity}] {finding.get('title', 'Unknown')}")
            lines.append(f"{detail_prefix}Bucket: {finding.get('bucket_name', 'N/A')}")
            lines.append(f"{detail_prefix}Public: {'Yes' if finding.get('is_public') else 'No'}")
            
            if finding.get('mitre_techniques'):
                techniques = ', '.join(finding['mitre_techniques'])
                lines.append(f"{detail_prefix}MITRE: {techniques}")
            
            if not is_last_finding and j < len(provider_findings) - 1:
                if not is_last_provider:
                    lines.append("│  │")
        
        if not is_last_provider:
            lines.append("│")
    
    lines.append("")
    lines.append("=" * 60)
    lines.append(f"Total Findings: {len(findings)}")
    
    # Count by severity
    severity_counts = {}
    for finding in findings:
        sev = finding.get('severity', 'INFO').upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        if sev in severity_counts:
            lines.append(f"{sev}: {severity_counts[sev]}")
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


__all__ = ['export_tree']
