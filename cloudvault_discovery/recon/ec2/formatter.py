"""
EC2 Output Formatter
Tree-style and other output formatters for EC2 enumeration results
"""

from typing import Dict, Any, List

from .models import SecurityRisk


def format_tree(results: Dict[str, Any]) -> str:
    """Format enumeration results as tree"""
    lines = []
    
    lines.append("🖥️  EC2 Instance Enumeration")
    lines.append("═" * 60)
    lines.append("")
    
    for region, data in results.get('regions', {}).items():
        instances = data.get('instances', [])
        if not instances:
            continue
        
        lines.append(f"📍 Region: {region}")
        lines.append(f"Found {len(instances)} instances")
        lines.append("")
        
        for i, inst in enumerate(instances):
            is_last = i == len(instances) - 1
            prefix = "└──" if is_last else "├──"
            child_prefix = "    " if is_last else "│   "
            
            state_emoji = "🟢" if inst.state == 'running' else "🔴" if inst.state == 'stopped' else "🟡"
            lines.append(f"{prefix} {state_emoji} {inst.instance_id} ({inst.state})")
            
            if inst.public_ip:
                lines.append(f"{child_prefix}├── 🌐 Public IP:  {inst.public_ip} ({inst.public_dns})")
            if inst.private_ip:
                lines.append(f"{child_prefix}├── 🔒 Private IP: {inst.private_ip} ({inst.private_dns})")
            
            lines.append(f"{child_prefix}├── 📋 Type: {inst.instance_type}")
            
            if inst.key_name:
                lines.append(f"{child_prefix}├── 🔑 Key: {inst.key_name}")
            
            if inst.iam_role:
                role_name = inst.iam_role.split('/')[-1] if '/' in inst.iam_role else inst.iam_role
                lines.append(f"{child_prefix}├── 👤 IAM Role: {role_name}")
            
            # Security groups
            if inst.security_groups:
                lines.append(f"{child_prefix}├── 🛡️  Security Groups:")
                for sg in inst.security_groups:
                    if sg.has_ssh_exposed or sg.has_rdp_exposed:
                        warn = "⚠️ " + ("SSH" if sg.has_ssh_exposed else "") + \
                               (" + " if sg.has_ssh_exposed and sg.has_rdp_exposed else "") + \
                               ("RDP" if sg.has_rdp_exposed else "") + " OPEN to 0.0.0.0/0"
                        lines.append(f"{child_prefix}│   ├── ⚠️  {sg.group_id} [{sg.group_name}] - {warn}")
                    else:
                        lines.append(f"{child_prefix}│   ├── ✅ {sg.group_id} [{sg.group_name}]")
            
            # Tags
            if inst.tags:
                lines.append(f"{child_prefix}└── 🏷️  Tags:")
                tag_items = list(inst.tags.items())[:5]  # Limit to 5 tags
                for j, (key, value) in enumerate(tag_items):
                    tag_prefix = "└──" if j == len(tag_items) - 1 else "├──"
                    lines.append(f"{child_prefix}    {tag_prefix} {key}: {value}")
            
            lines.append("")
        
        lines.append("")
    
    # Security findings summary
    findings = results.get('findings', [])
    if findings:
        lines.append("🔒 Security Analysis")
        lines.append("─" * 60)
        
        critical = [f for f in findings if f.severity == SecurityRisk.CRITICAL]
        high = [f for f in findings if f.severity == SecurityRisk.HIGH]
        medium = [f for f in findings if f.severity == SecurityRisk.MEDIUM]
        
        if critical:
            lines.append(f"⚠️  CRITICAL: {len(critical)} finding(s)")
        if high:
            lines.append(f"⚠️  HIGH: {len(high)} finding(s)")
        if medium:
            lines.append(f"⚠️  MEDIUM: {len(medium)} finding(s)")
        
        lines.append("")
        
        # MITRE ATT&CK mapping
        all_techniques = set()
        for finding in findings:
            all_techniques.update(finding.mitre_techniques)
        
        if all_techniques:
            lines.append("📊 MITRE ATT&CK Mapping")
            technique_list = sorted(list(all_techniques))
            for i, tech in enumerate(technique_list):
                prefix = "└──" if i == len(technique_list) - 1 else "├──"
                lines.append(f"{prefix} {tech}")
    
    return "\n".join(lines)


def format_json(results: Dict[str, Any]) -> Dict[str, Any]:
    """Format results for JSON output"""
    return {
        'summary': results['summary'],
        'findings': [
            {
                'type': f.finding_type,
                'severity': f.severity.value,
                'resource_id': f.resource_id,
                'resource_type': f.resource_type,
                'region': f.region,
                'title': f.title,
                'description': f.description,
                'recommendation': f.recommendation,
                'mitre_techniques': f.mitre_techniques
            }
            for f in results.get('findings', [])
        ],
        'regions': {
            region: {
                'instance_count': len(data.get('instances', [])),
                'instances': [
                    {
                        'id': inst.instance_id,
                        'name': inst.name,
                        'state': inst.state,
                        'type': inst.instance_type,
                        'public_ip': inst.public_ip,
                        'private_ip': inst.private_ip,
                        'has_exposed_ssh': inst.has_exposed_ssh,
                        'has_exposed_rdp': inst.has_exposed_rdp
                    }
                    for inst in data.get('instances', [])
                ]
            }
            for region, data in results.get('regions', {}).items()
        }
    }


__all__ = ['format_tree', 'format_json']
