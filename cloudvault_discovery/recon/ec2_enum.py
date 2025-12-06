"""
AWS EC2 Enumeration Module
Re-exports from ec2 package for backward compatibility
"""

# Re-export everything from the ec2 package
from .ec2 import (
    # Main enumerator
    EC2Enumerator,
    AWS_REGIONS,
    
    # Models
    EC2State,
    SecurityRisk,
    SecurityGroupRule,
    SecurityGroup,
    EBSVolume,
    EBSSnapshot,
    EC2Instance,
    EC2Finding,
    
    # Security
    analyze_instance_security,
    analyze_snapshot_security,
    MITRE_TECHNIQUES,
    
    # Metadata/SSRF
    METADATA_ENDPOINTS,
    IMDSV2_TOKEN_ENDPOINT,
    SSRF_BYPASSES,
    get_ssrf_patterns,
    
    # Formatters
    format_tree,
    format_json
)


__all__ = [
    'EC2Enumerator',
    'AWS_REGIONS',
    'EC2State',
    'SecurityRisk',
    'SecurityGroupRule',
    'SecurityGroup',
    'EBSVolume',
    'EBSSnapshot',
    'EC2Instance',
    'EC2Finding',
    'analyze_instance_security',
    'analyze_snapshot_security',
    'MITRE_TECHNIQUES',
    'METADATA_ENDPOINTS',
    'IMDSV2_TOKEN_ENDPOINT',
    'SSRF_BYPASSES',
    'get_ssrf_patterns',
    'format_tree',
    'format_json'
]
