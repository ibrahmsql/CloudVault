"""
EC2 Enumeration Package
Comprehensive AWS EC2 instance discovery and security analysis
"""

from .models import (
    EC2State,
    SecurityRisk,
    SecurityGroupRule,
    SecurityGroup,
    EBSVolume,
    EBSSnapshot,
    EC2Instance,
    EC2Finding
)

from .enumerator import EC2Enumerator, AWS_REGIONS

from .security import (
    analyze_instance_security,
    analyze_snapshot_security,
    MITRE_TECHNIQUES
)

from .metadata import (
    METADATA_ENDPOINTS,
    IMDSV2_TOKEN_ENDPOINT,
    SSRF_BYPASSES,
    get_ssrf_patterns
)

from .formatter import format_tree, format_json


__all__ = [
    # Main enumerator
    'EC2Enumerator',
    'AWS_REGIONS',
    
    # Models
    'EC2State',
    'SecurityRisk',
    'SecurityGroupRule',
    'SecurityGroup',
    'EBSVolume',
    'EBSSnapshot',
    'EC2Instance',
    'EC2Finding',
    
    # Security
    'analyze_instance_security',
    'analyze_snapshot_security',
    'MITRE_TECHNIQUES',
    
    # Metadata/SSRF
    'METADATA_ENDPOINTS',
    'IMDSV2_TOKEN_ENDPOINT',
    'SSRF_BYPASSES',
    'get_ssrf_patterns',
    
    # Formatters
    'format_tree',
    'format_json'
]
