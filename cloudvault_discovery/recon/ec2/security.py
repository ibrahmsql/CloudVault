"""
EC2 Security Analyzer
Security analysis and MITRE ATT&CK mapping for EC2 resources
"""

import logging
from typing import List, Dict, Any

from .models import (
    EC2Instance, SecurityGroup, EBSSnapshot, 
    EC2Finding, SecurityRisk
)

logger = logging.getLogger(__name__)


# MITRE ATT&CK techniques
MITRE_TECHNIQUES = {
    'credential_access': 'T1552.001',  # Credentials In Files
    'valid_accounts': 'T1078',  # Valid Accounts
    'data_from_cloud': 'T1530',  # Data from Cloud Storage Object
    'exfiltration': 'T1537',  # Transfer Data to Cloud Account
    'network_service_discovery': 'T1046',  # Network Service Discovery
    'cloud_infrastructure_discovery': 'T1580',  # Cloud Infrastructure Discovery
    'remote_services': 'T1021',  # Remote Services
    'ssh': 'T1021.004',  # SSH
    'rdp': 'T1021.001',  # Remote Desktop Protocol
}


def analyze_instance_security(instances: List[EC2Instance]) -> List[EC2Finding]:
    """
    Analyze EC2 instances for security issues.
    
    Args:
        instances: List of EC2Instance objects
        
    Returns:
        List of EC2Finding objects
    """
    findings = []
    
    for instance in instances:
        # Check for exposed SSH
        if instance.has_exposed_ssh:
            findings.append(EC2Finding(
                finding_type='EXPOSED_SSH',
                severity=SecurityRisk.CRITICAL,
                resource_id=instance.instance_id,
                resource_type='EC2Instance',
                region=instance.region,
                title='SSH Exposed to Internet',
                description=f"Instance {instance.name} ({instance.instance_id}) has SSH (port 22) "
                           f"exposed to the internet via public IP {instance.public_ip}",
                recommendation='Restrict SSH access to specific IP ranges or use AWS Systems Manager Session Manager',
                mitre_techniques=[
                    MITRE_TECHNIQUES['ssh'],
                    MITRE_TECHNIQUES['remote_services']
                ],
                metadata={
                    'public_ip': instance.public_ip,
                    'security_groups': [sg.group_id for sg in instance.security_groups if sg.has_ssh_exposed]
                }
            ))
        
        # Check for exposed RDP
        if instance.has_exposed_rdp:
            findings.append(EC2Finding(
                finding_type='EXPOSED_RDP',
                severity=SecurityRisk.CRITICAL,
                resource_id=instance.instance_id,
                resource_type='EC2Instance',
                region=instance.region,
                title='RDP Exposed to Internet',
                description=f"Instance {instance.name} ({instance.instance_id}) has RDP (port 3389) "
                           f"exposed to the internet via public IP {instance.public_ip}",
                recommendation='Restrict RDP access to specific IP ranges or use AWS Systems Manager Session Manager',
                mitre_techniques=[
                    MITRE_TECHNIQUES['rdp'],
                    MITRE_TECHNIQUES['remote_services']
                ],
                metadata={
                    'public_ip': instance.public_ip,
                    'security_groups': [sg.group_id for sg in instance.security_groups if sg.has_rdp_exposed]
                }
            ))
        
        # Check for overly permissive security groups
        for sg in instance.security_groups:
            exposed = sg.exposed_ports
            if exposed:
                # Filter out already reported SSH/RDP
                other_exposed = [p for p in exposed 
                               if not (p['from_port'] == 22 or p['from_port'] == 3389)]
                if other_exposed:
                    findings.append(EC2Finding(
                        finding_type='OVERLY_PERMISSIVE_SG',
                        severity=SecurityRisk.HIGH,
                        resource_id=sg.group_id,
                        resource_type='SecurityGroup',
                        region=instance.region,
                        title='Overly Permissive Security Group',
                        description=f"Security group {sg.group_name} ({sg.group_id}) allows traffic "
                                   f"from 0.0.0.0/0 on {len(other_exposed)} port(s)",
                        recommendation='Review and restrict inbound rules to specific IP ranges',
                        mitre_techniques=[
                            MITRE_TECHNIQUES['network_service_discovery'],
                            MITRE_TECHNIQUES['cloud_infrastructure_discovery']
                        ],
                        metadata={
                            'exposed_ports': other_exposed,
                            'attached_to': instance.instance_id
                        }
                    ))
        
        # Check for public IP without IAM role
        if instance.is_public and not instance.iam_role:
            findings.append(EC2Finding(
                finding_type='PUBLIC_NO_IAM_ROLE',
                severity=SecurityRisk.MEDIUM,
                resource_id=instance.instance_id,
                resource_type='EC2Instance',
                region=instance.region,
                title='Public Instance Without IAM Role',
                description=f"Public instance {instance.name} ({instance.instance_id}) has no IAM role attached. "
                           "Applications may be using hardcoded credentials.",
                recommendation='Attach an IAM role with least-privilege permissions',
                mitre_techniques=[
                    MITRE_TECHNIQUES['credential_access']
                ],
                metadata={
                    'public_ip': instance.public_ip
                }
            ))
    
    return findings


def analyze_snapshot_security(snapshots: List[EBSSnapshot]) -> List[EC2Finding]:
    """Analyze snapshots for security issues"""
    findings = []
    
    for snapshot in snapshots:
        # Check for public snapshots
        if snapshot.is_public:
            findings.append(EC2Finding(
                finding_type='PUBLIC_SNAPSHOT',
                severity=SecurityRisk.CRITICAL,
                resource_id=snapshot.snapshot_id,
                resource_type='EBSSnapshot',
                region='global',
                title='Public EBS Snapshot',
                description=f"EBS snapshot {snapshot.snapshot_id} is publicly accessible. "
                           "May contain sensitive data.",
                recommendation='Make snapshot private and audit for sensitive data exposure',
                mitre_techniques=[
                    MITRE_TECHNIQUES['data_from_cloud']
                ],
                metadata={
                    'volume_id': snapshot.volume_id,
                    'size_gb': snapshot.volume_size,
                    'encrypted': snapshot.encrypted
                }
            ))
        
        # Check for unencrypted snapshots
        if not snapshot.encrypted:
            findings.append(EC2Finding(
                finding_type='UNENCRYPTED_SNAPSHOT',
                severity=SecurityRisk.MEDIUM,
                resource_id=snapshot.snapshot_id,
                resource_type='EBSSnapshot',
                region='global',
                title='Unencrypted EBS Snapshot',
                description=f"EBS snapshot {snapshot.snapshot_id} is not encrypted.",
                recommendation='Create encrypted copy and delete unencrypted snapshot',
                mitre_techniques=[
                    MITRE_TECHNIQUES['data_from_cloud']
                ],
                metadata={
                    'volume_id': snapshot.volume_id,
                    'size_gb': snapshot.volume_size
                }
            ))
    
    return findings


__all__ = [
    'analyze_instance_security',
    'analyze_snapshot_security',
    'MITRE_TECHNIQUES'
]
