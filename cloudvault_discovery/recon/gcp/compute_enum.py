"""
GCP Compute Enumerator
Google Cloud VM instance discovery and security analysis
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class GCPRisk(Enum):
    """GCP security risk levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class GCPInstance:
    """GCP Compute Engine instance details"""
    name: str
    instance_id: str
    project: str
    zone: str
    machine_type: str = ""
    status: str = ""
    internal_ip: str = ""
    external_ip: str = ""
    service_account: str = ""
    service_account_scopes: List[str] = field(default_factory=list)
    network: str = ""
    subnetwork: str = ""
    can_ip_forward: bool = False
    deletion_protection: bool = False
    shielded_vm: Dict[str, bool] = field(default_factory=dict)
    metadata: Dict[str, str] = field(default_factory=dict)
    labels: Dict[str, str] = field(default_factory=dict)
    disks: List[Dict] = field(default_factory=list)
    
    @property
    def has_external_ip(self) -> bool:
        return bool(self.external_ip)
    
    @property
    def has_ssh_keys_in_metadata(self) -> bool:
        return 'ssh-keys' in self.metadata or 'sshKeys' in self.metadata
    
    @property
    def has_full_cloud_access(self) -> bool:
        """Check if instance has cloud-platform scope (full access)"""
        full_scopes = [
            'https://www.googleapis.com/auth/cloud-platform',
            'https://www.googleapis.com/auth/compute',
        ]
        return any(s in self.service_account_scopes for s in full_scopes)


@dataclass
class GCPFirewallRule:
    """GCP firewall rule details"""
    name: str
    network: str
    direction: str
    priority: int
    allowed: List[Dict] = field(default_factory=list)
    denied: List[Dict] = field(default_factory=list)
    source_ranges: List[str] = field(default_factory=list)
    target_tags: List[str] = field(default_factory=list)
    
    @property
    def allows_ssh_from_internet(self) -> bool:
        if '0.0.0.0/0' not in self.source_ranges:
            return False
        for allowed in self.allowed:
            ports = allowed.get('ports', [])
            if allowed.get('IPProtocol') == 'tcp':
                if '22' in ports or not ports:  # Empty means all ports
                    return True
        return False
    
    @property
    def allows_rdp_from_internet(self) -> bool:
        if '0.0.0.0/0' not in self.source_ranges:
            return False
        for allowed in self.allowed:
            ports = allowed.get('ports', [])
            if allowed.get('IPProtocol') == 'tcp':
                if '3389' in ports:
                    return True
        return False


@dataclass
class GCPFinding:
    """Security finding for GCP"""
    finding_type: str
    severity: GCPRisk
    resource_id: str
    resource_type: str
    title: str
    description: str
    recommendation: str = ""
    mitre_techniques: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


MITRE_GCP_TECHNIQUES = {
    'valid_accounts': 'T1078.004',
    'cloud_instance_metadata': 'T1552.005',
    'remote_services': 'T1021',
    'steal_service_account': 'T1528',
    'cloud_compute': 'T1578',
}


# GCP metadata endpoints for SSRF
GCP_METADATA_ENDPOINTS = {
    'base': 'http://metadata.google.internal/computeMetadata/v1/',
    'project': 'http://metadata.google.internal/computeMetadata/v1/project/',
    'instance': 'http://metadata.google.internal/computeMetadata/v1/instance/',
    'service_account': 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/',
    'access_token': 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
    'identity_token': 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity',
    'ssh_keys': 'http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys',
    'kube_env': 'http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env',
}


class GCPComputeEnumerator:
    """
    GCP Compute Enumerator
    
    Discovers GCP VM instances, firewall rules, and analyzes security.
    Uses Google Cloud SDK (google-cloud-compute).
    """
    
    def __init__(self,
                 project_id: Optional[str] = None,
                 credentials: Optional[Any] = None):
        self.project_id = project_id
        self.credentials = credentials
        self._instance_client = None
        self._firewall_client = None
    
    def _get_instance_client(self):
        """Get compute instances client"""
        if not self._instance_client:
            try:
                from google.cloud import compute_v1
                self._instance_client = compute_v1.InstancesClient(credentials=self.credentials)
            except ImportError:
                raise ImportError("google-cloud-compute required: pip install google-cloud-compute")
        return self._instance_client
    
    def _get_firewall_client(self):
        """Get firewall client"""
        if not self._firewall_client:
            try:
                from google.cloud import compute_v1
                self._firewall_client = compute_v1.FirewallsClient(credentials=self.credentials)
            except ImportError:
                raise ImportError("google-cloud-compute required")
        return self._firewall_client
    
    def enumerate_instances(self, zone: Optional[str] = None) -> List[GCPInstance]:
        """Enumerate GCP instances"""
        instances = []
        
        try:
            client = self._get_instance_client()
            
            if zone:
                # Single zone
                request = {"project": self.project_id, "zone": zone}
                for instance in client.list(request=request):
                    instances.append(self._parse_instance(instance, zone))
            else:
                # All zones (aggregated list)
                from google.cloud.compute_v1 import AggregatedListInstancesRequest
                request = AggregatedListInstancesRequest(project=self.project_id)
                
                for zone_name, response in client.aggregated_list(request=request):
                    if response.instances:
                        for instance in response.instances:
                            z = zone_name.replace('zones/', '')
                            instances.append(self._parse_instance(instance, z))
                            
        except Exception as e:
            logger.error(f"Error enumerating GCP instances: {e}")
        
        return instances
    
    def _parse_instance(self, instance, zone: str) -> GCPInstance:
        """Parse GCP instance to dataclass"""
        # Get network info
        external_ip = ""
        internal_ip = ""
        network = ""
        subnetwork = ""
        
        if instance.network_interfaces:
            nic = instance.network_interfaces[0]
            internal_ip = nic.network_i_p or ""
            network = nic.network.split('/')[-1] if nic.network else ""
            subnetwork = nic.subnetwork.split('/')[-1] if nic.subnetwork else ""
            
            if nic.access_configs:
                external_ip = nic.access_configs[0].nat_i_p or ""
        
        # Get service account info
        sa_email = ""
        sa_scopes = []
        if instance.service_accounts:
            sa = instance.service_accounts[0]
            sa_email = sa.email or ""
            sa_scopes = list(sa.scopes) if sa.scopes else []
        
        # Get metadata
        metadata = {}
        if instance.metadata and instance.metadata.items:
            for item in instance.metadata.items:
                metadata[item.key] = item.value
        
        # Get shielded VM config
        shielded = {}
        if instance.shielded_instance_config:
            shielded = {
                'secure_boot': instance.shielded_instance_config.enable_secure_boot,
                'vtpm': instance.shielded_instance_config.enable_vtpm,
                'integrity_monitoring': instance.shielded_instance_config.enable_integrity_monitoring,
            }
        
        # Get disks
        disks = []
        if instance.disks:
            for disk in instance.disks:
                disks.append({
                    'name': disk.source.split('/')[-1] if disk.source else "",
                    'boot': disk.boot,
                    'auto_delete': disk.auto_delete,
                })
        
        return GCPInstance(
            name=instance.name,
            instance_id=str(instance.id),
            project=self.project_id,
            zone=zone,
            machine_type=instance.machine_type.split('/')[-1] if instance.machine_type else "",
            status=instance.status or "",
            internal_ip=internal_ip,
            external_ip=external_ip,
            service_account=sa_email,
            service_account_scopes=sa_scopes,
            network=network,
            subnetwork=subnetwork,
            can_ip_forward=instance.can_ip_forward or False,
            deletion_protection=instance.deletion_protection or False,
            shielded_vm=shielded,
            metadata=metadata,
            labels=dict(instance.labels) if instance.labels else {},
            disks=disks
        )
    
    def enumerate_firewall_rules(self) -> List[GCPFirewallRule]:
        """Enumerate firewall rules"""
        rules = []
        
        try:
            client = self._get_firewall_client()
            request = {"project": self.project_id}
            
            for rule in client.list(request=request):
                allowed = []
                for a in (rule.allowed or []):
                    allowed.append({
                        'IPProtocol': a.i_p_protocol,
                        'ports': list(a.ports) if a.ports else []
                    })
                
                denied = []
                for d in (rule.denied or []):
                    denied.append({
                        'IPProtocol': d.i_p_protocol,
                        'ports': list(d.ports) if d.ports else []
                    })
                
                gcp_rule = GCPFirewallRule(
                    name=rule.name,
                    network=rule.network.split('/')[-1] if rule.network else "",
                    direction=rule.direction or "INGRESS",
                    priority=rule.priority or 1000,
                    allowed=allowed,
                    denied=denied,
                    source_ranges=list(rule.source_ranges) if rule.source_ranges else [],
                    target_tags=list(rule.target_tags) if rule.target_tags else []
                )
                rules.append(gcp_rule)
                
        except Exception as e:
            logger.error(f"Error enumerating firewall rules: {e}")
        
        return rules
    
    def analyze_security(self,
                        instances: List[GCPInstance],
                        firewall_rules: List[GCPFirewallRule]) -> List[GCPFinding]:
        """Analyze GCP resources for security issues"""
        findings = []
        
        for instance in instances:
            # External IP
            if instance.has_external_ip:
                findings.append(GCPFinding(
                    finding_type='EXTERNAL_IP',
                    severity=GCPRisk.MEDIUM,
                    resource_id=f"{instance.project}/zones/{instance.zone}/instances/{instance.name}",
                    resource_type='Instance',
                    title='Instance Has External IP',
                    description=f"Instance {instance.name} has external IP {instance.external_ip}",
                    recommendation='Use Cloud NAT or IAP for access',
                    mitre_techniques=[MITRE_GCP_TECHNIQUES['remote_services']],
                    metadata={'external_ip': instance.external_ip}
                ))
            
            # Full cloud access scope
            if instance.has_full_cloud_access:
                findings.append(GCPFinding(
                    finding_type='OVERLY_PERMISSIVE_SA',
                    severity=GCPRisk.HIGH,
                    resource_id=f"{instance.project}/zones/{instance.zone}/instances/{instance.name}",
                    resource_type='Instance',
                    title='Instance Has Full Cloud Access',
                    description=f"Instance {instance.name} has cloud-platform or compute scope",
                    recommendation='Use minimal required scopes',
                    mitre_techniques=[MITRE_GCP_TECHNIQUES['steal_service_account']],
                    metadata={'service_account': instance.service_account}
                ))
            
            # SSH keys in metadata
            if instance.has_ssh_keys_in_metadata:
                findings.append(GCPFinding(
                    finding_type='SSH_KEYS_IN_METADATA',
                    severity=GCPRisk.LOW,
                    resource_id=f"{instance.project}/zones/{instance.zone}/instances/{instance.name}",
                    resource_type='Instance',
                    title='SSH Keys in Instance Metadata',
                    description=f"Instance {instance.name} has SSH keys stored in metadata",
                    recommendation='Use OS Login for SSH key management',
                    mitre_techniques=[MITRE_GCP_TECHNIQUES['valid_accounts']]
                ))
            
            # No shielded VM
            if not instance.shielded_vm.get('secure_boot'):
                findings.append(GCPFinding(
                    finding_type='NO_SHIELDED_VM',
                    severity=GCPRisk.LOW,
                    resource_id=f"{instance.project}/zones/{instance.zone}/instances/{instance.name}",
                    resource_type='Instance',
                    title='Shielded VM Not Enabled',
                    description=f"Instance {instance.name} does not have Secure Boot enabled",
                    recommendation='Enable Shielded VM features'
                ))
        
        for rule in firewall_rules:
            # Open SSH
            if rule.allows_ssh_from_internet:
                findings.append(GCPFinding(
                    finding_type='OPEN_SSH',
                    severity=GCPRisk.CRITICAL,
                    resource_id=f"{self.project_id}/global/firewalls/{rule.name}",
                    resource_type='FirewallRule',
                    title='Firewall Allows SSH from Internet',
                    description=f"Firewall rule {rule.name} allows SSH (22) from 0.0.0.0/0",
                    recommendation='Restrict to specific source IPs or use IAP',
                    mitre_techniques=[MITRE_GCP_TECHNIQUES['remote_services']]
                ))
            
            # Open RDP
            if rule.allows_rdp_from_internet:
                findings.append(GCPFinding(
                    finding_type='OPEN_RDP',
                    severity=GCPRisk.CRITICAL,
                    resource_id=f"{self.project_id}/global/firewalls/{rule.name}",
                    resource_type='FirewallRule',
                    title='Firewall Allows RDP from Internet',
                    description=f"Firewall rule {rule.name} allows RDP (3389) from 0.0.0.0/0",
                    recommendation='Restrict to specific source IPs or use IAP',
                    mitre_techniques=[MITRE_GCP_TECHNIQUES['remote_services']]
                ))
        
        return findings
    
    def enumerate_all(self) -> Dict[str, Any]:
        """Enumerate all GCP compute resources"""
        results = {
            'instances': [],
            'firewall_rules': [],
            'findings': [],
            'summary': {
                'total_instances': 0,
                'public_instances': 0,
                'overly_permissive': 0,
                'total_rules': 0,
                'insecure_rules': 0,
                'total_findings': 0
            }
        }
        
        instances = self.enumerate_instances()
        firewall_rules = self.enumerate_firewall_rules()
        
        results['instances'] = instances
        results['firewall_rules'] = firewall_rules
        
        # Analyze security
        findings = self.analyze_security(instances, firewall_rules)
        results['findings'] = findings
        
        # Update summary
        results['summary']['total_instances'] = len(instances)
        results['summary']['public_instances'] = len([i for i in instances if i.has_external_ip])
        results['summary']['overly_permissive'] = len([i for i in instances if i.has_full_cloud_access])
        results['summary']['total_rules'] = len(firewall_rules)
        results['summary']['insecure_rules'] = len([r for r in firewall_rules if r.allows_ssh_from_internet or r.allows_rdp_from_internet])
        results['summary']['total_findings'] = len(findings)
        
        return results
    
    @staticmethod
    def get_metadata_ssrf_patterns() -> Dict[str, Any]:
        """Get GCP metadata SSRF patterns for testing"""
        return {
            'endpoints': GCP_METADATA_ENDPOINTS,
            'headers': {'Metadata-Flavor': 'Google'},
            'example_token_request': (
                'curl -H "Metadata-Flavor: Google" '
                '"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"'
            ),
            'bypasses': [
                'http://metadata.google.internal/computeMetadata/v1/',
                'http://169.254.169.254/computeMetadata/v1/',
                'http://metadata/computeMetadata/v1/',
            ],
            'high_value_targets': [
                GCP_METADATA_ENDPOINTS['access_token'],
                GCP_METADATA_ENDPOINTS['kube_env'],
                GCP_METADATA_ENDPOINTS['ssh_keys'],
            ]
        }


__all__ = [
    'GCPComputeEnumerator',
    'GCPInstance',
    'GCPFirewallRule',
    'GCPFinding',
    'GCP_METADATA_ENDPOINTS'
]
