"""
Azure VM Enumerator
Azure Virtual Machine discovery and security analysis
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class AzureRisk(Enum):
    """Azure security risk levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class AzureVM:
    """Azure Virtual Machine details"""
    name: str
    resource_id: str
    resource_group: str
    location: str
    vm_size: str = ""
    os_type: str = ""
    os_disk_name: str = ""
    provisioning_state: str = ""
    public_ip: str = ""
    private_ip: str = ""
    nsg_id: str = ""
    subnet_id: str = ""
    managed_identity: Dict[str, Any] = field(default_factory=dict)
    extensions: List[str] = field(default_factory=list)
    disk_encryption: bool = False
    tags: Dict[str, str] = field(default_factory=dict)
    
    @property
    def has_public_ip(self) -> bool:
        return bool(self.public_ip)
    
    @property
    def has_managed_identity(self) -> bool:
        return bool(self.managed_identity)


@dataclass
class AzureNSG:
    """Azure Network Security Group"""
    name: str
    resource_id: str
    resource_group: str
    location: str
    rules: List[Dict[str, Any]] = field(default_factory=list)
    
    @property
    def has_open_ssh(self) -> bool:
        for rule in self.rules:
            if rule.get('access') == 'Allow' and rule.get('direction') == 'Inbound':
                if rule.get('destination_port_range') in ['22', '*', '22-22']:
                    source = rule.get('source_address_prefix', '')
                    if source in ['*', 'Internet', '0.0.0.0/0']:
                        return True
        return False
    
    @property
    def has_open_rdp(self) -> bool:
        for rule in self.rules:
            if rule.get('access') == 'Allow' and rule.get('direction') == 'Inbound':
                if rule.get('destination_port_range') in ['3389', '*', '3389-3389']:
                    source = rule.get('source_address_prefix', '')
                    if source in ['*', 'Internet', '0.0.0.0/0']:
                        return True
        return False


@dataclass
class AzureFinding:
    """Security finding for Azure"""
    finding_type: str
    severity: AzureRisk
    resource_id: str
    resource_type: str
    title: str
    description: str
    recommendation: str = ""
    mitre_techniques: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


MITRE_AZURE_TECHNIQUES = {
    'valid_accounts': 'T1078',
    'cloud_compute': 'T1578',
    'cloud_instance_metadata': 'T1552.005',
    'remote_services': 'T1021',
    'account_discovery': 'T1087.004',
}


# Azure metadata endpoints for SSRF
AZURE_METADATA_ENDPOINTS = {
    'base': 'http://169.254.169.254/metadata/instance',
    'identity': 'http://169.254.169.254/metadata/identity/oauth2/token',
    'instance': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
    'attested': 'http://169.254.169.254/metadata/attested/document',
}


class AzureVMEnumerator:
    """
    Azure VM Enumerator
    
    Discovers Azure VMs, NSGs, and analyzes security.
    Uses Azure SDK for Python (azure-mgmt-compute, azure-identity).
    """
    
    def __init__(self,
                 subscription_id: Optional[str] = None,
                 credential: Optional[Any] = None):
        self.subscription_id = subscription_id
        self.credential = credential
        self._compute_client = None
        self._network_client = None
    
    def _get_credential(self):
        """Get Azure credential"""
        if self.credential:
            return self.credential
        
        try:
            from azure.identity import DefaultAzureCredential
            return DefaultAzureCredential()
        except ImportError:
            raise ImportError("azure-identity required: pip install azure-identity azure-mgmt-compute azure-mgmt-network")
    
    def _get_compute_client(self):
        """Get compute management client"""
        if not self._compute_client:
            try:
                from azure.mgmt.compute import ComputeManagementClient
                credential = self._get_credential()
                self._compute_client = ComputeManagementClient(credential, self.subscription_id)
            except ImportError:
                raise ImportError("azure-mgmt-compute required")
        return self._compute_client
    
    def _get_network_client(self):
        """Get network management client"""
        if not self._network_client:
            try:
                from azure.mgmt.network import NetworkManagementClient
                credential = self._get_credential()
                self._network_client = NetworkManagementClient(credential, self.subscription_id)
            except ImportError:
                raise ImportError("azure-mgmt-network required")
        return self._network_client
    
    def enumerate_vms(self, resource_group: Optional[str] = None) -> List[AzureVM]:
        """Enumerate Azure VMs"""
        vms = []
        
        try:
            compute = self._get_compute_client()
            network = self._get_network_client()
            
            if resource_group:
                vm_list = compute.virtual_machines.list(resource_group)
            else:
                vm_list = compute.virtual_machines.list_all()
            
            for vm in vm_list:
                # Get public IP if exists
                public_ip = ""
                private_ip = ""
                
                try:
                    for nic_ref in vm.network_profile.network_interfaces:
                        nic_name = nic_ref.id.split('/')[-1]
                        rg = nic_ref.id.split('/')[4]
                        nic = network.network_interfaces.get(rg, nic_name)
                        
                        for ip_config in nic.ip_configurations:
                            if ip_config.private_ip_address:
                                private_ip = ip_config.private_ip_address
                            if ip_config.public_ip_address:
                                pip_id = ip_config.public_ip_address.id
                                pip_name = pip_id.split('/')[-1]
                                pip_rg = pip_id.split('/')[4]
                                pip = network.public_ip_addresses.get(pip_rg, pip_name)
                                public_ip = pip.ip_address or ""
                except Exception as e:
                    logger.debug(f"Error getting IP for {vm.name}: {e}")
                
                # Get extensions
                extensions = []
                try:
                    ext_list = compute.virtual_machine_extensions.list(
                        vm.id.split('/')[4], vm.name
                    )
                    extensions = [e.name for e in ext_list.value] if ext_list.value else []
                except Exception:
                    pass
                
                azure_vm = AzureVM(
                    name=vm.name,
                    resource_id=vm.id,
                    resource_group=vm.id.split('/')[4],
                    location=vm.location,
                    vm_size=vm.hardware_profile.vm_size if vm.hardware_profile else "",
                    os_type=vm.storage_profile.os_disk.os_type if vm.storage_profile else "",
                    os_disk_name=vm.storage_profile.os_disk.name if vm.storage_profile else "",
                    provisioning_state=vm.provisioning_state or "",
                    public_ip=public_ip,
                    private_ip=private_ip,
                    managed_identity=vm.identity.as_dict() if vm.identity else {},
                    extensions=extensions,
                    tags=dict(vm.tags) if vm.tags else {}
                )
                vms.append(azure_vm)
                
        except Exception as e:
            logger.error(f"Error enumerating Azure VMs: {e}")
        
        return vms
    
    def enumerate_nsgs(self, resource_group: Optional[str] = None) -> List[AzureNSG]:
        """Enumerate NSGs"""
        nsgs = []
        
        try:
            network = self._get_network_client()
            
            if resource_group:
                nsg_list = network.network_security_groups.list(resource_group)
            else:
                nsg_list = network.network_security_groups.list_all()
            
            for nsg in nsg_list:
                rules = []
                
                for rule in (nsg.security_rules or []):
                    rules.append({
                        'name': rule.name,
                        'priority': rule.priority,
                        'access': rule.access,
                        'direction': rule.direction,
                        'protocol': rule.protocol,
                        'source_address_prefix': rule.source_address_prefix,
                        'source_port_range': rule.source_port_range,
                        'destination_address_prefix': rule.destination_address_prefix,
                        'destination_port_range': rule.destination_port_range,
                    })
                
                azure_nsg = AzureNSG(
                    name=nsg.name,
                    resource_id=nsg.id,
                    resource_group=nsg.id.split('/')[4],
                    location=nsg.location,
                    rules=rules
                )
                nsgs.append(azure_nsg)
                
        except Exception as e:
            logger.error(f"Error enumerating NSGs: {e}")
        
        return nsgs
    
    def analyze_security(self,
                        vms: List[AzureVM],
                        nsgs: List[AzureNSG]) -> List[AzureFinding]:
        """Analyze Azure resources for security issues"""
        findings = []
        
        for vm in vms:
            # Public IP exposure
            if vm.has_public_ip:
                findings.append(AzureFinding(
                    finding_type='PUBLIC_VM',
                    severity=AzureRisk.MEDIUM,
                    resource_id=vm.resource_id,
                    resource_type='VirtualMachine',
                    title='VM Has Public IP',
                    description=f"VM {vm.name} has public IP {vm.public_ip}",
                    recommendation='Use Azure Bastion or VPN for access',
                    mitre_techniques=[MITRE_AZURE_TECHNIQUES['remote_services']],
                    metadata={'public_ip': vm.public_ip}
                ))
            
            # No encryption
            if not vm.disk_encryption:
                findings.append(AzureFinding(
                    finding_type='UNENCRYPTED_DISK',
                    severity=AzureRisk.MEDIUM,
                    resource_id=vm.resource_id,
                    resource_type='VirtualMachine',
                    title='VM Disk Not Encrypted',
                    description=f"VM {vm.name} does not have disk encryption enabled",
                    recommendation='Enable Azure Disk Encryption'
                ))
        
        for nsg in nsgs:
            # Open SSH
            if nsg.has_open_ssh:
                findings.append(AzureFinding(
                    finding_type='OPEN_SSH',
                    severity=AzureRisk.CRITICAL,
                    resource_id=nsg.resource_id,
                    resource_type='NetworkSecurityGroup',
                    title='NSG Allows SSH from Internet',
                    description=f"NSG {nsg.name} allows SSH (22) from any source",
                    recommendation='Restrict SSH to specific IPs or use Azure Bastion',
                    mitre_techniques=[MITRE_AZURE_TECHNIQUES['remote_services']]
                ))
            
            # Open RDP
            if nsg.has_open_rdp:
                findings.append(AzureFinding(
                    finding_type='OPEN_RDP',
                    severity=AzureRisk.CRITICAL,
                    resource_id=nsg.resource_id,
                    resource_type='NetworkSecurityGroup',
                    title='NSG Allows RDP from Internet',
                    description=f"NSG {nsg.name} allows RDP (3389) from any source",
                    recommendation='Restrict RDP to specific IPs or use Azure Bastion',
                    mitre_techniques=[MITRE_AZURE_TECHNIQUES['remote_services']]
                ))
        
        return findings
    
    def enumerate_all(self) -> Dict[str, Any]:
        """Enumerate all Azure VM resources"""
        results = {
            'vms': [],
            'nsgs': [],
            'findings': [],
            'summary': {
                'total_vms': 0,
                'public_vms': 0,
                'total_nsgs': 0,
                'insecure_nsgs': 0,
                'total_findings': 0
            }
        }
        
        vms = self.enumerate_vms()
        nsgs = self.enumerate_nsgs()
        
        results['vms'] = vms
        results['nsgs'] = nsgs
        
        # Analyze security
        findings = self.analyze_security(vms, nsgs)
        results['findings'] = findings
        
        # Update summary
        results['summary']['total_vms'] = len(vms)
        results['summary']['public_vms'] = len([v for v in vms if v.has_public_ip])
        results['summary']['total_nsgs'] = len(nsgs)
        results['summary']['insecure_nsgs'] = len([n for n in nsgs if n.has_open_ssh or n.has_open_rdp])
        results['summary']['total_findings'] = len(findings)
        
        return results
    
    @staticmethod
    def get_metadata_ssrf_patterns() -> Dict[str, Any]:
        """Get Azure IMDS SSRF patterns for testing"""
        return {
            'endpoints': AZURE_METADATA_ENDPOINTS,
            'headers': {'Metadata': 'true'},
            'example_identity_request': (
                'curl -H "Metadata: true" '
                '"http://169.254.169.254/metadata/identity/oauth2/token'
                '?api-version=2018-02-01&resource=https://management.azure.com/"'
            ),
            'bypasses': [
                'http://169.254.169.254/metadata/instance',
                'http://[::ffff:a9fe:a9fe]/metadata/instance',
                'http://169.254.169.254%00/metadata/instance',
            ]
        }


__all__ = [
    'AzureVMEnumerator',
    'AzureVM',
    'AzureNSG',
    'AzureFinding',
    'AZURE_METADATA_ENDPOINTS'
]
