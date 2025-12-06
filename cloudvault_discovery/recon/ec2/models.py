"""
EC2 Data Models
Dataclasses for EC2 enumeration results
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum


class EC2State(Enum):
    """EC2 instance states"""
    PENDING = "pending"
    RUNNING = "running"
    SHUTTING_DOWN = "shutting-down"
    TERMINATED = "terminated"
    STOPPING = "stopping"
    STOPPED = "stopped"


class SecurityRisk(Enum):
    """Security risk levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SecurityGroupRule:
    """Security group rule details"""
    protocol: str
    from_port: int
    to_port: int
    cidr_blocks: List[str] = field(default_factory=list)
    ipv6_cidr_blocks: List[str] = field(default_factory=list)
    prefix_list_ids: List[str] = field(default_factory=list)
    security_groups: List[str] = field(default_factory=list)
    description: str = ""
    
    @property
    def is_open_to_world(self) -> bool:
        """Check if rule allows traffic from anywhere"""
        return "0.0.0.0/0" in self.cidr_blocks or "::/0" in self.ipv6_cidr_blocks
    
    @property
    def is_ssh(self) -> bool:
        """Check if rule is for SSH"""
        return self.from_port <= 22 <= self.to_port and self.protocol in ["tcp", "-1"]
    
    @property
    def is_rdp(self) -> bool:
        """Check if rule is for RDP"""
        return self.from_port <= 3389 <= self.to_port and self.protocol in ["tcp", "-1"]


@dataclass
class SecurityGroup:
    """Security group details"""
    group_id: str
    group_name: str
    description: str = ""
    vpc_id: str = ""
    owner_id: str = ""
    inbound_rules: List[SecurityGroupRule] = field(default_factory=list)
    outbound_rules: List[SecurityGroupRule] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)
    
    @property
    def has_ssh_exposed(self) -> bool:
        """Check if SSH is exposed to internet"""
        return any(r.is_ssh and r.is_open_to_world for r in self.inbound_rules)
    
    @property
    def has_rdp_exposed(self) -> bool:
        """Check if RDP is exposed to internet"""
        return any(r.is_rdp and r.is_open_to_world for r in self.inbound_rules)
    
    @property
    def exposed_ports(self) -> List[Dict[str, Any]]:
        """Get all ports exposed to internet"""
        exposed = []
        for rule in self.inbound_rules:
            if rule.is_open_to_world:
                exposed.append({
                    'protocol': rule.protocol,
                    'from_port': rule.from_port,
                    'to_port': rule.to_port,
                    'cidr': '0.0.0.0/0' if '0.0.0.0/0' in rule.cidr_blocks else '::/0'
                })
        return exposed


@dataclass
class EBSVolume:
    """EBS volume details"""
    volume_id: str
    size: int  # GiB
    volume_type: str
    state: str
    encrypted: bool = False
    iops: Optional[int] = None
    snapshot_id: str = ""
    availability_zone: str = ""
    create_time: str = ""
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class EBSSnapshot:
    """EBS snapshot details"""
    snapshot_id: str
    volume_id: str
    volume_size: int
    state: str
    owner_id: str
    encrypted: bool = False
    description: str = ""
    start_time: str = ""
    progress: str = ""
    is_public: bool = False
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class EC2Instance:
    """EC2 instance details"""
    instance_id: str
    instance_type: str
    state: str
    region: str
    availability_zone: str = ""
    public_ip: str = ""
    private_ip: str = ""
    public_dns: str = ""
    private_dns: str = ""
    launch_time: str = ""
    key_name: str = ""
    platform: str = "linux"
    architecture: str = "x86_64"
    vpc_id: str = ""
    subnet_id: str = ""
    ami_id: str = ""
    iam_role: str = ""
    security_groups: List[SecurityGroup] = field(default_factory=list)
    volumes: List[EBSVolume] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)
    hypervisor: str = ""
    
    @property
    def name(self) -> str:
        """Get instance name from tags"""
        return self.tags.get('Name', self.instance_id)
    
    @property
    def is_public(self) -> bool:
        """Check if instance has public IP"""
        return bool(self.public_ip)
    
    @property
    def has_exposed_ssh(self) -> bool:
        """Check if SSH is exposed to internet"""
        return self.is_public and any(sg.has_ssh_exposed for sg in self.security_groups)
    
    @property
    def has_exposed_rdp(self) -> bool:
        """Check if RDP is exposed to internet"""
        return self.is_public and any(sg.has_rdp_exposed for sg in self.security_groups)


@dataclass
class EC2Finding:
    """Security finding for EC2"""
    finding_type: str
    severity: SecurityRisk
    resource_id: str
    resource_type: str
    region: str
    title: str
    description: str
    recommendation: str = ""
    mitre_techniques: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


__all__ = [
    'EC2State',
    'SecurityRisk',
    'SecurityGroupRule',
    'SecurityGroup',
    'EBSVolume',
    'EBSSnapshot',
    'EC2Instance',
    'EC2Finding'
]
