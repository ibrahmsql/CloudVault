"""
AWS EKS Enumerator
Kubernetes cluster discovery and security analysis
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class EKSRisk(Enum):
    """EKS security risk levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class EKSCluster:
    """EKS cluster details"""
    name: str
    arn: str
    region: str
    version: str = ""
    status: str = ""
    endpoint: str = ""
    role_arn: str = ""
    vpc_id: str = ""
    subnet_ids: List[str] = field(default_factory=list)
    security_group_ids: List[str] = field(default_factory=list)
    cluster_security_group_id: str = ""
    endpoint_public_access: bool = True
    endpoint_private_access: bool = False
    public_access_cidrs: List[str] = field(default_factory=list)
    encryption_config: Dict[str, Any] = field(default_factory=dict)
    logging_enabled: Dict[str, bool] = field(default_factory=dict)
    tags: Dict[str, str] = field(default_factory=dict)
    
    @property
    def is_public(self) -> bool:
        return self.endpoint_public_access
    
    @property
    def allows_all_ips(self) -> bool:
        return '0.0.0.0/0' in self.public_access_cidrs


@dataclass
class EKSNodeGroup:
    """EKS node group details"""
    name: str
    cluster_name: str
    node_role_arn: str
    status: str = ""
    instance_types: List[str] = field(default_factory=list)
    scaling_config: Dict[str, int] = field(default_factory=dict)
    ami_type: str = ""
    disk_size: int = 20
    remote_access: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def has_ssh_access(self) -> bool:
        return bool(self.remote_access.get('ec2SshKey'))


@dataclass
class EKSFinding:
    """Security finding for EKS"""
    finding_type: str
    severity: EKSRisk
    resource_id: str
    resource_type: str
    title: str
    description: str
    recommendation: str = ""
    mitre_techniques: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


MITRE_EKS_TECHNIQUES = {
    'container_administration': 'T1609',
    'container_api': 'T1610',
    'valid_accounts': 'T1078',
    'implant_container': 'T1525',
    'network_service_discovery': 'T1046',
}


class EKSEnumerator:
    """
    AWS EKS Enumerator
    
    Discovers EKS clusters, node groups, and analyzes security.
    """
    
    def __init__(self,
                 access_key: Optional[str] = None,
                 secret_key: Optional[str] = None,
                 session_token: Optional[str] = None,
                 profile: Optional[str] = None,
                 regions: Optional[List[str]] = None):
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token
        self.profile = profile
        self.regions = regions or ['us-east-1']
        self._session = None
        self._clients = {}
    
    def _get_boto3_session(self):
        """Create boto3 session"""
        try:
            import boto3
            
            if self.profile:
                return boto3.Session(profile_name=self.profile)
            elif self.access_key and self.secret_key:
                return boto3.Session(
                    aws_access_key_id=self.access_key,
                    aws_secret_access_key=self.secret_key,
                    aws_session_token=self.session_token
                )
            else:
                return boto3.Session()
        except ImportError:
            raise ImportError("boto3 required: pip install boto3")
    
    def _get_client(self, region: str):
        """Get EKS client for region"""
        if region not in self._clients:
            if not self._session:
                self._session = self._get_boto3_session()
            self._clients[region] = self._session.client('eks', region_name=region)
        return self._clients[region]
    
    def enumerate_clusters(self, region: str) -> List[EKSCluster]:
        """Enumerate EKS clusters in a region"""
        clusters = []
        
        try:
            client = self._get_client(region)
            cluster_names = client.list_clusters().get('clusters', [])
            
            for name in cluster_names:
                try:
                    response = client.describe_cluster(name=name)
                    cluster_data = response.get('cluster', {})
                    
                    # Get VPC config
                    vpc_config = cluster_data.get('resourcesVpcConfig', {})
                    
                    # Get logging
                    logging_enabled = {}
                    for log_type in ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler']:
                        enabled = False
                        for log_config in cluster_data.get('logging', {}).get('clusterLogging', []):
                            if log_type in log_config.get('types', []) and log_config.get('enabled'):
                                enabled = True
                        logging_enabled[log_type] = enabled
                    
                    cluster = EKSCluster(
                        name=name,
                        arn=cluster_data.get('arn', ''),
                        region=region,
                        version=cluster_data.get('version', ''),
                        status=cluster_data.get('status', ''),
                        endpoint=cluster_data.get('endpoint', ''),
                        role_arn=cluster_data.get('roleArn', ''),
                        vpc_id=vpc_config.get('vpcId', ''),
                        subnet_ids=vpc_config.get('subnetIds', []),
                        security_group_ids=vpc_config.get('securityGroupIds', []),
                        cluster_security_group_id=vpc_config.get('clusterSecurityGroupId', ''),
                        endpoint_public_access=vpc_config.get('endpointPublicAccess', True),
                        endpoint_private_access=vpc_config.get('endpointPrivateAccess', False),
                        public_access_cidrs=vpc_config.get('publicAccessCidrs', []),
                        encryption_config=cluster_data.get('encryptionConfig', []),
                        logging_enabled=logging_enabled,
                        tags=cluster_data.get('tags', {})
                    )
                    clusters.append(cluster)
                except Exception as e:
                    logger.debug(f"Error getting cluster {name}: {e}")
                    
        except Exception as e:
            logger.error(f"Error enumerating EKS in {region}: {e}")
        
        return clusters
    
    def enumerate_node_groups(self, 
                             cluster_name: str,
                             region: str) -> List[EKSNodeGroup]:
        """Enumerate node groups for a cluster"""
        node_groups = []
        
        try:
            client = self._get_client(region)
            ng_names = client.list_nodegroups(clusterName=cluster_name).get('nodegroups', [])
            
            for name in ng_names:
                try:
                    response = client.describe_nodegroup(
                        clusterName=cluster_name,
                        nodegroupName=name
                    )
                    ng_data = response.get('nodegroup', {})
                    
                    node_group = EKSNodeGroup(
                        name=name,
                        cluster_name=cluster_name,
                        node_role_arn=ng_data.get('nodeRole', ''),
                        status=ng_data.get('status', ''),
                        instance_types=ng_data.get('instanceTypes', []),
                        scaling_config=ng_data.get('scalingConfig', {}),
                        ami_type=ng_data.get('amiType', ''),
                        disk_size=ng_data.get('diskSize', 20),
                        remote_access=ng_data.get('remoteAccess', {})
                    )
                    node_groups.append(node_group)
                except Exception as e:
                    logger.debug(f"Error getting node group {name}: {e}")
                    
        except Exception as e:
            logger.error(f"Error enumerating node groups for {cluster_name}: {e}")
        
        return node_groups
    
    def analyze_security(self,
                        clusters: List[EKSCluster],
                        node_groups: List[EKSNodeGroup]) -> List[EKSFinding]:
        """Analyze EKS resources for security issues"""
        findings = []
        
        for cluster in clusters:
            # Public endpoint with 0.0.0.0/0
            if cluster.is_public and cluster.allows_all_ips:
                findings.append(EKSFinding(
                    finding_type='PUBLIC_ENDPOINT',
                    severity=EKSRisk.CRITICAL,
                    resource_id=cluster.name,
                    resource_type='EKSCluster',
                    title='EKS Endpoint Public to All IPs',
                    description=f"Cluster {cluster.name} API endpoint is accessible from any IP (0.0.0.0/0)",
                    recommendation='Restrict public access CIDRs or enable private endpoint only',
                    mitre_techniques=[
                        MITRE_EKS_TECHNIQUES['container_api'],
                        MITRE_EKS_TECHNIQUES['network_service_discovery']
                    ],
                    metadata={'endpoint': cluster.endpoint}
                ))
            elif cluster.is_public:
                findings.append(EKSFinding(
                    finding_type='PUBLIC_ENDPOINT',
                    severity=EKSRisk.MEDIUM,
                    resource_id=cluster.name,
                    resource_type='EKSCluster',
                    title='EKS Endpoint Publicly Accessible',
                    description=f"Cluster {cluster.name} API endpoint is publicly accessible",
                    recommendation='Consider enabling private endpoint only',
                    mitre_techniques=[MITRE_EKS_TECHNIQUES['container_api']]
                ))
            
            # No encryption
            if not cluster.encryption_config:
                findings.append(EKSFinding(
                    finding_type='NO_ENCRYPTION',
                    severity=EKSRisk.MEDIUM,
                    resource_id=cluster.name,
                    resource_type='EKSCluster',
                    title='EKS Secrets Not Encrypted',
                    description=f"Cluster {cluster.name} does not have secrets encryption enabled",
                    recommendation='Enable KMS encryption for Kubernetes secrets'
                ))
            
            # Insufficient logging
            disabled_logs = [k for k, v in cluster.logging_enabled.items() if not v]
            if disabled_logs:
                findings.append(EKSFinding(
                    finding_type='LOGGING_DISABLED',
                    severity=EKSRisk.LOW,
                    resource_id=cluster.name,
                    resource_type='EKSCluster',
                    title='EKS Logging Partially Disabled',
                    description=f"Cluster {cluster.name} has logging disabled for: {disabled_logs}",
                    recommendation='Enable all control plane logging types',
                    metadata={'disabled_logs': disabled_logs}
                ))
            
            # Outdated version
            try:
                version = float(cluster.version)
                if version < 1.27:
                    findings.append(EKSFinding(
                        finding_type='OUTDATED_VERSION',
                        severity=EKSRisk.MEDIUM,
                        resource_id=cluster.name,
                        resource_type='EKSCluster',
                        title='Outdated EKS Version',
                        description=f"Cluster {cluster.name} is running version {cluster.version}",
                        recommendation='Upgrade to a supported Kubernetes version'
                    ))
            except ValueError:
                pass
        
        for ng in node_groups:
            # SSH access enabled
            if ng.has_ssh_access:
                findings.append(EKSFinding(
                    finding_type='SSH_ACCESS',
                    severity=EKSRisk.LOW,
                    resource_id=ng.name,
                    resource_type='EKSNodeGroup',
                    title='Node Group Has SSH Access',
                    description=f"Node group {ng.name} has SSH key configured",
                    recommendation='Remove SSH access if not required',
                    mitre_techniques=[MITRE_EKS_TECHNIQUES['valid_accounts']]
                ))
        
        return findings
    
    def enumerate_all(self) -> Dict[str, Any]:
        """Enumerate all EKS resources"""
        results = {
            'regions': {},
            'clusters': [],
            'node_groups': [],
            'findings': [],
            'summary': {
                'total_clusters': 0,
                'public_clusters': 0,
                'unencrypted': 0,
                'total_node_groups': 0,
                'total_findings': 0
            }
        }
        
        all_clusters = []
        all_node_groups = []
        
        for region in self.regions:
            logger.info(f"Enumerating EKS in {region}")
            
            clusters = self.enumerate_clusters(region)
            
            region_node_groups = []
            for cluster in clusters:
                ngs = self.enumerate_node_groups(cluster.name, region)
                region_node_groups.extend(ngs)
            
            results['regions'][region] = {
                'clusters': clusters,
                'node_groups': region_node_groups
            }
            
            all_clusters.extend(clusters)
            all_node_groups.extend(region_node_groups)
        
        results['clusters'] = all_clusters
        results['node_groups'] = all_node_groups
        
        # Analyze security
        findings = self.analyze_security(all_clusters, all_node_groups)
        results['findings'] = findings
        
        # Update summary
        results['summary']['total_clusters'] = len(all_clusters)
        results['summary']['public_clusters'] = len([c for c in all_clusters if c.is_public])
        results['summary']['unencrypted'] = len([c for c in all_clusters if not c.encryption_config])
        results['summary']['total_node_groups'] = len(all_node_groups)
        results['summary']['total_findings'] = len(findings)
        
        return results


__all__ = ['EKSEnumerator', 'EKSCluster', 'EKSNodeGroup', 'EKSFinding']
