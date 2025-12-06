"""
AWS RDS Enumerator
Database instance discovery and security analysis
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class RDSRisk(Enum):
    """RDS security risk levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class RDSInstance:
    """RDS database instance details"""
    db_instance_id: str
    db_instance_arn: str
    engine: str
    engine_version: str
    db_instance_class: str
    region: str
    availability_zone: str = ""
    db_name: str = ""
    master_username: str = ""
    endpoint_address: str = ""
    endpoint_port: int = 0
    publicly_accessible: bool = False
    storage_encrypted: bool = False
    storage_type: str = ""
    allocated_storage: int = 0
    vpc_id: str = ""
    vpc_security_groups: List[str] = field(default_factory=list)
    db_subnet_group: str = ""
    multi_az: bool = False
    auto_minor_version_upgrade: bool = True
    backup_retention_period: int = 0
    deletion_protection: bool = False
    iam_auth_enabled: bool = False
    performance_insights_enabled: bool = False
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class RDSSnapshot:
    """RDS snapshot details"""
    snapshot_id: str
    snapshot_arn: str
    db_instance_id: str
    engine: str
    region: str
    snapshot_type: str = "manual"
    status: str = ""
    allocated_storage: int = 0
    encrypted: bool = False
    is_public: bool = False
    create_time: str = ""


@dataclass
class RDSFinding:
    """Security finding for RDS"""
    finding_type: str
    severity: RDSRisk
    resource_id: str
    resource_type: str
    title: str
    description: str
    recommendation: str = ""
    mitre_techniques: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


MITRE_RDS_TECHNIQUES = {
    'data_from_cloud': 'T1530',
    'sql_stored_procedures': 'T1505.001',
    'valid_accounts': 'T1078',
    'brute_force': 'T1110',
    'network_service_discovery': 'T1046',
}

# Default ports for database engines
DEFAULT_DB_PORTS = {
    'mysql': 3306,
    'mariadb': 3306,
    'postgres': 5432,
    'oracle-ee': 1521,
    'oracle-se': 1521,
    'oracle-se1': 1521,
    'oracle-se2': 1521,
    'sqlserver-ee': 1433,
    'sqlserver-se': 1433,
    'sqlserver-ex': 1433,
    'sqlserver-web': 1433,
    'aurora': 3306,
    'aurora-mysql': 3306,
    'aurora-postgresql': 5432,
}


class RDSEnumerator:
    """
    AWS RDS Enumerator
    
    Discovers RDS instances and snapshots,
    analyzes for security issues.
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
        """Get RDS client for region"""
        if region not in self._clients:
            if not self._session:
                self._session = self._get_boto3_session()
            self._clients[region] = self._session.client('rds', region_name=region)
        return self._clients[region]
    
    def enumerate_instances(self, region: str) -> List[RDSInstance]:
        """Enumerate RDS instances in a region"""
        instances = []
        
        try:
            client = self._get_client(region)
            paginator = client.get_paginator('describe_db_instances')
            
            for page in paginator.paginate():
                for db in page.get('DBInstances', []):
                    endpoint = db.get('Endpoint', {})
                    
                    # Get security group IDs
                    sg_ids = [
                        sg['VpcSecurityGroupId'] 
                        for sg in db.get('VpcSecurityGroups', [])
                        if sg.get('Status') == 'active'
                    ]
                    
                    # Get tags
                    tags = {}
                    try:
                        tags_response = client.list_tags_for_resource(
                            ResourceName=db['DBInstanceArn']
                        )
                        tags = {t['Key']: t['Value'] for t in tags_response.get('TagList', [])}
                    except Exception:
                        pass
                    
                    instance = RDSInstance(
                        db_instance_id=db['DBInstanceIdentifier'],
                        db_instance_arn=db['DBInstanceArn'],
                        engine=db.get('Engine', ''),
                        engine_version=db.get('EngineVersion', ''),
                        db_instance_class=db.get('DBInstanceClass', ''),
                        region=region,
                        availability_zone=db.get('AvailabilityZone', ''),
                        db_name=db.get('DBName', ''),
                        master_username=db.get('MasterUsername', ''),
                        endpoint_address=endpoint.get('Address', ''),
                        endpoint_port=endpoint.get('Port', 0),
                        publicly_accessible=db.get('PubliclyAccessible', False),
                        storage_encrypted=db.get('StorageEncrypted', False),
                        storage_type=db.get('StorageType', ''),
                        allocated_storage=db.get('AllocatedStorage', 0),
                        vpc_id=db.get('DBSubnetGroup', {}).get('VpcId', ''),
                        vpc_security_groups=sg_ids,
                        db_subnet_group=db.get('DBSubnetGroup', {}).get('DBSubnetGroupName', ''),
                        multi_az=db.get('MultiAZ', False),
                        auto_minor_version_upgrade=db.get('AutoMinorVersionUpgrade', True),
                        backup_retention_period=db.get('BackupRetentionPeriod', 0),
                        deletion_protection=db.get('DeletionProtection', False),
                        iam_auth_enabled=db.get('IAMDatabaseAuthenticationEnabled', False),
                        performance_insights_enabled=db.get('PerformanceInsightsEnabled', False),
                        tags=tags
                    )
                    instances.append(instance)
                    
        except Exception as e:
            logger.error(f"Error enumerating RDS in {region}: {e}")
        
        return instances
    
    def enumerate_snapshots(self, 
                           region: str,
                           include_public: bool = True) -> List[RDSSnapshot]:
        """Enumerate RDS snapshots"""
        snapshots = []
        
        try:
            client = self._get_client(region)
            
            # Get owned snapshots
            paginator = client.get_paginator('describe_db_snapshots')
            for page in paginator.paginate(SnapshotType='manual'):
                for snap in page.get('DBSnapshots', []):
                    # Check if public
                    is_public = False
                    try:
                        attr_response = client.describe_db_snapshot_attributes(
                            DBSnapshotIdentifier=snap['DBSnapshotIdentifier']
                        )
                        for attr in attr_response.get('DBSnapshotAttributesResult', {}).get('DBSnapshotAttributes', []):
                            if attr.get('AttributeName') == 'restore' and 'all' in attr.get('AttributeValues', []):
                                is_public = True
                                break
                    except Exception:
                        pass
                    
                    snapshot = RDSSnapshot(
                        snapshot_id=snap['DBSnapshotIdentifier'],
                        snapshot_arn=snap['DBSnapshotArn'],
                        db_instance_id=snap.get('DBInstanceIdentifier', ''),
                        engine=snap.get('Engine', ''),
                        region=region,
                        snapshot_type=snap.get('SnapshotType', 'manual'),
                        status=snap.get('Status', ''),
                        allocated_storage=snap.get('AllocatedStorage', 0),
                        encrypted=snap.get('Encrypted', False),
                        is_public=is_public,
                        create_time=str(snap.get('SnapshotCreateTime', ''))
                    )
                    snapshots.append(snapshot)
                    
        except Exception as e:
            logger.error(f"Error enumerating RDS snapshots in {region}: {e}")
        
        return snapshots
    
    def analyze_security(self,
                        instances: List[RDSInstance],
                        snapshots: List[RDSSnapshot]) -> List[RDSFinding]:
        """Analyze RDS resources for security issues"""
        findings = []
        
        for instance in instances:
            # Public database
            if instance.publicly_accessible:
                findings.append(RDSFinding(
                    finding_type='PUBLIC_RDS',
                    severity=RDSRisk.CRITICAL,
                    resource_id=instance.db_instance_id,
                    resource_type='RDSInstance',
                    title='Publicly Accessible RDS Instance',
                    description=f"RDS instance {instance.db_instance_id} ({instance.engine}) is publicly accessible "
                               f"at {instance.endpoint_address}:{instance.endpoint_port}",
                    recommendation='Disable public accessibility and use VPC security groups',
                    mitre_techniques=[
                        MITRE_RDS_TECHNIQUES['network_service_discovery'],
                        MITRE_RDS_TECHNIQUES['brute_force']
                    ],
                    metadata={
                        'endpoint': f"{instance.endpoint_address}:{instance.endpoint_port}",
                        'engine': instance.engine
                    }
                ))
            
            # Unencrypted storage
            if not instance.storage_encrypted:
                findings.append(RDSFinding(
                    finding_type='UNENCRYPTED_RDS',
                    severity=RDSRisk.HIGH,
                    resource_id=instance.db_instance_id,
                    resource_type='RDSInstance',
                    title='Unencrypted RDS Storage',
                    description=f"RDS instance {instance.db_instance_id} does not have storage encryption enabled",
                    recommendation='Enable storage encryption (requires snapshot restore)',
                    mitre_techniques=[MITRE_RDS_TECHNIQUES['data_from_cloud']]
                ))
            
            # No deletion protection
            if not instance.deletion_protection:
                findings.append(RDSFinding(
                    finding_type='NO_DELETION_PROTECTION',
                    severity=RDSRisk.MEDIUM,
                    resource_id=instance.db_instance_id,
                    resource_type='RDSInstance',
                    title='RDS Deletion Protection Disabled',
                    description=f"RDS instance {instance.db_instance_id} can be deleted without protection",
                    recommendation='Enable deletion protection for production databases'
                ))
            
            # No backups
            if instance.backup_retention_period == 0:
                findings.append(RDSFinding(
                    finding_type='NO_BACKUPS',
                    severity=RDSRisk.HIGH,
                    resource_id=instance.db_instance_id,
                    resource_type='RDSInstance',
                    title='RDS Automated Backups Disabled',
                    description=f"RDS instance {instance.db_instance_id} has no automated backups",
                    recommendation='Enable automated backups with appropriate retention period'
                ))
            
            # No IAM authentication
            if not instance.iam_auth_enabled:
                findings.append(RDSFinding(
                    finding_type='NO_IAM_AUTH',
                    severity=RDSRisk.LOW,
                    resource_id=instance.db_instance_id,
                    resource_type='RDSInstance',
                    title='IAM Database Authentication Disabled',
                    description=f"RDS instance {instance.db_instance_id} uses password-only authentication",
                    recommendation='Enable IAM database authentication for enhanced security',
                    mitre_techniques=[MITRE_RDS_TECHNIQUES['valid_accounts']]
                ))
        
        for snapshot in snapshots:
            # Public snapshot
            if snapshot.is_public:
                findings.append(RDSFinding(
                    finding_type='PUBLIC_SNAPSHOT',
                    severity=RDSRisk.CRITICAL,
                    resource_id=snapshot.snapshot_id,
                    resource_type='RDSSnapshot',
                    title='Public RDS Snapshot',
                    description=f"RDS snapshot {snapshot.snapshot_id} is publicly accessible. "
                               "Anyone can restore and access the data",
                    recommendation='Remove public access from the snapshot immediately',
                    mitre_techniques=[MITRE_RDS_TECHNIQUES['data_from_cloud']],
                    metadata={
                        'db_instance': snapshot.db_instance_id,
                        'engine': snapshot.engine,
                        'size_gb': snapshot.allocated_storage
                    }
                ))
            
            # Unencrypted snapshot
            if not snapshot.encrypted:
                findings.append(RDSFinding(
                    finding_type='UNENCRYPTED_SNAPSHOT',
                    severity=RDSRisk.MEDIUM,
                    resource_id=snapshot.snapshot_id,
                    resource_type='RDSSnapshot',
                    title='Unencrypted RDS Snapshot',
                    description=f"RDS snapshot {snapshot.snapshot_id} is not encrypted",
                    recommendation='Create encrypted copy and delete unencrypted snapshot'
                ))
        
        return findings
    
    def enumerate_all(self) -> Dict[str, Any]:
        """Enumerate all RDS resources"""
        results = {
            'regions': {},
            'instances': [],
            'snapshots': [],
            'findings': [],
            'summary': {
                'total_instances': 0,
                'total_snapshots': 0,
                'public_instances': 0,
                'public_snapshots': 0,
                'unencrypted': 0,
                'total_findings': 0
            }
        }
        
        all_instances = []
        all_snapshots = []
        
        for region in self.regions:
            logger.info(f"Enumerating RDS in {region}")
            
            instances = self.enumerate_instances(region)
            snapshots = self.enumerate_snapshots(region)
            
            results['regions'][region] = {
                'instances': instances,
                'snapshots': snapshots
            }
            
            all_instances.extend(instances)
            all_snapshots.extend(snapshots)
        
        results['instances'] = all_instances
        results['snapshots'] = all_snapshots
        
        # Analyze security
        findings = self.analyze_security(all_instances, all_snapshots)
        results['findings'] = findings
        
        # Update summary
        results['summary']['total_instances'] = len(all_instances)
        results['summary']['total_snapshots'] = len(all_snapshots)
        results['summary']['public_instances'] = len([i for i in all_instances if i.publicly_accessible])
        results['summary']['public_snapshots'] = len([s for s in all_snapshots if s.is_public])
        results['summary']['unencrypted'] = len([i for i in all_instances if not i.storage_encrypted])
        results['summary']['total_findings'] = len(findings)
        
        return results


__all__ = [
    'RDSEnumerator',
    'RDSInstance',
    'RDSSnapshot',
    'RDSFinding'
]
