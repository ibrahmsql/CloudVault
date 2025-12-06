"""
EC2 Enumerator Core
Main enumeration logic for EC2 instances, security groups, and snapshots
"""

import logging
from typing import List, Dict, Any, Optional

from .models import (
    EC2Instance, SecurityGroup, SecurityGroupRule,
    EBSSnapshot
)
from .security import analyze_instance_security, analyze_snapshot_security
from .metadata import get_ssrf_patterns
from .formatter import format_tree

logger = logging.getLogger(__name__)


# AWS regions for enumeration
AWS_REGIONS = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1',
    'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
    'ap-southeast-1', 'ap-southeast-2',
    'ap-south-1', 'sa-east-1', 'ca-central-1',
    'me-south-1', 'af-south-1'
]


class EC2Enumerator:
    """
    AWS EC2 Instance Enumerator
    
    Provides comprehensive EC2 enumeration including:
    - Instance discovery across regions
    - Security group analysis
    - EBS volume/snapshot discovery
    - Security finding generation
    """
    
    def __init__(self, 
                 access_key: Optional[str] = None,
                 secret_key: Optional[str] = None,
                 session_token: Optional[str] = None,
                 profile: Optional[str] = None,
                 regions: Optional[List[str]] = None,
                 timeout: int = 30):
        """
        Initialize EC2 Enumerator.
        
        Args:
            access_key: AWS Access Key ID
            secret_key: AWS Secret Access Key
            session_token: AWS Session Token (optional)
            profile: AWS CLI profile name
            regions: List of regions to enumerate (None = all)
            timeout: Request timeout in seconds
        """
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token
        self.profile = profile
        self.regions = regions or AWS_REGIONS
        self.timeout = timeout
        self._ec2_clients = {}
        self._session = None
    
    def _get_boto3_session(self):
        """Create boto3 session with credentials"""
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
            logger.error("boto3 not installed. Run: pip install boto3")
            raise
    
    def _get_ec2_client(self, region: str):
        """Get EC2 client for region"""
        if region not in self._ec2_clients:
            if not self._session:
                self._session = self._get_boto3_session()
            self._ec2_clients[region] = self._session.client('ec2', region_name=region)
        return self._ec2_clients[region]
    
    def _get_ec2_resource(self, region: str):
        """Get EC2 resource for region"""
        if not self._session:
            self._session = self._get_boto3_session()
        return self._session.resource('ec2', region_name=region)
    
    def enumerate_regions(self) -> List[str]:
        """Get all available AWS regions"""
        try:
            ec2 = self._get_ec2_client('us-east-1')
            response = ec2.describe_regions()
            return [r['RegionName'] for r in response.get('Regions', [])]
        except Exception as e:
            logger.warning(f"Failed to enumerate regions: {e}")
            return AWS_REGIONS
    
    def enumerate_instances(self, 
                           region: str, 
                           limit: Optional[int] = None) -> List[EC2Instance]:
        """
        Enumerate EC2 instances in a region.
        
        Args:
            region: AWS region
            limit: Maximum number of instances to return
            
        Returns:
            List of EC2Instance objects
        """
        instances = []
        
        try:
            ec2 = self._get_ec2_resource(region)
            
            if limit:
                ec2_instances = list(ec2.instances.limit(limit))
            else:
                ec2_instances = list(ec2.instances.all())
            
            for inst in ec2_instances:
                # Extract tags
                tags = {}
                if inst.tags:
                    tags = {t['Key']: t['Value'] for t in inst.tags}
                
                # Get security groups
                security_groups = []
                for sg_info in (inst.security_groups or []):
                    sg = self._get_security_group(region, sg_info['GroupId'])
                    if sg:
                        security_groups.append(sg)
                
                # Get IAM profile
                iam_role = ""
                if inst.iam_instance_profile:
                    iam_role = inst.iam_instance_profile.get('Arn', '')
                
                instance = EC2Instance(
                    instance_id=inst.id,
                    instance_type=inst.instance_type or 'unknown',
                    state=inst.state['Name'] if inst.state else 'unknown',
                    region=region,
                    availability_zone=inst.placement.get('AvailabilityZone', '') if inst.placement else '',
                    public_ip=inst.public_ip_address or '',
                    private_ip=inst.private_ip_address or '',
                    public_dns=inst.public_dns_name or '',
                    private_dns=inst.private_dns_name or '',
                    launch_time=str(inst.launch_time) if inst.launch_time else '',
                    key_name=inst.key_name or '',
                    platform=inst.platform_details or 'linux',
                    architecture=inst.architecture or 'x86_64',
                    vpc_id=inst.vpc_id or '',
                    subnet_id=inst.subnet_id or '',
                    ami_id=inst.image_id or '',
                    iam_role=iam_role,
                    security_groups=security_groups,
                    tags=tags,
                    hypervisor=inst.hypervisor or ''
                )
                
                instances.append(instance)
                
        except Exception as e:
            logger.error(f"Error enumerating instances in {region}: {e}")
        
        return instances
    
    def _get_security_group(self, region: str, group_id: str) -> Optional[SecurityGroup]:
        """Get security group details"""
        try:
            ec2 = self._get_ec2_client(region)
            response = ec2.describe_security_groups(GroupIds=[group_id])
            
            if not response.get('SecurityGroups'):
                return None
            
            sg_data = response['SecurityGroups'][0]
            
            # Parse inbound rules
            inbound_rules = []
            for perm in sg_data.get('IpPermissions', []):
                rule = SecurityGroupRule(
                    protocol=perm.get('IpProtocol', '-1'),
                    from_port=perm.get('FromPort', 0),
                    to_port=perm.get('ToPort', 65535),
                    cidr_blocks=[r['CidrIp'] for r in perm.get('IpRanges', [])],
                    ipv6_cidr_blocks=[r['CidrIpv6'] for r in perm.get('Ipv6Ranges', [])],
                    prefix_list_ids=[p['PrefixListId'] for p in perm.get('PrefixListIds', [])],
                    security_groups=[g['GroupId'] for g in perm.get('UserIdGroupPairs', [])],
                    description=perm.get('IpRanges', [{}])[0].get('Description', '') if perm.get('IpRanges') else ''
                )
                inbound_rules.append(rule)
            
            # Parse outbound rules
            outbound_rules = []
            for perm in sg_data.get('IpPermissionsEgress', []):
                rule = SecurityGroupRule(
                    protocol=perm.get('IpProtocol', '-1'),
                    from_port=perm.get('FromPort', 0),
                    to_port=perm.get('ToPort', 65535),
                    cidr_blocks=[r['CidrIp'] for r in perm.get('IpRanges', [])],
                    ipv6_cidr_blocks=[r['CidrIpv6'] for r in perm.get('Ipv6Ranges', [])],
                )
                outbound_rules.append(rule)
            
            # Extract tags
            tags = {}
            if sg_data.get('Tags'):
                tags = {t['Key']: t['Value'] for t in sg_data['Tags']}
            
            return SecurityGroup(
                group_id=sg_data['GroupId'],
                group_name=sg_data.get('GroupName', ''),
                description=sg_data.get('Description', ''),
                vpc_id=sg_data.get('VpcId', ''),
                owner_id=sg_data.get('OwnerId', ''),
                inbound_rules=inbound_rules,
                outbound_rules=outbound_rules,
                tags=tags
            )
            
        except Exception as e:
            logger.debug(f"Error getting security group {group_id}: {e}")
            return None
    
    def enumerate_security_groups(self, region: str) -> List[SecurityGroup]:
        """Enumerate all security groups in a region"""
        security_groups = []
        
        try:
            ec2 = self._get_ec2_client(region)
            paginator = ec2.get_paginator('describe_security_groups')
            
            for page in paginator.paginate():
                for sg_data in page.get('SecurityGroups', []):
                    sg = self._get_security_group(region, sg_data['GroupId'])
                    if sg:
                        security_groups.append(sg)
                        
        except Exception as e:
            logger.error(f"Error enumerating security groups in {region}: {e}")
        
        return security_groups
    
    def enumerate_snapshots(self, 
                           region: str, 
                           owner_id: Optional[str] = None,
                           check_public: bool = True) -> List[EBSSnapshot]:
        """
        Enumerate EBS snapshots.
        
        Args:
            region: AWS region
            owner_id: Filter by owner ID (None = self)
            check_public: Include public snapshot check
            
        Returns:
            List of EBSSnapshot objects
        """
        snapshots = []
        
        try:
            ec2 = self._get_ec2_client(region)
            
            filters = []
            if owner_id:
                filters.append({'Name': 'owner-id', 'Values': [owner_id]})
            
            paginator = ec2.get_paginator('describe_snapshots')
            owner_ids = [owner_id] if owner_id else ['self']
            
            for page in paginator.paginate(OwnerIds=owner_ids, Filters=filters if filters else []):
                for snap in page.get('Snapshots', []):
                    # Check if public
                    is_public = False
                    if check_public:
                        try:
                            attr_response = ec2.describe_snapshot_attribute(
                                SnapshotId=snap['SnapshotId'],
                                Attribute='createVolumePermission'
                            )
                            for perm in attr_response.get('CreateVolumePermissions', []):
                                if perm.get('Group') == 'all':
                                    is_public = True
                                    break
                        except Exception:
                            pass
                    
                    # Extract tags
                    tags = {}
                    if snap.get('Tags'):
                        tags = {t['Key']: t['Value'] for t in snap['Tags']}
                    
                    snapshot = EBSSnapshot(
                        snapshot_id=snap['SnapshotId'],
                        volume_id=snap.get('VolumeId', ''),
                        volume_size=snap.get('VolumeSize', 0),
                        state=snap.get('State', 'unknown'),
                        owner_id=snap.get('OwnerId', ''),
                        encrypted=snap.get('Encrypted', False),
                        description=snap.get('Description', ''),
                        start_time=str(snap.get('StartTime', '')),
                        progress=snap.get('Progress', ''),
                        is_public=is_public,
                        tags=tags
                    )
                    snapshots.append(snapshot)
                    
        except Exception as e:
            logger.error(f"Error enumerating snapshots in {region}: {e}")
        
        return snapshots
    
    def enumerate_all(self, 
                     limit: Optional[int] = None,
                     include_snapshots: bool = True) -> Dict[str, Any]:
        """
        Enumerate EC2 resources across all configured regions.
        
        Args:
            limit: Maximum instances per region
            include_snapshots: Include snapshot enumeration
            
        Returns:
            Dictionary with all enumeration results
        """
        results = {
            'regions': {},
            'summary': {
                'total_instances': 0,
                'total_running': 0,
                'total_public': 0,
                'total_security_groups': 0,
                'total_snapshots': 0,
                'total_findings': 0
            },
            'findings': []
        }
        
        all_instances = []
        all_snapshots = []
        
        for region in self.regions:
            logger.info(f"Enumerating region: {region}")
            
            region_data = {
                'instances': [],
                'security_groups': [],
                'snapshots': []
            }
            
            # Enumerate instances
            instances = self.enumerate_instances(region, limit)
            region_data['instances'] = instances
            all_instances.extend(instances)
            
            # Enumerate snapshots if requested
            if include_snapshots:
                snapshots = self.enumerate_snapshots(region)
                region_data['snapshots'] = snapshots
                all_snapshots.extend(snapshots)
            
            # Update summary
            results['summary']['total_instances'] += len(instances)
            results['summary']['total_running'] += len([i for i in instances if i.state == 'running'])
            results['summary']['total_public'] += len([i for i in instances if i.is_public])
            results['summary']['total_snapshots'] += len(region_data['snapshots'])
            
            results['regions'][region] = region_data
        
        # Analyze security
        instance_findings = analyze_instance_security(all_instances)
        snapshot_findings = analyze_snapshot_security(all_snapshots)
        
        results['findings'] = instance_findings + snapshot_findings
        results['summary']['total_findings'] = len(results['findings'])
        
        return results
    
    def get_metadata_ssrf_patterns(self) -> Dict[str, Any]:
        """Get metadata service SSRF patterns for testing"""
        return get_ssrf_patterns()
    
    def format_tree(self, results: Dict[str, Any]) -> str:
        """Format enumeration results as tree"""
        return format_tree(results)


__all__ = ['EC2Enumerator', 'AWS_REGIONS']
