"""
AWS S3 Advanced Analyzer
Deep S3 bucket analysis with ACL, policy, and versioning checks
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class S3Risk(Enum):
    """S3 security risk levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class S3Bucket:
    """S3 bucket details"""
    name: str
    region: str
    creation_date: str = ""
    versioning_enabled: bool = False
    mfa_delete: bool = False
    encryption: str = ""
    public_access_block: Dict[str, bool] = field(default_factory=dict)
    acl_grants: List[Dict[str, str]] = field(default_factory=list)
    policy: Dict[str, Any] = field(default_factory=dict)
    logging_enabled: bool = False
    website_enabled: bool = False
    cors_enabled: bool = False
    lifecycle_rules: List[Dict] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)
    object_count: int = 0
    
    @property
    def is_public_acl(self) -> bool:
        """Check if bucket has public ACL"""
        public_uris = [
            'http://acs.amazonaws.com/groups/global/AllUsers',
            'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
        ]
        for grant in self.acl_grants:
            grantee = grant.get('Grantee', {})
            if grantee.get('URI') in public_uris:
                return True
        return False
    
    @property
    def is_public_policy(self) -> bool:
        """Check if bucket policy allows public access"""
        if not self.policy:
            return False
        
        for statement in self.policy.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                principal = statement.get('Principal', '')
                if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                    conditions = statement.get('Condition', {})
                    if not conditions:
                        return True
        return False
    
    @property
    def has_public_access_blocked(self) -> bool:
        """Check if all public access is blocked"""
        pab = self.public_access_block
        return (
            pab.get('BlockPublicAcls', False) and
            pab.get('IgnorePublicAcls', False) and
            pab.get('BlockPublicPolicy', False) and
            pab.get('RestrictPublicBuckets', False)
        )


@dataclass
class S3Object:
    """S3 object details"""
    key: str
    bucket: str
    size: int
    last_modified: str = ""
    storage_class: str = "STANDARD"
    is_public: bool = False
    content_type: str = ""
    version_id: str = ""
    is_deleted: bool = False


@dataclass
class S3Finding:
    """Security finding for S3"""
    finding_type: str
    severity: S3Risk
    resource_id: str
    resource_type: str
    title: str
    description: str
    recommendation: str = ""
    mitre_techniques: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


MITRE_S3_TECHNIQUES = {
    'data_from_cloud': 'T1530',
    'data_staged': 'T1074.002',
    'defacement': 'T1491',
    'transfer_cloud': 'T1537',
}

# Sensitive file patterns
SENSITIVE_PATTERNS = [
    '.env', '.pem', '.key', '.p12', '.pfx', '.cer',
    'credentials', 'secrets', 'password', 'config.json',
    'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
    '.git/', '.svn/', 'backup', 'dump', '.sql',
    'private', 'confidential', 'internal',
    '.aws', '.azure', '.gcp', 'terraform.tfstate'
]


class S3AdvancedAnalyzer:
    """
    AWS S3 Advanced Analyzer
    
    Performs deep analysis of S3 buckets including:
    - ACL and policy analysis
    - Versioning exploitation (recover deleted files)
    - Public file detection
    - Sensitive content scanning
    """
    
    def __init__(self,
                 access_key: Optional[str] = None,
                 secret_key: Optional[str] = None,
                 session_token: Optional[str] = None,
                 profile: Optional[str] = None):
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token
        self.profile = profile
        self._session = None
        self._s3_client = None
    
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
    
    def _get_s3_client(self):
        """Get S3 client"""
        if not self._s3_client:
            if not self._session:
                self._session = self._get_boto3_session()
            self._s3_client = self._session.client('s3')
        return self._s3_client
    
    def list_buckets(self) -> List[str]:
        """List all accessible buckets"""
        try:
            s3 = self._get_s3_client()
            response = s3.list_buckets()
            return [b['Name'] for b in response.get('Buckets', [])]
        except Exception as e:
            logger.error(f"Error listing buckets: {e}")
            return []
    
    def analyze_bucket(self, bucket_name: str) -> S3Bucket:
        """Perform deep analysis of a bucket"""
        s3 = self._get_s3_client()
        
        bucket = S3Bucket(name=bucket_name, region='unknown')
        
        # Get region
        try:
            location = s3.get_bucket_location(Bucket=bucket_name)
            bucket.region = location.get('LocationConstraint') or 'us-east-1'
        except Exception:
            pass
        
        # Get versioning
        try:
            versioning = s3.get_bucket_versioning(Bucket=bucket_name)
            bucket.versioning_enabled = versioning.get('Status') == 'Enabled'
            bucket.mfa_delete = versioning.get('MFADelete') == 'Enabled'
        except Exception:
            pass
        
        # Get encryption
        try:
            encryption = s3.get_bucket_encryption(Bucket=bucket_name)
            rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
            if rules:
                bucket.encryption = rules[0].get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm', '')
        except Exception:
            pass
        
        # Get public access block
        try:
            pab = s3.get_public_access_block(Bucket=bucket_name)
            bucket.public_access_block = pab.get('PublicAccessBlockConfiguration', {})
        except Exception:
            # No public access block configured
            pass
        
        # Get ACL
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            bucket.acl_grants = acl.get('Grants', [])
        except Exception:
            pass
        
        # Get policy
        try:
            import json
            policy = s3.get_bucket_policy(Bucket=bucket_name)
            bucket.policy = json.loads(policy.get('Policy', '{}'))
        except Exception:
            pass
        
        # Get logging
        try:
            logging_config = s3.get_bucket_logging(Bucket=bucket_name)
            bucket.logging_enabled = 'LoggingEnabled' in logging_config
        except Exception:
            pass
        
        # Get website config
        try:
            s3.get_bucket_website(Bucket=bucket_name)
            bucket.website_enabled = True
        except Exception:
            pass
        
        # Get tags
        try:
            tags = s3.get_bucket_tagging(Bucket=bucket_name)
            bucket.tags = {t['Key']: t['Value'] for t in tags.get('TagSet', [])}
        except Exception:
            pass
        
        return bucket
    
    def list_objects(self, 
                    bucket_name: str,
                    max_keys: int = 1000,
                    include_versions: bool = False) -> List[S3Object]:
        """List objects in bucket"""
        objects = []
        s3 = self._get_s3_client()
        
        try:
            if include_versions:
                # List all versions including deleted
                paginator = s3.get_paginator('list_object_versions')
                for page in paginator.paginate(Bucket=bucket_name, MaxKeys=max_keys):
                    # Current versions
                    for obj in page.get('Versions', []):
                        objects.append(S3Object(
                            key=obj['Key'],
                            bucket=bucket_name,
                            size=obj.get('Size', 0),
                            last_modified=str(obj.get('LastModified', '')),
                            storage_class=obj.get('StorageClass', 'STANDARD'),
                            version_id=obj.get('VersionId', ''),
                            is_deleted=False
                        ))
                    
                    # Delete markers (deleted files)
                    for marker in page.get('DeleteMarkers', []):
                        objects.append(S3Object(
                            key=marker['Key'],
                            bucket=bucket_name,
                            size=0,
                            last_modified=str(marker.get('LastModified', '')),
                            version_id=marker.get('VersionId', ''),
                            is_deleted=True
                        ))
                    
                    if len(objects) >= max_keys:
                        break
            else:
                # Just current objects
                paginator = s3.get_paginator('list_objects_v2')
                for page in paginator.paginate(Bucket=bucket_name, MaxKeys=min(max_keys, 1000)):
                    for obj in page.get('Contents', []):
                        objects.append(S3Object(
                            key=obj['Key'],
                            bucket=bucket_name,
                            size=obj.get('Size', 0),
                            last_modified=str(obj.get('LastModified', '')),
                            storage_class=obj.get('StorageClass', 'STANDARD')
                        ))
                    
                    if len(objects) >= max_keys:
                        break
                        
        except Exception as e:
            logger.error(f"Error listing objects in {bucket_name}: {e}")
        
        return objects
    
    def find_sensitive_files(self, 
                            bucket_name: str,
                            max_keys: int = 1000) -> List[S3Object]:
        """Find potentially sensitive files"""
        all_objects = self.list_objects(bucket_name, max_keys)
        sensitive = []
        
        for obj in all_objects:
            key_lower = obj.key.lower()
            for pattern in SENSITIVE_PATTERNS:
                if pattern in key_lower:
                    sensitive.append(obj)
                    break
        
        return sensitive
    
    def find_deleted_files(self, bucket_name: str) -> List[S3Object]:
        """Find deleted files that can be recovered (versioning exploitation)"""
        objects = self.list_objects(bucket_name, include_versions=True)
        return [obj for obj in objects if obj.is_deleted]
    
    def analyze_security(self, buckets: List[S3Bucket]) -> List[S3Finding]:
        """Analyze buckets for security issues"""
        findings = []
        
        for bucket in buckets:
            # Public ACL
            if bucket.is_public_acl and not bucket.has_public_access_blocked:
                findings.append(S3Finding(
                    finding_type='PUBLIC_ACL',
                    severity=S3Risk.CRITICAL,
                    resource_id=bucket.name,
                    resource_type='S3Bucket',
                    title='Bucket Has Public ACL',
                    description=f"Bucket {bucket.name} has public ACL grants",
                    recommendation='Remove public ACL grants or enable public access block',
                    mitre_techniques=[MITRE_S3_TECHNIQUES['data_from_cloud']]
                ))
            
            # Public policy
            if bucket.is_public_policy and not bucket.has_public_access_blocked:
                findings.append(S3Finding(
                    finding_type='PUBLIC_POLICY',
                    severity=S3Risk.CRITICAL,
                    resource_id=bucket.name,
                    resource_type='S3Bucket',
                    title='Bucket Has Public Policy',
                    description=f"Bucket {bucket.name} has bucket policy allowing public access",
                    recommendation='Review and restrict bucket policy or enable public access block',
                    mitre_techniques=[MITRE_S3_TECHNIQUES['data_from_cloud']]
                ))
            
            # No encryption
            if not bucket.encryption:
                findings.append(S3Finding(
                    finding_type='NO_ENCRYPTION',
                    severity=S3Risk.MEDIUM,
                    resource_id=bucket.name,
                    resource_type='S3Bucket',
                    title='Bucket Not Encrypted',
                    description=f"Bucket {bucket.name} does not have default encryption",
                    recommendation='Enable AES-256 or KMS encryption'
                ))
            
            # No logging
            if not bucket.logging_enabled:
                findings.append(S3Finding(
                    finding_type='NO_LOGGING',
                    severity=S3Risk.LOW,
                    resource_id=bucket.name,
                    resource_type='S3Bucket',
                    title='Bucket Access Logging Disabled',
                    description=f"Bucket {bucket.name} does not have access logging enabled",
                    recommendation='Enable server access logging for audit trail'
                ))
            
            # Versioning disabled (can't recover from ransomware)
            if not bucket.versioning_enabled:
                findings.append(S3Finding(
                    finding_type='NO_VERSIONING',
                    severity=S3Risk.LOW,
                    resource_id=bucket.name,
                    resource_type='S3Bucket',
                    title='Bucket Versioning Disabled',
                    description=f"Bucket {bucket.name} does not have versioning enabled",
                    recommendation='Enable versioning for data recovery capability'
                ))
            
            # Website hosting (potential defacement risk)
            if bucket.website_enabled:
                findings.append(S3Finding(
                    finding_type='WEBSITE_HOSTING',
                    severity=S3Risk.MEDIUM if not bucket.is_public_acl else S3Risk.HIGH,
                    resource_id=bucket.name,
                    resource_type='S3Bucket',
                    title='Static Website Hosting Enabled',
                    description=f"Bucket {bucket.name} has static website hosting enabled",
                    recommendation='Ensure proper access controls if intentional',
                    mitre_techniques=[MITRE_S3_TECHNIQUES['defacement']]
                ))
        
        return findings
    
    def enumerate_all(self, 
                     max_objects_per_bucket: int = 100,
                     scan_sensitive: bool = True) -> Dict[str, Any]:
        """Enumerate all S3 resources"""
        results = {
            'buckets': [],
            'sensitive_files': [],
            'deleted_files': [],
            'findings': [],
            'summary': {
                'total_buckets': 0,
                'public_buckets': 0,
                'unencrypted': 0,
                'sensitive_file_count': 0,
                'recoverable_deleted': 0,
                'total_findings': 0
            }
        }
        
        bucket_names = self.list_buckets()
        
        for name in bucket_names:
            logger.info(f"Analyzing bucket: {name}")
            bucket = self.analyze_bucket(name)
            results['buckets'].append(bucket)
            
            if scan_sensitive:
                sensitive = self.find_sensitive_files(name, max_objects_per_bucket)
                results['sensitive_files'].extend(sensitive)
            
            if bucket.versioning_enabled:
                deleted = self.find_deleted_files(name)
                results['deleted_files'].extend(deleted)
        
        # Analyze security
        findings = self.analyze_security(results['buckets'])
        results['findings'] = findings
        
        # Update summary
        results['summary']['total_buckets'] = len(results['buckets'])
        results['summary']['public_buckets'] = len([b for b in results['buckets'] if b.is_public_acl or b.is_public_policy])
        results['summary']['unencrypted'] = len([b for b in results['buckets'] if not b.encryption])
        results['summary']['sensitive_file_count'] = len(results['sensitive_files'])
        results['summary']['recoverable_deleted'] = len(results['deleted_files'])
        results['summary']['total_findings'] = len(findings)
        
        return results


__all__ = [
    'S3AdvancedAnalyzer',
    'S3Bucket',
    'S3Object',
    'S3Finding'
]
