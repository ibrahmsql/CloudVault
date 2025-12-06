"""
AWS Secrets Manager and SSM Parameter Store Scanner
Secret enumeration and security analysis
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


class SecretRisk(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class SecretInfo:
    """Secrets Manager secret details"""
    name: str
    arn: str
    description: str = ""
    kms_key_id: str = ""
    rotation_enabled: bool = False
    rotation_lambda: str = ""
    rotation_days: int = 0
    last_rotated: str = ""
    last_accessed: str = ""
    created_date: str = ""
    tags: Dict[str, str] = field(default_factory=dict)
    version_ids: List[str] = field(default_factory=list)
    
    @property
    def needs_rotation(self) -> bool:
        if not self.rotation_enabled:
            return True
        if self.last_rotated:
            try:
                last = datetime.fromisoformat(self.last_rotated.replace('Z', '+00:00').split('+')[0])
                days_since = (datetime.now() - last).days
                return days_since > (self.rotation_days or 90)
            except Exception:
                pass
        return False


@dataclass
class SSMParameter:
    """SSM Parameter Store parameter details"""
    name: str
    type: str
    description: str = ""
    value: str = ""
    version: int = 1
    tier: str = "Standard"
    key_id: str = ""
    last_modified: str = ""
    
    @property
    def is_secure(self) -> bool:
        return self.type == 'SecureString'
    
    @property
    def is_encrypted(self) -> bool:
        return bool(self.key_id) or self.type == 'SecureString'


@dataclass
class SecretFinding:
    """Security finding for secrets"""
    finding_type: str
    severity: SecretRisk
    resource_id: str
    resource_type: str
    title: str
    description: str
    recommendation: str = ""
    mitre_technique: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


class SecretsManagerScanner:
    """
    AWS Secrets Manager and SSM Parameter Store Scanner
    
    Enumerates and analyzes:
    - Secrets Manager secrets
    - SSM Parameter Store parameters
    - Rotation policies
    - Encryption settings
    - Cross-account access
    """
    
    def __init__(self,
                 access_key: Optional[str] = None,
                 secret_key: Optional[str] = None,
                 session_token: Optional[str] = None,
                 profile: Optional[str] = None,
                 region: str = 'us-east-1'):
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token
        self.profile = profile
        self.region = region
        self._session = None
        self._sm_client = None
        self._ssm_client = None
    
    def _get_boto3_session(self):
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
            return boto3.Session()
        except ImportError:
            raise ImportError("boto3 required")
    
    def _get_sm_client(self):
        if not self._sm_client:
            if not self._session:
                self._session = self._get_boto3_session()
            self._sm_client = self._session.client('secretsmanager', region_name=self.region)
        return self._sm_client
    
    def _get_ssm_client(self):
        if not self._ssm_client:
            if not self._session:
                self._session = self._get_boto3_session()
            self._ssm_client = self._session.client('ssm', region_name=self.region)
        return self._ssm_client
    
    def enumerate_secrets(self) -> List[SecretInfo]:
        """Enumerate Secrets Manager secrets"""
        secrets = []
        
        try:
            client = self._get_sm_client()
            paginator = client.get_paginator('list_secrets')
            
            for page in paginator.paginate():
                for secret_data in page.get('SecretList', []):
                    secret = SecretInfo(
                        name=secret_data.get('Name', ''),
                        arn=secret_data.get('ARN', ''),
                        description=secret_data.get('Description', ''),
                        kms_key_id=secret_data.get('KmsKeyId', ''),
                        rotation_enabled=secret_data.get('RotationEnabled', False),
                        rotation_lambda=secret_data.get('RotationLambdaARN', ''),
                        rotation_days=secret_data.get('RotationRules', {}).get('AutomaticallyAfterDays', 0),
                        last_rotated=str(secret_data.get('LastRotatedDate', '')),
                        last_accessed=str(secret_data.get('LastAccessedDate', '')),
                        created_date=str(secret_data.get('CreatedDate', '')),
                        tags={t['Key']: t['Value'] for t in secret_data.get('Tags', [])}
                    )
                    
                    try:
                        versions = client.list_secret_version_ids(SecretId=secret.arn)
                        secret.version_ids = [v['VersionId'] for v in versions.get('Versions', [])]
                    except Exception:
                        pass
                    
                    secrets.append(secret)
                    
        except Exception as e:
            logger.error(f"Error enumerating secrets: {e}")
        
        return secrets
    
    def enumerate_ssm_parameters(self, with_decryption: bool = False) -> List[SSMParameter]:
        """Enumerate SSM Parameter Store parameters"""
        parameters = []
        
        try:
            client = self._get_ssm_client()
            paginator = client.get_paginator('describe_parameters')
            
            for page in paginator.paginate():
                for param_data in page.get('Parameters', []):
                    param = SSMParameter(
                        name=param_data.get('Name', ''),
                        type=param_data.get('Type', 'String'),
                        description=param_data.get('Description', ''),
                        version=param_data.get('Version', 1),
                        tier=param_data.get('Tier', 'Standard'),
                        key_id=param_data.get('KeyId', ''),
                        last_modified=str(param_data.get('LastModifiedDate', ''))
                    )
                    
                    if with_decryption and param.type != 'SecureString':
                        try:
                            value_resp = client.get_parameter(Name=param.name)
                            param.value = value_resp.get('Parameter', {}).get('Value', '')
                        except Exception:
                            pass
                    
                    parameters.append(param)
                    
        except Exception as e:
            logger.error(f"Error enumerating SSM parameters: {e}")
        
        return parameters
    
    def check_secret_policy(self, secret_arn: str) -> Dict[str, Any]:
        """Check secret resource policy for cross-account access"""
        try:
            client = self._get_sm_client()
            policy_resp = client.get_resource_policy(SecretId=secret_arn)
            
            import json
            policy = json.loads(policy_resp.get('ResourcePolicy', '{}'))
            
            cross_account = False
            external_principals = []
            
            for statement in policy.get('Statement', []):
                principal = statement.get('Principal', {})
                if isinstance(principal, str) and principal == '*':
                    cross_account = True
                    external_principals.append('*')
                elif isinstance(principal, dict):
                    aws_principal = principal.get('AWS', [])
                    if isinstance(aws_principal, str):
                        aws_principal = [aws_principal]
                    for p in aws_principal:
                        if ':' in p:
                            account = p.split(':')[4] if len(p.split(':')) > 4 else ''
                            if account:
                                cross_account = True
                                external_principals.append(account)
            
            return {
                'has_policy': True,
                'cross_account': cross_account,
                'external_principals': external_principals,
                'policy': policy
            }
        except Exception:
            return {'has_policy': False, 'cross_account': False}
    
    def analyze_security(self,
                        secrets: List[SecretInfo],
                        parameters: List[SSMParameter]) -> List[SecretFinding]:
        """Analyze secrets for security issues"""
        findings = []
        
        for secret in secrets:
            if not secret.rotation_enabled:
                findings.append(SecretFinding(
                    finding_type='NO_ROTATION',
                    severity=SecretRisk.HIGH,
                    resource_id=secret.arn,
                    resource_type='Secret',
                    title='Secret Rotation Disabled',
                    description=f"Secret {secret.name} does not have rotation enabled",
                    recommendation='Enable automatic rotation',
                    mitre_technique='T1552'
                ))
            
            if secret.needs_rotation:
                findings.append(SecretFinding(
                    finding_type='STALE_SECRET',
                    severity=SecretRisk.MEDIUM,
                    resource_id=secret.arn,
                    resource_type='Secret',
                    title='Secret Needs Rotation',
                    description=f"Secret {secret.name} has not been rotated recently",
                    recommendation='Rotate secret immediately'
                ))
            
            if not secret.kms_key_id:
                findings.append(SecretFinding(
                    finding_type='DEFAULT_KMS',
                    severity=SecretRisk.LOW,
                    resource_id=secret.arn,
                    resource_type='Secret',
                    title='Using Default KMS Key',
                    description=f"Secret {secret.name} uses default AWS managed key",
                    recommendation='Use customer managed KMS key for better control'
                ))
            
            policy_info = self.check_secret_policy(secret.arn)
            if policy_info.get('cross_account'):
                findings.append(SecretFinding(
                    finding_type='CROSS_ACCOUNT',
                    severity=SecretRisk.HIGH,
                    resource_id=secret.arn,
                    resource_type='Secret',
                    title='Cross-Account Secret Access',
                    description=f"Secret {secret.name} allows cross-account access",
                    recommendation='Review and restrict cross-account access',
                    metadata={'principals': policy_info.get('external_principals', [])}
                ))
        
        for param in parameters:
            if not param.is_encrypted:
                findings.append(SecretFinding(
                    finding_type='UNENCRYPTED_PARAM',
                    severity=SecretRisk.MEDIUM,
                    resource_id=param.name,
                    resource_type='SSMParameter',
                    title='Unencrypted Parameter',
                    description=f"Parameter {param.name} is not using SecureString",
                    recommendation='Use SecureString type for sensitive parameters'
                ))
        
        return findings
    
    def enumerate_all(self) -> Dict[str, Any]:
        """Full enumeration and analysis"""
        secrets = self.enumerate_secrets()
        parameters = self.enumerate_ssm_parameters()
        findings = self.analyze_security(secrets, parameters)
        
        return {
            'secrets': secrets,
            'parameters': parameters,
            'findings': findings,
            'summary': {
                'total_secrets': len(secrets),
                'total_parameters': len(parameters),
                'secrets_without_rotation': len([s for s in secrets if not s.rotation_enabled]),
                'unencrypted_parameters': len([p for p in parameters if not p.is_encrypted]),
                'total_findings': len(findings)
            }
        }


__all__ = ['SecretsManagerScanner', 'SecretInfo', 'SSMParameter', 'SecretFinding']
