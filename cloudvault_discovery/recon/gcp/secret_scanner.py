"""
GCP Secret Manager Scanner
Secret enumeration, version tracking, and IAM binding analysis
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class GCPSecretRisk(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class GCPSecret:
    """GCP Secret Manager secret details"""
    name: str
    project: str
    secret_id: str
    create_time: str = ""
    labels: Dict[str, str] = field(default_factory=dict)
    replication: str = ""
    rotation: Dict[str, Any] = field(default_factory=dict)
    version_count: int = 0
    latest_version: str = ""
    topics: List[str] = field(default_factory=list)
    
    @property
    def has_rotation(self) -> bool:
        return bool(self.rotation.get('rotationPeriod'))
    
    @property
    def short_name(self) -> str:
        return self.name.split('/')[-1] if '/' in self.name else self.name


@dataclass
class GCPSecretVersion:
    """GCP Secret version details"""
    name: str
    secret_name: str
    state: str = "ENABLED"
    create_time: str = ""
    destroy_time: str = ""
    
    @property
    def is_enabled(self) -> bool:
        return self.state == "ENABLED"
    
    @property
    def version_number(self) -> str:
        return self.name.split('/')[-1] if '/' in self.name else self.name


@dataclass
class GCPSecretIAMBinding:
    """IAM binding for a secret"""
    secret_name: str
    role: str
    members: List[str] = field(default_factory=list)
    
    @property
    def has_public_access(self) -> bool:
        return 'allUsers' in self.members or 'allAuthenticatedUsers' in self.members
    
    @property
    def has_service_account(self) -> bool:
        return any('serviceAccount:' in m for m in self.members)


@dataclass
class GCPSecretFinding:
    """Security finding for GCP secrets"""
    finding_type: str
    severity: GCPSecretRisk
    resource_id: str
    resource_type: str
    title: str
    description: str
    recommendation: str = ""
    mitre_technique: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


class GCPSecretManagerScanner:
    """
    GCP Secret Manager Scanner
    
    Discovers and analyzes:
    - Secrets and versions
    - Rotation policies
    - IAM bindings
    - Replication settings
    """
    
    def __init__(self,
                 project_id: Optional[str] = None,
                 credentials: Optional[Any] = None):
        self.project_id = project_id
        self.credentials = credentials
        self._sm_client = None
    
    def _get_client(self):
        if not self._sm_client:
            try:
                from google.cloud import secretmanager
                self._sm_client = secretmanager.SecretManagerServiceClient(credentials=self.credentials)
            except ImportError:
                raise ImportError("google-cloud-secret-manager required")
        return self._sm_client
    
    def enumerate_secrets(self) -> List[GCPSecret]:
        """Enumerate all secrets in project"""
        secrets = []
        
        try:
            client = self._get_client()
            parent = f"projects/{self.project_id}"
            
            for secret in client.list_secrets(request={"parent": parent}):
                replication = ""
                if secret.replication:
                    if secret.replication.automatic:
                        replication = "automatic"
                    elif secret.replication.user_managed:
                        replication = "user_managed"
                
                rotation = {}
                if secret.rotation:
                    rotation = {
                        'rotationPeriod': str(secret.rotation.rotation_period),
                        'nextRotationTime': str(secret.rotation.next_rotation_time)
                    }
                
                gcp_secret = GCPSecret(
                    name=secret.name,
                    project=self.project_id,
                    secret_id=secret.name.split('/')[-1],
                    create_time=str(secret.create_time),
                    labels=dict(secret.labels) if secret.labels else {},
                    replication=replication,
                    rotation=rotation,
                    topics=[t for t in secret.topics] if secret.topics else []
                )
                
                versions = self.enumerate_versions(secret.name)
                gcp_secret.version_count = len(versions)
                if versions:
                    gcp_secret.latest_version = versions[0].version_number
                
                secrets.append(gcp_secret)
                
        except Exception as e:
            logger.error(f"Error enumerating secrets: {e}")
        
        return secrets
    
    def enumerate_versions(self, secret_name: str) -> List[GCPSecretVersion]:
        """Enumerate versions of a secret"""
        versions = []
        
        try:
            client = self._get_client()
            
            for version in client.list_secret_versions(request={"parent": secret_name}):
                ver = GCPSecretVersion(
                    name=version.name,
                    secret_name=secret_name,
                    state=version.state.name if version.state else "UNKNOWN",
                    create_time=str(version.create_time),
                    destroy_time=str(version.destroy_time) if version.destroy_time else ""
                )
                versions.append(ver)
                
        except Exception as e:
            logger.debug(f"Error enumerating versions for {secret_name}: {e}")
        
        return versions
    
    def get_iam_bindings(self, secret_name: str) -> List[GCPSecretIAMBinding]:
        """Get IAM bindings for a secret"""
        bindings = []
        
        try:
            client = self._get_client()
            policy = client.get_iam_policy(request={"resource": secret_name})
            
            for binding in policy.bindings:
                iam_binding = GCPSecretIAMBinding(
                    secret_name=secret_name,
                    role=binding.role,
                    members=list(binding.members)
                )
                bindings.append(iam_binding)
                
        except Exception as e:
            logger.debug(f"Error getting IAM for {secret_name}: {e}")
        
        return bindings
    
    def analyze_security(self,
                        secrets: List[GCPSecret],
                        all_bindings: Dict[str, List[GCPSecretIAMBinding]]) -> List[GCPSecretFinding]:
        """Analyze secrets for security issues"""
        findings = []
        
        for secret in secrets:
            if not secret.has_rotation:
                findings.append(GCPSecretFinding(
                    finding_type='NO_ROTATION',
                    severity=GCPSecretRisk.MEDIUM,
                    resource_id=secret.name,
                    resource_type='Secret',
                    title='No Rotation Policy',
                    description=f"Secret {secret.short_name} has no rotation policy",
                    recommendation='Configure automatic rotation',
                    mitre_technique='T1552'
                ))
            
            if secret.version_count > 10:
                findings.append(GCPSecretFinding(
                    finding_type='TOO_MANY_VERSIONS',
                    severity=GCPSecretRisk.LOW,
                    resource_id=secret.name,
                    resource_type='Secret',
                    title='Many Secret Versions',
                    description=f"Secret {secret.short_name} has {secret.version_count} versions",
                    recommendation='Cleanup old versions to reduce attack surface'
                ))
            
            bindings = all_bindings.get(secret.name, [])
            for binding in bindings:
                if binding.has_public_access:
                    findings.append(GCPSecretFinding(
                        finding_type='PUBLIC_ACCESS',
                        severity=GCPSecretRisk.CRITICAL,
                        resource_id=secret.name,
                        resource_type='Secret',
                        title='Public Secret Access',
                        description=f"Secret {secret.short_name} is accessible publicly",
                        recommendation='Remove allUsers/allAuthenticatedUsers from IAM',
                        mitre_technique='T1552.005',
                        metadata={'role': binding.role, 'members': binding.members}
                    ))
                
                accessor_roles = [
                    'roles/secretmanager.secretAccessor',
                    'roles/secretmanager.admin',
                    'roles/owner'
                ]
                if binding.role in accessor_roles:
                    external_members = [m for m in binding.members 
                                       if not m.endswith(f'@{self.project_id}.iam.gserviceaccount.com')]
                    if external_members and '@' in str(external_members):
                        findings.append(GCPSecretFinding(
                            finding_type='EXTERNAL_ACCESS',
                            severity=GCPSecretRisk.HIGH,
                            resource_id=secret.name,
                            resource_type='Secret',
                            title='External Secret Access',
                            description=f"Secret {secret.short_name} accessible by external principals",
                            recommendation='Review and restrict external access',
                            metadata={'external': external_members}
                        ))
        
        return findings
    
    def enumerate_all(self) -> Dict[str, Any]:
        """Full enumeration and analysis"""
        secrets = self.enumerate_secrets()
        
        all_bindings = {}
        for secret in secrets:
            bindings = self.get_iam_bindings(secret.name)
            all_bindings[secret.name] = bindings
        
        findings = self.analyze_security(secrets, all_bindings)
        
        total_versions = sum(s.version_count for s in secrets)
        
        return {
            'secrets': secrets,
            'bindings': all_bindings,
            'findings': findings,
            'summary': {
                'total_secrets': len(secrets),
                'total_versions': total_versions,
                'without_rotation': len([s for s in secrets if not s.has_rotation]),
                'total_findings': len(findings)
            }
        }


__all__ = ['GCPSecretManagerScanner', 'GCPSecret', 'GCPSecretVersion', 'GCPSecretIAMBinding', 'GCPSecretFinding']
