"""
Azure Key Vault Enumerator
Secret, key, and certificate discovery with security analysis
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class KeyVaultRisk(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class KeyVaultInfo:
    """Azure Key Vault details"""
    name: str
    resource_id: str
    location: str
    vault_uri: str = ""
    sku: str = "standard"
    tenant_id: str = ""
    soft_delete_enabled: bool = True
    purge_protection: bool = False
    enabled_for_deployment: bool = False
    enabled_for_disk_encryption: bool = False
    enabled_for_template_deployment: bool = False
    network_acls: Dict[str, Any] = field(default_factory=dict)
    access_policies: List[Dict] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)
    
    @property
    def is_public(self) -> bool:
        acls = self.network_acls
        return acls.get('defaultAction', 'Allow') == 'Allow'
    
    @property
    def has_purge_protection(self) -> bool:
        return self.purge_protection


@dataclass
class KeyVaultSecret:
    """Key Vault secret details"""
    name: str
    vault_name: str
    secret_id: str
    enabled: bool = True
    created: str = ""
    updated: str = ""
    expires: str = ""
    content_type: str = ""
    tags: Dict[str, str] = field(default_factory=dict)
    
    @property
    def is_expired(self) -> bool:
        if self.expires:
            from datetime import datetime
            try:
                exp = datetime.fromisoformat(self.expires.replace('Z', '+00:00').split('+')[0])
                return exp < datetime.now()
            except Exception:
                pass
        return False


@dataclass
class KeyVaultKey:
    """Key Vault key details"""
    name: str
    vault_name: str
    key_id: str
    key_type: str = ""
    key_size: int = 0
    enabled: bool = True
    created: str = ""
    updated: str = ""
    expires: str = ""
    operations: List[str] = field(default_factory=list)
    
    @property
    def is_weak(self) -> bool:
        if self.key_type == 'RSA' and self.key_size < 2048:
            return True
        return False


@dataclass
class KeyVaultCertificate:
    """Key Vault certificate details"""
    name: str
    vault_name: str
    cert_id: str
    enabled: bool = True
    created: str = ""
    updated: str = ""
    expires: str = ""
    issuer: str = ""
    subject: str = ""
    thumbprint: str = ""


@dataclass
class KeyVaultFinding:
    """Security finding for Key Vault"""
    finding_type: str
    severity: KeyVaultRisk
    resource_id: str
    resource_type: str
    title: str
    description: str
    recommendation: str = ""
    mitre_technique: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


class AzureKeyVaultEnumerator:
    """
    Azure Key Vault Enumerator
    
    Discovers and analyzes:
    - Key Vaults and access policies
    - Secrets, keys, and certificates
    - Soft delete and purge protection
    - Network access controls
    """
    
    def __init__(self,
                 subscription_id: Optional[str] = None,
                 credential: Optional[Any] = None):
        self.subscription_id = subscription_id
        self.credential = credential
        self._mgmt_client = None
        self._vault_clients = {}
    
    def _get_credential(self):
        if self.credential:
            return self.credential
        try:
            from azure.identity import DefaultAzureCredential
            return DefaultAzureCredential()
        except ImportError:
            raise ImportError("azure-identity required")
    
    def _get_mgmt_client(self):
        if not self._mgmt_client:
            try:
                from azure.mgmt.keyvault import KeyVaultManagementClient
                credential = self._get_credential()
                self._mgmt_client = KeyVaultManagementClient(credential, self.subscription_id)
            except ImportError:
                raise ImportError("azure-mgmt-keyvault required")
        return self._mgmt_client
    
    def _get_secret_client(self, vault_uri: str):
        if vault_uri not in self._vault_clients:
            try:
                from azure.keyvault.secrets import SecretClient
                credential = self._get_credential()
                self._vault_clients[vault_uri] = {
                    'secrets': SecretClient(vault_url=vault_uri, credential=credential)
                }
            except ImportError:
                raise ImportError("azure-keyvault-secrets required")
        return self._vault_clients[vault_uri].get('secrets')
    
    def enumerate_vaults(self) -> List[KeyVaultInfo]:
        """Enumerate all Key Vaults"""
        vaults = []
        
        try:
            mgmt = self._get_mgmt_client()
            
            for vault in mgmt.vaults.list():
                vault_info = KeyVaultInfo(
                    name=vault.name,
                    resource_id=vault.id,
                    location=vault.location,
                    vault_uri=vault.properties.vault_uri if vault.properties else "",
                    sku=vault.properties.sku.name if vault.properties and vault.properties.sku else "standard",
                    tenant_id=vault.properties.tenant_id if vault.properties else "",
                    soft_delete_enabled=vault.properties.enable_soft_delete if vault.properties else True,
                    purge_protection=vault.properties.enable_purge_protection if vault.properties else False,
                    enabled_for_deployment=vault.properties.enabled_for_deployment if vault.properties else False,
                    enabled_for_disk_encryption=vault.properties.enabled_for_disk_encryption if vault.properties else False,
                    enabled_for_template_deployment=vault.properties.enabled_for_template_deployment if vault.properties else False,
                    network_acls=vault.properties.network_acls.as_dict() if vault.properties and vault.properties.network_acls else {},
                    access_policies=[p.as_dict() for p in vault.properties.access_policies] if vault.properties and vault.properties.access_policies else [],
                    tags=dict(vault.tags) if vault.tags else {}
                )
                vaults.append(vault_info)
                
        except Exception as e:
            logger.error(f"Error enumerating vaults: {e}")
        
        return vaults
    
    def enumerate_secrets(self, vault_uri: str, vault_name: str) -> List[KeyVaultSecret]:
        """Enumerate secrets in a vault"""
        secrets = []
        
        try:
            client = self._get_secret_client(vault_uri)
            
            for secret_props in client.list_properties_of_secrets():
                secret = KeyVaultSecret(
                    name=secret_props.name,
                    vault_name=vault_name,
                    secret_id=secret_props.id or "",
                    enabled=secret_props.enabled or True,
                    created=str(secret_props.created_on) if secret_props.created_on else "",
                    updated=str(secret_props.updated_on) if secret_props.updated_on else "",
                    expires=str(secret_props.expires_on) if secret_props.expires_on else "",
                    content_type=secret_props.content_type or "",
                    tags=dict(secret_props.tags) if secret_props.tags else {}
                )
                secrets.append(secret)
                
        except Exception as e:
            logger.debug(f"Error enumerating secrets in {vault_name}: {e}")
        
        return secrets
    
    def analyze_security(self,
                        vaults: List[KeyVaultInfo],
                        secrets: List[KeyVaultSecret]) -> List[KeyVaultFinding]:
        """Analyze Key Vault security"""
        findings = []
        
        for vault in vaults:
            if not vault.has_purge_protection:
                findings.append(KeyVaultFinding(
                    finding_type='NO_PURGE_PROTECTION',
                    severity=KeyVaultRisk.HIGH,
                    resource_id=vault.resource_id,
                    resource_type='KeyVault',
                    title='Purge Protection Disabled',
                    description=f"Key Vault {vault.name} does not have purge protection",
                    recommendation='Enable purge protection to prevent permanent deletion',
                    mitre_technique='T1485'
                ))
            
            if vault.is_public:
                findings.append(KeyVaultFinding(
                    finding_type='PUBLIC_ACCESS',
                    severity=KeyVaultRisk.HIGH,
                    resource_id=vault.resource_id,
                    resource_type='KeyVault',
                    title='Public Network Access Allowed',
                    description=f"Key Vault {vault.name} allows public network access",
                    recommendation='Configure network ACLs to restrict access'
                ))
            
            overly_permissive = []
            for policy in vault.access_policies:
                permissions = policy.get('permissions', {})
                secret_perms = permissions.get('secrets', [])
                if 'all' in secret_perms or len(secret_perms) > 5:
                    overly_permissive.append(policy.get('objectId', 'unknown'))
            
            if overly_permissive:
                findings.append(KeyVaultFinding(
                    finding_type='BROAD_ACCESS_POLICY',
                    severity=KeyVaultRisk.MEDIUM,
                    resource_id=vault.resource_id,
                    resource_type='KeyVault',
                    title='Overly Permissive Access Policy',
                    description=f"Key Vault {vault.name} has broad access policies",
                    recommendation='Apply principle of least privilege',
                    metadata={'principals': overly_permissive}
                ))
        
        for secret in secrets:
            if secret.is_expired:
                findings.append(KeyVaultFinding(
                    finding_type='EXPIRED_SECRET',
                    severity=KeyVaultRisk.MEDIUM,
                    resource_id=secret.secret_id,
                    resource_type='Secret',
                    title='Expired Secret',
                    description=f"Secret {secret.name} has expired",
                    recommendation='Rotate or remove expired secrets'
                ))
        
        return findings
    
    def enumerate_all(self) -> Dict[str, Any]:
        """Full enumeration and analysis"""
        vaults = self.enumerate_vaults()
        
        all_secrets = []
        for vault in vaults:
            if vault.vault_uri:
                secrets = self.enumerate_secrets(vault.vault_uri, vault.name)
                all_secrets.extend(secrets)
        
        findings = self.analyze_security(vaults, all_secrets)
        
        return {
            'vaults': vaults,
            'secrets': all_secrets,
            'findings': findings,
            'summary': {
                'total_vaults': len(vaults),
                'total_secrets': len(all_secrets),
                'public_vaults': len([v for v in vaults if v.is_public]),
                'no_purge_protection': len([v for v in vaults if not v.has_purge_protection]),
                'expired_secrets': len([s for s in all_secrets if s.is_expired]),
                'total_findings': len(findings)
            }
        }


__all__ = ['AzureKeyVaultEnumerator', 'KeyVaultInfo', 'KeyVaultSecret', 'KeyVaultFinding']
