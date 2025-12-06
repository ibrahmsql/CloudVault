"""
Cloud Compliance Checker
CIS Benchmark checks for AWS, Azure, and GCP
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable
from enum import Enum

logger = logging.getLogger(__name__)


class ComplianceFramework(Enum):
    """Compliance frameworks"""
    CIS_AWS_1_4 = "cis_aws_1.4.0"
    CIS_AZURE_1_3 = "cis_azure_1.3.0"
    CIS_GCP_1_2 = "cis_gcp_1.2.0"
    PCI_DSS = "pci_dss"
    SOC2 = "soc2"


class ComplianceStatus(Enum):
    """Compliance check status"""
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


class Severity(Enum):
    """Finding severity"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ComplianceCheck:
    """Single compliance check definition"""
    check_id: str
    title: str
    description: str
    framework: ComplianceFramework
    section: str
    severity: Severity
    check_function: Optional[Callable] = None
    remediation: str = ""
    rationale: str = ""


@dataclass
class ComplianceResult:
    """Result of a compliance check"""
    check_id: str
    title: str
    status: ComplianceStatus
    framework: str
    section: str
    severity: str
    resource_id: str = ""
    resource_type: str = ""
    details: str = ""
    remediation: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


# CIS AWS Benchmark Checks
CIS_AWS_CHECKS = {
    # 1.x Identity and Access Management
    '1.4': {
        'title': 'Ensure no root access keys exist',
        'section': '1.4',
        'severity': Severity.CRITICAL,
        'description': 'The root user should not have access keys',
        'remediation': 'Delete all access keys associated with the root user'
    },
    '1.5': {
        'title': 'Ensure MFA is enabled for root account',
        'section': '1.5',
        'severity': Severity.CRITICAL,
        'description': 'Root account should have MFA enabled',
        'remediation': 'Enable MFA for the root account'
    },
    '1.10': {
        'title': 'Ensure MFA is enabled for all IAM users with console password',
        'section': '1.10',
        'severity': Severity.HIGH,
        'description': 'All console users should have MFA enabled',
        'remediation': 'Enable MFA for all IAM users with console access'
    },
    '1.12': {
        'title': 'Ensure credentials unused for 90 days are disabled',
        'section': '1.12',
        'severity': Severity.MEDIUM,
        'description': 'Unused credentials should be disabled',
        'remediation': 'Disable or delete credentials not used for 90+ days'
    },
    '1.14': {
        'title': 'Ensure access keys are rotated every 90 days',
        'section': '1.14',
        'severity': Severity.MEDIUM,
        'description': 'Access keys should be rotated regularly',
        'remediation': 'Rotate access keys every 90 days or less'
    },
    '1.16': {
        'title': 'Ensure IAM policies are attached only to groups or roles',
        'section': '1.16',
        'severity': Severity.LOW,
        'description': 'Avoid attaching policies directly to users',
        'remediation': 'Attach policies to groups or roles instead of users'
    },
    
    # 2.x Logging
    '2.1': {
        'title': 'Ensure CloudTrail is enabled in all regions',
        'section': '2.1',
        'severity': Severity.HIGH,
        'description': 'CloudTrail should be enabled in all regions',
        'remediation': 'Enable multi-region CloudTrail'
    },
    '2.2': {
        'title': 'Ensure CloudTrail log file validation is enabled',
        'section': '2.2',
        'severity': Severity.MEDIUM,
        'description': 'CloudTrail log file validation ensures integrity',
        'remediation': 'Enable log file validation for CloudTrail'
    },
    
    # 3.x Monitoring
    '3.1': {
        'title': 'Ensure a log metric filter for unauthorized API calls',
        'section': '3.1',
        'severity': Severity.MEDIUM,
        'description': 'Monitor for unauthorized API calls',
        'remediation': 'Create CloudWatch metric filter for unauthorized API calls'
    },
    
    # 4.x Networking
    '4.1': {
        'title': 'Ensure no security groups allow ingress 0.0.0.0/0 to port 22',
        'section': '4.1',
        'severity': Severity.HIGH,
        'description': 'SSH should not be open to the world',
        'remediation': 'Restrict SSH access to specific IPs'
    },
    '4.2': {
        'title': 'Ensure no security groups allow ingress 0.0.0.0/0 to port 3389',
        'section': '4.2',
        'severity': Severity.HIGH,
        'description': 'RDP should not be open to the world',
        'remediation': 'Restrict RDP access to specific IPs'
    },
    '4.3': {
        'title': 'Ensure default VPC is not used',
        'section': '4.3',
        'severity': Severity.MEDIUM,
        'description': 'Avoid using default VPC for production',
        'remediation': 'Create custom VPCs with proper network segmentation'
    },
    
    # 5.x Storage
    '5.1': {
        'title': 'Ensure S3 bucket access logging is enabled',
        'section': '5.1',
        'severity': Severity.MEDIUM,
        'description': 'S3 buckets should have access logging enabled',
        'remediation': 'Enable server access logging on S3 buckets'
    },
    '5.2': {
        'title': 'Ensure S3 bucket encryption is enabled',
        'section': '5.2',
        'severity': Severity.MEDIUM,
        'description': 'S3 buckets should have default encryption',
        'remediation': 'Enable default encryption on S3 buckets'
    },
    '5.3': {
        'title': 'Ensure S3 bucket public access is blocked',
        'section': '5.3',
        'severity': Severity.HIGH,
        'description': 'S3 buckets should block public access',
        'remediation': 'Enable S3 block public access settings'
    },
}

# CIS Azure Benchmark Checks
CIS_AZURE_CHECKS = {
    '1.1': {
        'title': 'Ensure MFA is enabled for all privileged users',
        'section': '1.1',
        'severity': Severity.CRITICAL,
        'description': 'MFA should be enabled for privileged users',
        'remediation': 'Enable MFA in Azure AD for privileged accounts'
    },
    '2.1': {
        'title': 'Ensure Azure Defender is enabled',
        'section': '2.1',
        'severity': Severity.HIGH,
        'description': 'Azure Defender provides threat protection',
        'remediation': 'Enable Azure Defender for all resource types'
    },
    '4.1': {
        'title': 'Ensure NSG flow logs are enabled',
        'section': '4.1',
        'severity': Severity.MEDIUM,
        'description': 'NSG flow logs enable network monitoring',
        'remediation': 'Enable NSG flow logs for all NSGs'
    },
    '6.1': {
        'title': 'Ensure RDP access is restricted from internet',
        'section': '6.1',
        'severity': Severity.HIGH,
        'description': 'RDP should not be accessible from internet',
        'remediation': 'Restrict RDP access using NSG rules'
    },
    '6.2': {
        'title': 'Ensure SSH access is restricted from internet',
        'section': '6.2',
        'severity': Severity.HIGH,
        'description': 'SSH should not be accessible from internet',
        'remediation': 'Restrict SSH access using NSG rules'
    },
    '7.1': {
        'title': 'Ensure VM disks are encrypted',
        'section': '7.1',
        'severity': Severity.MEDIUM,
        'description': 'VM disks should use Azure Disk Encryption',
        'remediation': 'Enable Azure Disk Encryption on VMs'
    },
    '8.1': {
        'title': 'Ensure storage account encryption is enabled',
        'section': '8.1',
        'severity': Severity.MEDIUM,
        'description': 'Storage accounts should use encryption',
        'remediation': 'Encryption is enabled by default, verify settings'
    },
}

# CIS GCP Benchmark Checks
CIS_GCP_CHECKS = {
    '1.1': {
        'title': 'Ensure corporate login credentials are used',
        'section': '1.1',
        'severity': Severity.HIGH,
        'description': 'Use corporate accounts, not personal',
        'remediation': 'Use Cloud Identity or Google Workspace'
    },
    '1.4': {
        'title': 'Ensure service account has no admin privileges',
        'section': '1.4',
        'severity': Severity.HIGH,
        'description': 'Service accounts should have minimal privileges',
        'remediation': 'Use least privilege for service accounts'
    },
    '1.5': {
        'title': 'Ensure service account keys are rotated',
        'section': '1.5',
        'severity': Severity.MEDIUM,
        'description': 'Service account keys should be rotated',
        'remediation': 'Rotate service account keys regularly'
    },
    '2.1': {
        'title': 'Ensure Cloud Audit Logging is enabled',
        'section': '2.1',
        'severity': Severity.HIGH,
        'description': 'Cloud Audit Logs should be enabled',
        'remediation': 'Enable Cloud Audit Logs for all services'
    },
    '3.1': {
        'title': 'Ensure default network does not exist',
        'section': '3.1',
        'severity': Severity.MEDIUM,
        'description': 'Delete the default VPC network',
        'remediation': 'Delete default network and create custom VPCs'
    },
    '3.6': {
        'title': 'Ensure SSH access is restricted from internet',
        'section': '3.6',
        'severity': Severity.HIGH,
        'description': 'SSH should not be open to 0.0.0.0/0',
        'remediation': 'Restrict SSH using firewall rules or IAP'
    },
    '3.7': {
        'title': 'Ensure RDP access is restricted from internet',
        'section': '3.7',
        'severity': Severity.HIGH,
        'description': 'RDP should not be open to 0.0.0.0/0',
        'remediation': 'Restrict RDP using firewall rules'
    },
    '4.1': {
        'title': 'Ensure instances are not using default service account',
        'section': '4.1',
        'severity': Severity.MEDIUM,
        'description': 'Avoid using default compute service account',
        'remediation': 'Create dedicated service accounts for VMs'
    },
    '4.2': {
        'title': 'Ensure instances do not use full cloud-platform scope',
        'section': '4.2',
        'severity': Severity.HIGH,
        'description': 'Limit service account scopes',
        'remediation': 'Use minimal required scopes'
    },
    '5.1': {
        'title': 'Ensure Cloud Storage bucket has uniform bucket-level access',
        'section': '5.1',
        'severity': Severity.MEDIUM,
        'description': 'Use uniform bucket-level access',
        'remediation': 'Enable uniform bucket-level access'
    },
}


class ComplianceChecker:
    """
    Cloud Compliance Checker
    
    Runs CIS Benchmark checks against cloud resources
    and generates compliance reports.
    """
    
    def __init__(self, framework: ComplianceFramework = ComplianceFramework.CIS_AWS_1_4):
        self.framework = framework
        self.results: List[ComplianceResult] = []
        self._checks = self._get_checks_for_framework()
    
    def _get_checks_for_framework(self) -> Dict[str, Dict]:
        """Get checks for the selected framework"""
        if self.framework == ComplianceFramework.CIS_AWS_1_4:
            return CIS_AWS_CHECKS
        elif self.framework == ComplianceFramework.CIS_AZURE_1_3:
            return CIS_AZURE_CHECKS
        elif self.framework == ComplianceFramework.CIS_GCP_1_2:
            return CIS_GCP_CHECKS
        return {}
    
    def check_iam_users_mfa(self, users: List[Any]) -> List[ComplianceResult]:
        """Check CIS 1.10 - MFA for console users"""
        results = []
        
        for user in users:
            user_name = getattr(user, 'user_name', user.get('user_name', 'unknown'))
            has_mfa = getattr(user, 'has_mfa', user.get('has_mfa', False))
            has_console = getattr(user, 'has_console_access', user.get('has_console_access', False))
            
            if has_console:
                status = ComplianceStatus.PASS if has_mfa else ComplianceStatus.FAIL
                results.append(ComplianceResult(
                    check_id='1.10',
                    title='Ensure MFA is enabled for console users',
                    status=status,
                    framework=self.framework.value,
                    section='1.10',
                    severity='high',
                    resource_id=user_name,
                    resource_type='IAMUser',
                    details=f"User {user_name}: MFA {'enabled' if has_mfa else 'disabled'}",
                    remediation='Enable MFA for this user'
                ))
        
        return results
    
    def check_access_key_rotation(self, users: List[Any]) -> List[ComplianceResult]:
        """Check CIS 1.14 - Access key rotation"""
        results = []
        from datetime import datetime
        
        for user in users:
            user_name = getattr(user, 'user_name', user.get('user_name', 'unknown'))
            access_keys = getattr(user, 'access_keys', user.get('access_keys', []))
            
            for key in access_keys:
                key_id = key.get('access_key_id', 'unknown')
                create_date = key.get('create_date', '')
                
                if create_date:
                    try:
                        created = datetime.fromisoformat(create_date.replace('Z', '+00:00').split('+')[0])
                        age_days = (datetime.now() - created).days
                        status = ComplianceStatus.PASS if age_days <= 90 else ComplianceStatus.FAIL
                        
                        results.append(ComplianceResult(
                            check_id='1.14',
                            title='Ensure access keys are rotated every 90 days',
                            status=status,
                            framework=self.framework.value,
                            section='1.14',
                            severity='medium',
                            resource_id=key_id,
                            resource_type='AccessKey',
                            details=f"Access key {key_id} is {age_days} days old",
                            remediation='Rotate this access key',
                            metadata={'age_days': age_days, 'user': user_name}
                        ))
                    except Exception:
                        pass
        
        return results
    
    def check_s3_public_access(self, buckets: List[Any]) -> List[ComplianceResult]:
        """Check CIS 5.3 - S3 public access blocked"""
        results = []
        
        for bucket in buckets:
            name = getattr(bucket, 'name', bucket.get('name', 'unknown'))
            has_blocked = getattr(bucket, 'has_public_access_blocked', 
                                 bucket.get('has_public_access_blocked', False))
            
            status = ComplianceStatus.PASS if has_blocked else ComplianceStatus.FAIL
            results.append(ComplianceResult(
                check_id='5.3',
                title='Ensure S3 bucket public access is blocked',
                status=status,
                framework=self.framework.value,
                section='5.3',
                severity='high',
                resource_id=name,
                resource_type='S3Bucket',
                details=f"Bucket {name}: public access {'blocked' if has_blocked else 'NOT blocked'}",
                remediation='Enable S3 Block Public Access settings'
            ))
        
        return results
    
    def check_security_group_ssh(self, security_groups: List[Any]) -> List[ComplianceResult]:
        """Check CIS 4.1 - SSH not open to world"""
        results = []
        
        for sg in security_groups:
            sg_id = getattr(sg, 'group_id', sg.get('group_id', 'unknown'))
            has_exposed_ssh = getattr(sg, 'has_exposed_ssh', sg.get('has_exposed_ssh', False))
            
            status = ComplianceStatus.FAIL if has_exposed_ssh else ComplianceStatus.PASS
            results.append(ComplianceResult(
                check_id='4.1',
                title='Ensure no security groups allow ingress to SSH from 0.0.0.0/0',
                status=status,
                framework=self.framework.value,
                section='4.1',
                severity='high',
                resource_id=sg_id,
                resource_type='SecurityGroup',
                details=f"Security group {sg_id}: SSH {'exposed to 0.0.0.0/0' if has_exposed_ssh else 'restricted'}",
                remediation='Restrict SSH to specific IP ranges'
            ))
        
        return results
    
    def check_encryption(self, resources: List[Any], resource_type: str) -> List[ComplianceResult]:
        """Check encryption status for resources"""
        results = []
        
        for resource in resources:
            res_id = getattr(resource, 'resource_id', 
                           getattr(resource, 'db_instance_id',
                           getattr(resource, 'name', resource.get('id', 'unknown'))))
            encrypted = getattr(resource, 'storage_encrypted',
                              getattr(resource, 'encryption',
                              resource.get('encrypted', False)))
            
            status = ComplianceStatus.PASS if encrypted else ComplianceStatus.FAIL
            results.append(ComplianceResult(
                check_id='5.2',
                title='Ensure encryption is enabled',
                status=status,
                framework=self.framework.value,
                section='5.2',
                severity='medium',
                resource_id=str(res_id),
                resource_type=resource_type,
                details=f"Resource {res_id}: {'encrypted' if encrypted else 'NOT encrypted'}",
                remediation='Enable encryption for this resource'
            ))
        
        return results
    
    def run_all_checks(self, 
                      users: List[Any] = None,
                      buckets: List[Any] = None,
                      security_groups: List[Any] = None,
                      databases: List[Any] = None) -> Dict[str, Any]:
        """Run all applicable compliance checks"""
        all_results = []
        
        if users:
            all_results.extend(self.check_iam_users_mfa(users))
            all_results.extend(self.check_access_key_rotation(users))
        
        if buckets:
            all_results.extend(self.check_s3_public_access(buckets))
            all_results.extend(self.check_encryption(buckets, 'S3Bucket'))
        
        if security_groups:
            all_results.extend(self.check_security_group_ssh(security_groups))
        
        if databases:
            all_results.extend(self.check_encryption(databases, 'RDSInstance'))
        
        self.results = all_results
        
        # Generate summary
        passed = len([r for r in all_results if r.status == ComplianceStatus.PASS])
        failed = len([r for r in all_results if r.status == ComplianceStatus.FAIL])
        
        return {
            'framework': self.framework.value,
            'total_checks': len(all_results),
            'passed': passed,
            'failed': failed,
            'compliance_rate': (passed / len(all_results) * 100) if all_results else 0,
            'results': all_results,
            'by_severity': {
                'critical': len([r for r in all_results if r.severity == 'critical' and r.status == ComplianceStatus.FAIL]),
                'high': len([r for r in all_results if r.severity == 'high' and r.status == ComplianceStatus.FAIL]),
                'medium': len([r for r in all_results if r.severity == 'medium' and r.status == ComplianceStatus.FAIL]),
                'low': len([r for r in all_results if r.severity == 'low' and r.status == ComplianceStatus.FAIL])
            }
        }


__all__ = [
    'ComplianceChecker',
    'ComplianceResult',
    'ComplianceCheck',
    'ComplianceFramework',
    'ComplianceStatus',
    'CIS_AWS_CHECKS',
    'CIS_AZURE_CHECKS',
    'CIS_GCP_CHECKS'
]
