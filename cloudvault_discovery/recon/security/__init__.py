"""
Security Analysis Package
Cross-cloud security scanning tools
"""

from .secrets import (
    SecretsScanner,
    SecretFinding,
    SecretType,
    SecretSeverity,
    scan_text,
    scan_environment_variables,
    scan_user_data,
    SECRET_PATTERNS
)
from .attack_chain import (
    AttackChainBuilder,
    AttackChain,
    AttackNode,
    AttackStage,
    AttackSeverity,
    MITRE_CLOUD_TECHNIQUES
)
from .compliance import (
    ComplianceChecker,
    ComplianceResult,
    ComplianceCheck,
    ComplianceFramework,
    ComplianceStatus,
    CIS_AWS_CHECKS,
    CIS_AZURE_CHECKS,
    CIS_GCP_CHECKS
)

__all__ = [
    # Secrets Scanner
    'SecretsScanner',
    'SecretFinding',
    'SecretType',
    'SecretSeverity',
    'scan_text',
    'scan_environment_variables',
    'scan_user_data',
    'SECRET_PATTERNS',
    # Attack Chain
    'AttackChainBuilder',
    'AttackChain',
    'AttackNode',
    'AttackStage',
    'AttackSeverity',
    'MITRE_CLOUD_TECHNIQUES',
    # Compliance
    'ComplianceChecker',
    'ComplianceResult',
    'ComplianceCheck',
    'ComplianceFramework',
    'ComplianceStatus',
    'CIS_AWS_CHECKS',
    'CIS_AZURE_CHECKS',
    'CIS_GCP_CHECKS'
]
