"""
AWS Enumeration Package
Comprehensive AWS service enumeration for security assessment
"""

from .iam_enum import IAMEnumerator
from .iam_privesc import (
    PRIVESC_METHODS,
    analyze_user_privesc,
    analyze_role_privesc,
    detect_shadow_admins
)
from .iam_models import (
    IAMUser, IAMRole, IAMPolicy, IAMGroup, AccessKeyInfo,
    IAMFinding, IAMRiskLevel, MITRE_IAM_TECHNIQUES
)
from .lambda_enum import (
    LambdaEnumerator,
    LambdaFunction,
    APIGatewayEndpoint,
    LambdaFinding
)
from .rds_enum import (
    RDSEnumerator,
    RDSInstance,
    RDSSnapshot,
    RDSFinding
)
from .s3_analyzer import (
    S3AdvancedAnalyzer,
    S3Bucket,
    S3Object,
    S3Finding
)
from .eks_enum import (
    EKSEnumerator,
    EKSCluster,
    EKSNodeGroup,
    EKSFinding
)
from .cloudtrail_analyzer import (
    CloudTrailAnalyzer,
    CloudTrailEvent,
    SecurityAlert,
    ThreatLevel
)
from .secrets_scanner import (
    SecretsManagerScanner,
    SecretInfo,
    SSMParameter,
    SecretFinding
)

__all__ = [
    # IAM
    'IAMEnumerator',
    'IAMUser',
    'IAMRole',
    'IAMPolicy',
    'IAMGroup',
    'AccessKeyInfo',
    'IAMFinding',
    'IAMRiskLevel',
    'MITRE_IAM_TECHNIQUES',
    'PRIVESC_METHODS',
    'analyze_user_privesc',
    'analyze_role_privesc',
    'detect_shadow_admins',
    # Lambda
    'LambdaEnumerator',
    'LambdaFunction',
    'APIGatewayEndpoint',
    'LambdaFinding',
    # RDS
    'RDSEnumerator',
    'RDSInstance',
    'RDSSnapshot',
    'RDSFinding',
    # S3
    'S3AdvancedAnalyzer',
    'S3Bucket',
    'S3Object',
    'S3Finding',
    # EKS
    'EKSEnumerator',
    'EKSCluster',
    'EKSNodeGroup',
    'EKSFinding',
    # CloudTrail
    'CloudTrailAnalyzer',
    'CloudTrailEvent',
    'SecurityAlert',
    'ThreatLevel',
    # Secrets
    'SecretsManagerScanner',
    'SecretInfo',
    'SSMParameter',
    'SecretFinding',
]

