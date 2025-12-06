"""
AWS IAM Data Models
Dataclasses for IAM enumeration results
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum
from datetime import datetime


class IAMRiskLevel(Enum):
    """Risk levels for IAM findings"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PrivilegeEscalationType(Enum):
    """Types of privilege escalation vectors"""
    CREATE_USER = "iam:CreateUser"
    CREATE_LOGIN_PROFILE = "iam:CreateLoginProfile"
    UPDATE_LOGIN_PROFILE = "iam:UpdateLoginProfile"
    CREATE_ACCESS_KEY = "iam:CreateAccessKey"
    CREATE_POLICY_VERSION = "iam:CreatePolicyVersion"
    SET_DEFAULT_POLICY_VERSION = "iam:SetDefaultPolicyVersion"
    ATTACH_USER_POLICY = "iam:AttachUserPolicy"
    ATTACH_GROUP_POLICY = "iam:AttachGroupPolicy"
    ATTACH_ROLE_POLICY = "iam:AttachRolePolicy"
    PUT_USER_POLICY = "iam:PutUserPolicy"
    PUT_GROUP_POLICY = "iam:PutGroupPolicy"
    PUT_ROLE_POLICY = "iam:PutRolePolicy"
    ADD_USER_TO_GROUP = "iam:AddUserToGroup"
    UPDATE_ASSUME_ROLE_POLICY = "iam:UpdateAssumeRolePolicy"
    PASS_ROLE = "iam:PassRole"
    ASSUME_ROLE = "sts:AssumeRole"
    LAMBDA_CREATE = "lambda:CreateFunction"
    LAMBDA_INVOKE = "lambda:InvokeFunction"
    CLOUDFORMATION_CREATE = "cloudformation:CreateStack"
    DATAPIPELINE_CREATE = "datapipeline:CreatePipeline"
    GLUE_CREATE = "glue:CreateDevEndpoint"


@dataclass
class IAMUser:
    """IAM user details"""
    user_name: str
    user_id: str
    arn: str
    create_date: str = ""
    password_last_used: str = ""
    path: str = "/"
    permissions_boundary: str = ""
    tags: Dict[str, str] = field(default_factory=dict)
    groups: List[str] = field(default_factory=list)
    attached_policies: List[str] = field(default_factory=list)
    inline_policies: List[str] = field(default_factory=list)
    access_keys: List[Dict[str, Any]] = field(default_factory=list)
    mfa_devices: List[str] = field(default_factory=list)
    
    @property
    def has_console_access(self) -> bool:
        return bool(self.password_last_used)
    
    @property
    def has_mfa(self) -> bool:
        return len(self.mfa_devices) > 0
    
    @property
    def is_admin(self) -> bool:
        admin_policies = ['AdministratorAccess', 'IAMFullAccess', 'PowerUserAccess']
        return any(p in self.attached_policies for p in admin_policies)


@dataclass
class IAMRole:
    """IAM role details"""
    role_name: str
    role_id: str
    arn: str
    create_date: str = ""
    path: str = "/"
    description: str = ""
    max_session_duration: int = 3600
    assume_role_policy: Dict[str, Any] = field(default_factory=dict)
    attached_policies: List[str] = field(default_factory=list)
    inline_policies: List[str] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)
    instance_profiles: List[str] = field(default_factory=list)
    
    @property
    def is_service_role(self) -> bool:
        policy = self.assume_role_policy
        if not policy:
            return False
        for statement in policy.get('Statement', []):
            principal = statement.get('Principal', {})
            if isinstance(principal, dict) and 'Service' in principal:
                return True
        return False
    
    @property
    def allows_cross_account(self) -> bool:
        policy = self.assume_role_policy
        if not policy:
            return False
        for statement in policy.get('Statement', []):
            principal = statement.get('Principal', {})
            if isinstance(principal, dict):
                aws_principal = principal.get('AWS', '')
                if isinstance(aws_principal, str) and ':' in aws_principal:
                    return True
                elif isinstance(aws_principal, list):
                    return any(':' in p for p in aws_principal)
        return False


@dataclass
class IAMPolicy:
    """IAM policy details"""
    policy_name: str
    policy_id: str
    arn: str
    path: str = "/"
    default_version_id: str = "v1"
    attachment_count: int = 0
    is_attachable: bool = True
    create_date: str = ""
    update_date: str = ""
    description: str = ""
    policy_document: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_admin_policy(self) -> bool:
        doc = self.policy_document
        for statement in doc.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                resources = statement.get('Resource', [])
                if actions == '*' and resources == '*':
                    return True
                if isinstance(actions, list) and '*' in actions:
                    if resources == '*' or (isinstance(resources, list) and '*' in resources):
                        return True
        return False
    
    @property
    def allows_privilege_escalation(self) -> List[str]:
        dangerous_actions = [
            'iam:CreateUser', 'iam:CreateLoginProfile', 'iam:UpdateLoginProfile',
            'iam:CreateAccessKey', 'iam:CreatePolicyVersion', 'iam:SetDefaultPolicyVersion',
            'iam:AttachUserPolicy', 'iam:AttachGroupPolicy', 'iam:AttachRolePolicy',
            'iam:PutUserPolicy', 'iam:PutGroupPolicy', 'iam:PutRolePolicy',
            'iam:AddUserToGroup', 'iam:UpdateAssumeRolePolicy', 'iam:PassRole',
            'sts:AssumeRole', 'lambda:CreateFunction', 'lambda:InvokeFunction',
            'cloudformation:CreateStack', 'datapipeline:CreatePipeline',
            'glue:CreateDevEndpoint', 'iam:*', '*'
        ]
        found = []
        doc = self.policy_document
        for statement in doc.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                for action in actions:
                    if action in dangerous_actions or action == '*':
                        found.append(action)
        return list(set(found))


@dataclass
class IAMGroup:
    """IAM group details"""
    group_name: str
    group_id: str
    arn: str
    path: str = "/"
    create_date: str = ""
    attached_policies: List[str] = field(default_factory=list)
    inline_policies: List[str] = field(default_factory=list)
    users: List[str] = field(default_factory=list)


@dataclass
class AccessKeyInfo:
    """Access key details"""
    access_key_id: str
    user_name: str
    status: str
    create_date: str = ""
    last_used_date: str = ""
    last_used_service: str = ""
    last_used_region: str = ""
    
    @property
    def is_active(self) -> bool:
        return self.status == 'Active'
    
    @property
    def is_old(self) -> bool:
        if not self.create_date:
            return False
        try:
            created = datetime.fromisoformat(self.create_date.replace('Z', '+00:00'))
            age_days = (datetime.now(created.tzinfo) - created).days
            return age_days > 90
        except Exception:
            return False


@dataclass
class IAMFinding:
    """Security finding for IAM"""
    finding_type: str
    severity: IAMRiskLevel
    resource_id: str
    resource_type: str
    title: str
    description: str
    recommendation: str = ""
    privesc_methods: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


# MITRE ATT&CK Techniques
MITRE_IAM_TECHNIQUES = {
    'valid_accounts': 'T1078',
    'account_discovery': 'T1087',
    'permission_groups_discovery': 'T1069',
    'cloud_account': 'T1078.004',
    'additional_cloud_credentials': 'T1098.001',
    'additional_cloud_roles': 'T1098.003',
    'create_account': 'T1136.003',
    'forge_web_credentials': 'T1606',
    'steal_application_access_token': 'T1528',
}


__all__ = [
    'IAMRiskLevel',
    'PrivilegeEscalationType',
    'IAMUser',
    'IAMRole',
    'IAMPolicy',
    'IAMGroup',
    'AccessKeyInfo',
    'IAMFinding',
    'MITRE_IAM_TECHNIQUES'
]
