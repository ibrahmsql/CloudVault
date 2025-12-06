"""
AWS IAM Privilege Escalation Analyzer
Detects privilege escalation paths in AWS IAM
"""

import logging
from typing import List, Dict, Any, Set, Tuple

from .iam_models import (
    IAMUser, IAMRole, IAMPolicy, IAMGroup,
    IAMFinding, IAMRiskLevel, MITRE_IAM_TECHNIQUES
)

logger = logging.getLogger(__name__)


# 21 Known IAM Privilege Escalation Methods
PRIVESC_METHODS = {
    'CreateNewPolicyVersion': {
        'permissions': ['iam:CreatePolicyVersion'],
        'description': 'Create a new policy version with admin privileges',
        'severity': IAMRiskLevel.CRITICAL
    },
    'SetExistingDefaultPolicyVersion': {
        'permissions': ['iam:SetDefaultPolicyVersion'],
        'description': 'Set an older, more permissive policy version as default',
        'severity': IAMRiskLevel.CRITICAL
    },
    'CreateAccessKey': {
        'permissions': ['iam:CreateAccessKey'],
        'description': 'Create access keys for another user',
        'severity': IAMRiskLevel.HIGH
    },
    'CreateLoginProfile': {
        'permissions': ['iam:CreateLoginProfile'],
        'description': 'Create console login for users without one',
        'severity': IAMRiskLevel.HIGH
    },
    'UpdateLoginProfile': {
        'permissions': ['iam:UpdateLoginProfile'],
        'description': 'Change password for other users',
        'severity': IAMRiskLevel.HIGH
    },
    'AttachUserPolicy': {
        'permissions': ['iam:AttachUserPolicy'],
        'description': 'Attach admin policy to own user',
        'severity': IAMRiskLevel.CRITICAL
    },
    'AttachGroupPolicy': {
        'permissions': ['iam:AttachGroupPolicy'],
        'description': 'Attach admin policy to owned group',
        'severity': IAMRiskLevel.CRITICAL
    },
    'AttachRolePolicy': {
        'permissions': ['iam:AttachRolePolicy'],
        'description': 'Attach admin policy to assumable role',
        'severity': IAMRiskLevel.CRITICAL
    },
    'PutUserPolicy': {
        'permissions': ['iam:PutUserPolicy'],
        'description': 'Add inline admin policy to own user',
        'severity': IAMRiskLevel.CRITICAL
    },
    'PutGroupPolicy': {
        'permissions': ['iam:PutGroupPolicy'],
        'description': 'Add inline admin policy to owned group',
        'severity': IAMRiskLevel.CRITICAL
    },
    'PutRolePolicy': {
        'permissions': ['iam:PutRolePolicy'],
        'description': 'Add inline admin policy to assumable role',
        'severity': IAMRiskLevel.CRITICAL
    },
    'AddUserToGroup': {
        'permissions': ['iam:AddUserToGroup'],
        'description': 'Add self to admin group',
        'severity': IAMRiskLevel.HIGH
    },
    'UpdateAssumeRolePolicy': {
        'permissions': ['iam:UpdateAssumeRolePolicy'],
        'description': 'Allow self to assume privileged role',
        'severity': IAMRiskLevel.CRITICAL
    },
    'PassRoleLambda': {
        'permissions': ['iam:PassRole', 'lambda:CreateFunction', 'lambda:InvokeFunction'],
        'description': 'Create Lambda with privileged role and invoke',
        'severity': IAMRiskLevel.CRITICAL
    },
    'PassRoleEC2': {
        'permissions': ['iam:PassRole', 'ec2:RunInstances'],
        'description': 'Launch EC2 with privileged instance profile',
        'severity': IAMRiskLevel.CRITICAL
    },
    'PassRoleCloudFormation': {
        'permissions': ['iam:PassRole', 'cloudformation:CreateStack'],
        'description': 'Create CloudFormation stack with privileged role',
        'severity': IAMRiskLevel.CRITICAL
    },
    'PassRoleDataPipeline': {
        'permissions': ['iam:PassRole', 'datapipeline:CreatePipeline'],
        'description': 'Create Data Pipeline with privileged role',
        'severity': IAMRiskLevel.CRITICAL
    },
    'PassRoleGlue': {
        'permissions': ['iam:PassRole', 'glue:CreateDevEndpoint'],
        'description': 'Create Glue endpoint with privileged role',
        'severity': IAMRiskLevel.CRITICAL
    },
    'PassRoleSageMaker': {
        'permissions': ['iam:PassRole', 'sagemaker:CreateNotebookInstance'],
        'description': 'Create SageMaker notebook with privileged role',
        'severity': IAMRiskLevel.CRITICAL
    },
    'AssumeRole': {
        'permissions': ['sts:AssumeRole'],
        'description': 'Assume more privileged role',
        'severity': IAMRiskLevel.HIGH
    },
    'LambdaCodeUpdate': {
        'permissions': ['lambda:UpdateFunctionCode'],
        'description': 'Update Lambda code to steal its role credentials',
        'severity': IAMRiskLevel.HIGH
    }
}


def analyze_user_privesc(user: IAMUser, 
                         policies: Dict[str, IAMPolicy],
                         roles: List[IAMRole]) -> List[IAMFinding]:
    """Analyze user for privilege escalation vectors"""
    findings = []
    user_permissions = _get_effective_permissions(user, policies)
    
    for method_name, method_info in PRIVESC_METHODS.items():
        required = set(method_info['permissions'])
        
        # Check if user has all required permissions
        if _has_permissions(user_permissions, required):
            findings.append(IAMFinding(
                finding_type='PRIVILEGE_ESCALATION',
                severity=method_info['severity'],
                resource_id=user.arn,
                resource_type='IAMUser',
                title=f'Privilege Escalation: {method_name}',
                description=f"User {user.user_name} can escalate privileges via {method_name}. "
                           f"{method_info['description']}",
                recommendation=f"Remove or restrict permissions: {', '.join(required)}",
                privesc_methods=[method_name],
                mitre_techniques=[
                    MITRE_IAM_TECHNIQUES['valid_accounts'],
                    MITRE_IAM_TECHNIQUES['additional_cloud_credentials']
                ],
                metadata={
                    'required_permissions': list(required),
                    'user_name': user.user_name
                }
            ))
    
    return findings


def analyze_role_privesc(role: IAMRole,
                         policies: Dict[str, IAMPolicy]) -> List[IAMFinding]:
    """Analyze role for privilege escalation vectors"""
    findings = []
    role_permissions = _get_role_permissions(role, policies)
    
    for method_name, method_info in PRIVESC_METHODS.items():
        required = set(method_info['permissions'])
        
        if _has_permissions(role_permissions, required):
            findings.append(IAMFinding(
                finding_type='ROLE_PRIVILEGE_ESCALATION',
                severity=method_info['severity'],
                resource_id=role.arn,
                resource_type='IAMRole',
                title=f'Role Privilege Escalation: {method_name}',
                description=f"Role {role.role_name} can escalate privileges via {method_name}. "
                           f"{method_info['description']}",
                recommendation=f"Remove or restrict permissions: {', '.join(required)}",
                privesc_methods=[method_name],
                mitre_techniques=[
                    MITRE_IAM_TECHNIQUES['valid_accounts'],
                    MITRE_IAM_TECHNIQUES['additional_cloud_roles']
                ],
                metadata={
                    'required_permissions': list(required),
                    'role_name': role.role_name
                }
            ))
    
    return findings


def detect_shadow_admins(users: List[IAMUser],
                         policies: Dict[str, IAMPolicy]) -> List[IAMFinding]:
    """
    Detect shadow admins - users with admin-equivalent permissions
    who aren't explicitly admins
    """
    findings = []
    
    admin_equivalent_combos = [
        {'iam:*'},
        {'iam:CreateUser', 'iam:CreateLoginProfile', 'iam:AttachUserPolicy'},
        {'iam:CreatePolicyVersion'},
        {'iam:SetDefaultPolicyVersion'},
        {'iam:AttachUserPolicy', 'iam:AttachGroupPolicy', 'iam:AttachRolePolicy'},
        {'iam:PutUserPolicy', 'iam:PutGroupPolicy', 'iam:PutRolePolicy'},
    ]
    
    for user in users:
        if user.is_admin:
            continue
        
        user_perms = _get_effective_permissions(user, policies)
        
        for combo in admin_equivalent_combos:
            if _has_permissions(user_perms, combo):
                findings.append(IAMFinding(
                    finding_type='SHADOW_ADMIN',
                    severity=IAMRiskLevel.CRITICAL,
                    resource_id=user.arn,
                    resource_type='IAMUser',
                    title=f'Shadow Admin Detected: {user.user_name}',
                    description=f"User {user.user_name} has admin-equivalent permissions "
                               f"without explicit admin policy: {combo}",
                    recommendation='Review and restrict IAM permissions or convert to explicit admin',
                    mitre_techniques=[
                        MITRE_IAM_TECHNIQUES['valid_accounts'],
                        MITRE_IAM_TECHNIQUES['cloud_account']
                    ],
                    metadata={
                        'admin_equivalent_permissions': list(combo),
                        'all_permissions': list(user_perms)[:20]
                    }
                ))
                break
    
    return findings


def _get_effective_permissions(user: IAMUser, 
                               policies: Dict[str, IAMPolicy]) -> Set[str]:
    """Get all effective permissions for a user"""
    permissions = set()
    
    # From attached policies
    for policy_arn in user.attached_policies:
        if policy_arn in policies:
            policy = policies[policy_arn]
            for statement in policy.policy_document.get('Statement', []):
                if statement.get('Effect') == 'Allow':
                    actions = statement.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]
                    permissions.update(actions)
    
    return permissions


def _get_role_permissions(role: IAMRole,
                          policies: Dict[str, IAMPolicy]) -> Set[str]:
    """Get all effective permissions for a role"""
    permissions = set()
    
    for policy_arn in role.attached_policies:
        if policy_arn in policies:
            policy = policies[policy_arn]
            for statement in policy.policy_document.get('Statement', []):
                if statement.get('Effect') == 'Allow':
                    actions = statement.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]
                    permissions.update(actions)
    
    return permissions


def _has_permissions(user_perms: Set[str], required: Set[str]) -> bool:
    """Check if user has all required permissions (with wildcard support)"""
    for req in required:
        has_perm = False
        
        if req in user_perms or '*' in user_perms:
            has_perm = True
        else:
            # Check wildcards like iam:*
            service = req.split(':')[0] if ':' in req else ''
            if f'{service}:*' in user_perms:
                has_perm = True
        
        if not has_perm:
            return False
    
    return True


__all__ = [
    'PRIVESC_METHODS',
    'analyze_user_privesc',
    'analyze_role_privesc',
    'detect_shadow_admins'
]
