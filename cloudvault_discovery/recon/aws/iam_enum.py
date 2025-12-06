"""
AWS IAM Enumerator
Comprehensive IAM user, role, policy, and group enumeration
"""

import logging
from typing import List, Dict, Any, Optional

from .iam_models import (
    IAMUser, IAMRole, IAMPolicy, IAMGroup, AccessKeyInfo,
    IAMFinding, IAMRiskLevel, MITRE_IAM_TECHNIQUES
)
from .iam_privesc import (
    analyze_user_privesc, analyze_role_privesc, detect_shadow_admins
)

logger = logging.getLogger(__name__)


class IAMEnumerator:
    """
    AWS IAM Enumerator
    
    Provides comprehensive IAM enumeration including:
    - User/Role/Group/Policy discovery
    - Access key analysis
    - Privilege escalation detection
    - Shadow admin identification
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
        self._iam_client = None
        self._sts_client = None
    
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
            logger.error("boto3 not installed")
            raise
    
    def _get_iam_client(self):
        """Get IAM client"""
        if not self._iam_client:
            if not self._session:
                self._session = self._get_boto3_session()
            self._iam_client = self._session.client('iam')
        return self._iam_client
    
    def _get_sts_client(self):
        """Get STS client"""
        if not self._sts_client:
            if not self._session:
                self._session = self._get_boto3_session()
            self._sts_client = self._session.client('sts')
        return self._sts_client
    
    def get_caller_identity(self) -> Dict[str, str]:
        """Get current caller identity"""
        try:
            sts = self._get_sts_client()
            return sts.get_caller_identity()
        except Exception as e:
            logger.error(f"Failed to get caller identity: {e}")
            return {}
    
    def enumerate_users(self, limit: Optional[int] = None) -> List[IAMUser]:
        """Enumerate all IAM users"""
        users = []
        
        try:
            iam = self._get_iam_client()
            paginator = iam.get_paginator('list_users')
            
            count = 0
            for page in paginator.paginate():
                for user_data in page.get('Users', []):
                    if limit and count >= limit:
                        break
                    
                    user = self._get_user_details(user_data)
                    users.append(user)
                    count += 1
                
                if limit and count >= limit:
                    break
                    
        except Exception as e:
            logger.error(f"Error enumerating users: {e}")
        
        return users
    
    def _get_user_details(self, user_data: Dict) -> IAMUser:
        """Get detailed user information"""
        iam = self._get_iam_client()
        user_name = user_data['UserName']
        
        # Get groups
        groups = []
        try:
            group_response = iam.list_groups_for_user(UserName=user_name)
            groups = [g['GroupName'] for g in group_response.get('Groups', [])]
        except Exception:
            pass
        
        # Get attached policies
        attached_policies = []
        try:
            policy_response = iam.list_attached_user_policies(UserName=user_name)
            attached_policies = [p['PolicyArn'] for p in policy_response.get('AttachedPolicies', [])]
        except Exception:
            pass
        
        # Get inline policies
        inline_policies = []
        try:
            inline_response = iam.list_user_policies(UserName=user_name)
            inline_policies = inline_response.get('PolicyNames', [])
        except Exception:
            pass
        
        # Get access keys
        access_keys = []
        try:
            keys_response = iam.list_access_keys(UserName=user_name)
            for key in keys_response.get('AccessKeyMetadata', []):
                key_info = {
                    'access_key_id': key['AccessKeyId'],
                    'status': key['Status'],
                    'create_date': str(key.get('CreateDate', ''))
                }
                # Get last used info
                try:
                    last_used = iam.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                    key_info['last_used'] = str(last_used.get('AccessKeyLastUsed', {}).get('LastUsedDate', ''))
                except Exception:
                    pass
                access_keys.append(key_info)
        except Exception:
            pass
        
        # Get MFA devices
        mfa_devices = []
        try:
            mfa_response = iam.list_mfa_devices(UserName=user_name)
            mfa_devices = [m['SerialNumber'] for m in mfa_response.get('MFADevices', [])]
        except Exception:
            pass
        
        # Get tags
        tags = {}
        try:
            tags_response = iam.list_user_tags(UserName=user_name)
            tags = {t['Key']: t['Value'] for t in tags_response.get('Tags', [])}
        except Exception:
            pass
        
        return IAMUser(
            user_name=user_name,
            user_id=user_data['UserId'],
            arn=user_data['Arn'],
            create_date=str(user_data.get('CreateDate', '')),
            password_last_used=str(user_data.get('PasswordLastUsed', '')),
            path=user_data.get('Path', '/'),
            groups=groups,
            attached_policies=attached_policies,
            inline_policies=inline_policies,
            access_keys=access_keys,
            mfa_devices=mfa_devices,
            tags=tags
        )
    
    def enumerate_roles(self, limit: Optional[int] = None) -> List[IAMRole]:
        """Enumerate all IAM roles"""
        roles = []
        
        try:
            iam = self._get_iam_client()
            paginator = iam.get_paginator('list_roles')
            
            count = 0
            for page in paginator.paginate():
                for role_data in page.get('Roles', []):
                    if limit and count >= limit:
                        break
                    
                    role = self._get_role_details(role_data)
                    roles.append(role)
                    count += 1
                
                if limit and count >= limit:
                    break
                    
        except Exception as e:
            logger.error(f"Error enumerating roles: {e}")
        
        return roles
    
    def _get_role_details(self, role_data: Dict) -> IAMRole:
        """Get detailed role information"""
        iam = self._get_iam_client()
        role_name = role_data['RoleName']
        
        # Get attached policies
        attached_policies = []
        try:
            policy_response = iam.list_attached_role_policies(RoleName=role_name)
            attached_policies = [p['PolicyArn'] for p in policy_response.get('AttachedPolicies', [])]
        except Exception:
            pass
        
        # Get inline policies
        inline_policies = []
        try:
            inline_response = iam.list_role_policies(RoleName=role_name)
            inline_policies = inline_response.get('PolicyNames', [])
        except Exception:
            pass
        
        # Get instance profiles
        instance_profiles = []
        try:
            profile_response = iam.list_instance_profiles_for_role(RoleName=role_name)
            instance_profiles = [p['InstanceProfileName'] for p in profile_response.get('InstanceProfiles', [])]
        except Exception:
            pass
        
        # Get tags
        tags = {}
        try:
            tags_response = iam.list_role_tags(RoleName=role_name)
            tags = {t['Key']: t['Value'] for t in tags_response.get('Tags', [])}
        except Exception:
            pass
        
        return IAMRole(
            role_name=role_name,
            role_id=role_data['RoleId'],
            arn=role_data['Arn'],
            create_date=str(role_data.get('CreateDate', '')),
            path=role_data.get('Path', '/'),
            description=role_data.get('Description', ''),
            max_session_duration=role_data.get('MaxSessionDuration', 3600),
            assume_role_policy=role_data.get('AssumeRolePolicyDocument', {}),
            attached_policies=attached_policies,
            inline_policies=inline_policies,
            instance_profiles=instance_profiles,
            tags=tags
        )
    
    def enumerate_policies(self, 
                          scope: str = 'Local',
                          only_attached: bool = False) -> List[IAMPolicy]:
        """Enumerate IAM policies"""
        policies = []
        
        try:
            iam = self._get_iam_client()
            paginator = iam.get_paginator('list_policies')
            
            for page in paginator.paginate(Scope=scope, OnlyAttached=only_attached):
                for policy_data in page.get('Policies', []):
                    policy = self._get_policy_details(policy_data)
                    if policy:
                        policies.append(policy)
                    
        except Exception as e:
            logger.error(f"Error enumerating policies: {e}")
        
        return policies
    
    def _get_policy_details(self, policy_data: Dict) -> Optional[IAMPolicy]:
        """Get detailed policy information"""
        iam = self._get_iam_client()
        
        try:
            # Get policy document
            version_response = iam.get_policy_version(
                PolicyArn=policy_data['Arn'],
                VersionId=policy_data.get('DefaultVersionId', 'v1')
            )
            policy_document = version_response.get('PolicyVersion', {}).get('Document', {})
            
            return IAMPolicy(
                policy_name=policy_data['PolicyName'],
                policy_id=policy_data['PolicyId'],
                arn=policy_data['Arn'],
                path=policy_data.get('Path', '/'),
                default_version_id=policy_data.get('DefaultVersionId', 'v1'),
                attachment_count=policy_data.get('AttachmentCount', 0),
                is_attachable=policy_data.get('IsAttachable', True),
                create_date=str(policy_data.get('CreateDate', '')),
                update_date=str(policy_data.get('UpdateDate', '')),
                description=policy_data.get('Description', ''),
                policy_document=policy_document
            )
        except Exception as e:
            logger.debug(f"Error getting policy details: {e}")
            return None
    
    def enumerate_groups(self) -> List[IAMGroup]:
        """Enumerate IAM groups"""
        groups = []
        
        try:
            iam = self._get_iam_client()
            paginator = iam.get_paginator('list_groups')
            
            for page in paginator.paginate():
                for group_data in page.get('Groups', []):
                    group = self._get_group_details(group_data)
                    groups.append(group)
                    
        except Exception as e:
            logger.error(f"Error enumerating groups: {e}")
        
        return groups
    
    def _get_group_details(self, group_data: Dict) -> IAMGroup:
        """Get detailed group information"""
        iam = self._get_iam_client()
        group_name = group_data['GroupName']
        
        # Get attached policies
        attached_policies = []
        try:
            policy_response = iam.list_attached_group_policies(GroupName=group_name)
            attached_policies = [p['PolicyArn'] for p in policy_response.get('AttachedPolicies', [])]
        except Exception:
            pass
        
        # Get inline policies
        inline_policies = []
        try:
            inline_response = iam.list_group_policies(GroupName=group_name)
            inline_policies = inline_response.get('PolicyNames', [])
        except Exception:
            pass
        
        # Get users
        users = []
        try:
            users_response = iam.get_group(GroupName=group_name)
            users = [u['UserName'] for u in users_response.get('Users', [])]
        except Exception:
            pass
        
        return IAMGroup(
            group_name=group_name,
            group_id=group_data['GroupId'],
            arn=group_data['Arn'],
            path=group_data.get('Path', '/'),
            create_date=str(group_data.get('CreateDate', '')),
            attached_policies=attached_policies,
            inline_policies=inline_policies,
            users=users
        )
    
    def enumerate_all(self, 
                     user_limit: Optional[int] = None,
                     role_limit: Optional[int] = None) -> Dict[str, Any]:
        """
        Enumerate all IAM resources and analyze security.
        
        Returns comprehensive IAM enumeration results with findings.
        """
        results = {
            'identity': {},
            'users': [],
            'roles': [],
            'policies': [],
            'groups': [],
            'findings': [],
            'summary': {
                'total_users': 0,
                'total_roles': 0,
                'total_policies': 0,
                'total_groups': 0,
                'admins': 0,
                'users_without_mfa': 0,
                'old_access_keys': 0,
                'privilege_escalation_paths': 0,
                'shadow_admins': 0
            }
        }
        
        # Get identity
        results['identity'] = self.get_caller_identity()
        
        # Enumerate users
        logger.info("Enumerating IAM users...")
        users = self.enumerate_users(limit=user_limit)
        results['users'] = users
        results['summary']['total_users'] = len(users)
        
        # Enumerate roles
        logger.info("Enumerating IAM roles...")
        roles = self.enumerate_roles(limit=role_limit)
        results['roles'] = roles
        results['summary']['total_roles'] = len(roles)
        
        # Enumerate policies
        logger.info("Enumerating IAM policies...")
        policies = self.enumerate_policies(only_attached=True)
        results['policies'] = policies
        results['summary']['total_policies'] = len(policies)
        
        # Enumerate groups
        logger.info("Enumerating IAM groups...")
        groups = self.enumerate_groups()
        results['groups'] = groups
        results['summary']['total_groups'] = len(groups)
        
        # Build policy lookup
        policy_lookup = {p.arn: p for p in policies}
        
        # Analyze users
        all_findings = []
        for user in users:
            # Check for admins
            if user.is_admin:
                results['summary']['admins'] += 1
            
            # Check MFA
            if user.has_console_access and not user.has_mfa:
                results['summary']['users_without_mfa'] += 1
                all_findings.append(IAMFinding(
                    finding_type='NO_MFA',
                    severity=IAMRiskLevel.HIGH,
                    resource_id=user.arn,
                    resource_type='IAMUser',
                    title='Console User Without MFA',
                    description=f"User {user.user_name} has console access but no MFA enabled",
                    recommendation='Enable MFA for all console users',
                    mitre_techniques=[MITRE_IAM_TECHNIQUES['valid_accounts']]
                ))
            
            # Check access keys
            for key in user.access_keys:
                if key.get('status') == 'Active':
                    # Check age
                    create_date = key.get('create_date', '')
                    if create_date:
                        from datetime import datetime
                        try:
                            created = datetime.fromisoformat(create_date.replace('Z', '+00:00').split('+')[0])
                            age_days = (datetime.now() - created).days
                            if age_days > 90:
                                results['summary']['old_access_keys'] += 1
                                all_findings.append(IAMFinding(
                                    finding_type='OLD_ACCESS_KEY',
                                    severity=IAMRiskLevel.MEDIUM,
                                    resource_id=key.get('access_key_id', ''),
                                    resource_type='AccessKey',
                                    title='Old Access Key',
                                    description=f"Access key for {user.user_name} is {age_days} days old",
                                    recommendation='Rotate access keys every 90 days',
                                    metadata={'age_days': age_days, 'user': user.user_name}
                                ))
                        except Exception:
                            pass
            
            # Check privilege escalation
            user_findings = analyze_user_privesc(user, policy_lookup, roles)
            all_findings.extend(user_findings)
            results['summary']['privilege_escalation_paths'] += len(user_findings)
        
        # Detect shadow admins
        shadow_findings = detect_shadow_admins(users, policy_lookup)
        all_findings.extend(shadow_findings)
        results['summary']['shadow_admins'] = len(shadow_findings)
        
        # Analyze roles
        for role in roles:
            role_findings = analyze_role_privesc(role, policy_lookup)
            all_findings.extend(role_findings)
        
        results['findings'] = all_findings
        
        return results


__all__ = ['IAMEnumerator']
