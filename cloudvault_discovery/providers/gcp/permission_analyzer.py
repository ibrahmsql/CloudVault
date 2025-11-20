"""
GCP IAM and ACL Analysis Module
Analyzes bucket IAM policies and ACLs to determine access levels
"""
import logging
from typing import Tuple, Dict
from ...core.worker import AccessLevel

logger = logging.getLogger(__name__)


def analyze_iam_policy(iam_policy) -> Tuple[AccessLevel, Dict]:
    """
    Analyze IAM policy to determine access level and permissions
    
    Args:
        iam_policy: GCS IAM policy object
        
    Returns:
        Tuple of (AccessLevel, permission_analysis_dict)
    """
    analysis = {
        'public_read': False,
        'public_write': False,
        'authenticated_read': False,
        'authenticated_write': False,
        'bucket_policy_only': False,
        'risk_level': 'LOW',
        'bindings': []
    }
    
    # Check for uniform bucket-level access
    if hasattr(iam_policy, 'uniform_bucket_level_access_enabled'):
        analysis['bucket_policy_only'] = iam_policy.uniform_bucket_level_access_enabled
    
    # Analyze bindings
    for binding in iam_policy.bindings:
        role = binding.get('role', '')
        members = binding.get('members', [])
        
        analysis['bindings'].append({
            'role': role,
            'member_count': len(members)
        })
        
        # Check for public access
        if 'allUsers' in members or 'allAuthenticatedUsers' in members:
            if 'viewer' in role.lower() or 'reader' in role.lower():
                if 'allUsers' in members:
                    analysis['public_read'] = True
                else:
                    analysis['authenticated_read'] = True
            
            if 'editor' in role.lower() or 'writer' in role.lower() or 'admin' in role.lower():
                if 'allUsers' in members:
                    analysis['public_write'] = True
                else:
                    analysis['authenticated_write'] = True
    
    # Determine access level
    access_level = _determine_access_level(analysis)
    
    # Calculate risk level
    analysis['risk_level'] = _calculate_risk_level(analysis)
    
    return access_level, analysis


def analyze_bucket_iam(bucket) -> Tuple[AccessLevel, Dict]:
    """
    Analyze bucket IAM policy (wrapper for analyze_iam_policy)
    
    Args:
        bucket: GCS bucket object
        
    Returns:
        Tuple of (AccessLevel, permission_analysis_dict)
    """
    try:
        iam_policy = bucket.get_iam_policy()
        return analyze_iam_policy(iam_policy)
    except Exception as e:
        logger.debug(f"Error analyzing bucket IAM: {e}")
        return AccessLevel.PRIVATE, {'error': str(e)}


def _determine_access_level(analysis: Dict) -> AccessLevel:
    """Determine AccessLevel from analysis"""
    if analysis['public_write']:
        if analysis['public_read']:
            return AccessLevel.PUBLIC_READ_WRITE
        return AccessLevel.PUBLIC_WRITE
    
    if analysis['public_read']:
        return AccessLevel.PUBLIC_READ
    
    if analysis['authenticated_write'] or analysis['authenticated_read']:
        return AccessLevel.AUTHENTICATED_READ
    
    return AccessLevel.PRIVATE


def _calculate_risk_level(analysis: Dict) -> str:
    """Calculate risk level based on permissions"""
    if analysis['public_write']:
        return 'CRITICAL'
    
    if analysis['public_read'] or analysis['authenticated_write']:
        return 'HIGH'
    
    if analysis['authenticated_read']:
        return 'MEDIUM'
    
    return 'LOW'


def get_bucket_acl_info(bucket) -> Dict:
    """
    Get bucket ACL information
    
    Args:
        bucket: GCS bucket object
        
    Returns:
        Dictionary with ACL information
    """
    acl_info = {
        'owner': '(unknown)',
        'owner_type': '',
        'acl_entries': [],
        'default_object_acl': []
    }
    
    try:
        # Get bucket ACL
        acl = bucket.acl
        acl.reload()
        
        # Get owner
        if hasattr(acl, 'owner'):
            owner = acl.owner
            if owner:
                if hasattr(owner, 'email'):
                    acl_info['owner'] = owner.email
                    acl_info['owner_type'] = 'user'
                elif hasattr(owner, 'entity_id'):
                    acl_info['owner'] = owner.entity_id
                    acl_info['owner_type'] = 'group'
        
        # Get ACL entries
        for entry in acl:
            acl_info['acl_entries'].append({
                'entity': str(entry.entity),
                'role': entry.role,
                'entity_type': entry.entity_type if hasattr(entry, 'entity_type') else 'unknown'
            })
        
        # Get default object ACL
        try:
            default_acl = bucket.default_object_acl
            default_acl.reload()
            
            for entry in default_acl:
                acl_info['default_object_acl'].append({
                    'entity': str(entry.entity),
                    'role': entry.role
                })
        except Exception as e:
            logger.debug(f"Error getting default object ACL: {e}")
    
    except Exception as e:
        logger.debug(f"Error getting ACL info for {bucket.name}: {e}")
        acl_info['owner'] = '(error)'
    
    return acl_info


def format_iam_bindings(bindings: list) -> str:
    """
    Format IAM bindings for display
    
    Args:
        bindings: List of IAM bindings
        
    Returns:
        Formatted string
    """
    formatted = []
    
    for binding in bindings[:5]:  # Limit to 5
        role = binding.get('role', 'Unknown')
        member_count = binding.get('member_count', 0)
        formatted.append(f"  - {role}: {member_count} members")
    
    if len(bindings) > 5:
        formatted.append(f"  ... and {len(bindings) - 5} more bindings")
    
    return '\n'.join(formatted)
