"""
AWS S3 ACL Analysis Module
Analyzes bucket ACLs and determines access levels and permissions
"""
import logging
from typing import Dict
from ...core.worker import AccessLevel

logger = logging.getLogger(__name__)


def determine_access_level_from_acl(acl: dict) -> AccessLevel:
    """
    Determine bucket access level from ACL grants
    
    Args:
        acl: ACL dictionary from boto3
        
    Returns:
        AccessLevel enum value
    """
    grants = acl.get('Grants', [])
    public_read = False
    public_write = False
    authenticated_read = False
    authenticated_write = False
    
    for grant in grants:
        grantee = grant.get('Grantee', {})
        permission = grant.get('Permission', '')
        
        if grantee.get('Type') == 'Group':
            uri = grantee.get('URI', '')
            
            # Check for AllUsers (public access)
            if 'AllUsers' in uri:
                if permission == 'READ':
                    public_read = True
                elif permission == 'WRITE':
                    public_write = True
                elif permission == 'FULL_CONTROL':
                    public_read = public_write = True
            
            # Check for AuthenticatedUsers
            elif 'AuthenticatedUsers' in uri:
                if permission == 'READ':
                    authenticated_read = True
                elif permission == 'WRITE':
                    authenticated_write = True
                elif permission == 'FULL_CONTROL':
                    authenticated_read = authenticated_write = True
    
    # Determine final access level
    if public_write and public_read:
        return AccessLevel.PUBLIC_READ_WRITE
    elif public_write:
        return AccessLevel.PUBLIC_WRITE
    elif public_read:
        return AccessLevel.PUBLIC_READ
    elif authenticated_write and authenticated_read:
        return AccessLevel.AUTHENTICATED_READ
    elif authenticated_read:
        return AccessLevel.AUTHENTICATED_READ
    else:
        return AccessLevel.PRIVATE


def format_acl_info(acl_info: dict) -> Dict[str, any]:
    """
    Format ACL information for display
    
    Args:
        acl_info: ACL dictionary
        
    Returns:
        Formatted ACL information dictionary
    """
    if not acl_info:
        return {'summary': "No ACL information available"}
    
    formatted = {
        'owner': None,
        'grants': [],
        'total_grants': 0
    }
    
    # Extract owner
    owner_info = acl_info.get('Owner', {})
    if owner_info:
        display_name = owner_info.get('DisplayName', '')
        owner_id = owner_info.get('ID', '')
        if display_name:
            formatted['owner'] = display_name
        elif owner_id:
            formatted['owner'] = f"AWS-{owner_id[:12]}"
    
    # Extract grants
    grants = acl_info.get('Grants', [])
    formatted['total_grants'] = len(grants)
    
    for grant in grants[:5]:  # Limit to first 5
        grantee = grant.get('Grantee', {})
        permission = grant.get('Permission', 'Unknown')
        
        if grantee.get('Type') == 'Group':
            grantee_name = grantee.get('URI', '').split('/')[-1] or 'Unknown Group'
        elif grantee.get('Type') == 'CanonicalUser':
            grantee_name = grantee.get('DisplayName') or grantee.get('ID', 'Unknown User')[:20]
        else:
            grantee_name = str(grantee.get('DisplayName') or grantee.get('ID', 'Unknown'))[:20]
        
        formatted['grants'].append({
            'grantee': grantee_name,
            'permission': permission,
            'type': grantee.get('Type', 'Unknown')
        })
    
    return formatted


def enhance_permission_analysis(acl_info: dict, bucket_name: str = None) -> Dict[str, any]:
    """
    Enhanced permission analysis with detailed breakdown
    
    Args:
        acl_info: ACL dictionary
        bucket_name: Optional bucket name for context
        
    Returns:
        Detailed permission analysis dictionary
    """
    analysis = {
        'public_read': False,
        'public_write': False,
        'public_read_acp': False,
        'public_write_acp': False,
        'authenticated_read': False,
        'authenticated_write': False,
        'authenticated_read_acp': False,
        'authenticated_write_acp': False,
        'owner_permissions': [],
        'risk_level': 'LOW',
        'public_access_methods': [],
        'authenticated_access_methods': []
    }
    
    owner_id = acl_info.get('Owner', {}).get('ID', '')
    
    for grant in acl_info.get('Grants', []):
        grantee = grant.get('Grantee', {})
        permission = grant.get('Permission', '')
        
        if grantee.get('Type') == 'Group':
            uri = grantee.get('URI', '')
            
            # AllUsers (public) permissions
            if 'AllUsers' in uri:
                if permission == 'READ':
                    analysis['public_read'] = True
                    analysis['public_access_methods'].append('READ')
                elif permission == 'WRITE':
                    analysis['public_write'] = True
                    analysis['public_access_methods'].append('WRITE')
                elif permission == 'READ_ACP':
                    analysis['public_read_acp'] = True
                    analysis['public_access_methods'].append('READ_ACP')
                elif permission == 'WRITE_ACP':
                    analysis['public_write_acp'] = True
                    analysis['public_access_methods'].append('WRITE_ACP')
                elif permission == 'FULL_CONTROL':
                    analysis['public_read'] = True
                    analysis['public_write'] = True
                    analysis['public_read_acp'] = True
                    analysis['public_write_acp'] = True
                    analysis['public_access_methods'].append('FULL_CONTROL')
            
            # AuthenticatedUsers permissions
            elif 'AuthenticatedUsers' in uri:
                if permission == 'READ':
                    analysis['authenticated_read'] = True
                    analysis['authenticated_access_methods'].append('READ')
                elif permission == 'WRITE':
                    analysis['authenticated_write'] = True
                    analysis['authenticated_access_methods'].append('WRITE')
                elif permission == 'READ_ACP':
                    analysis['authenticated_read_acp'] = True
                    analysis['authenticated_access_methods'].append('READ_ACP')
                elif permission == 'WRITE_ACP':
                    analysis['authenticated_write_acp'] = True
                    analysis['authenticated_access_methods'].append('WRITE_ACP')
                elif permission == 'FULL_CONTROL':
                    analysis['authenticated_read'] = True
                    analysis['authenticated_write'] = True
                    analysis['authenticated_read_acp'] = True
                    analysis['authenticated_write_acp'] = True
                    analysis['authenticated_access_methods'].append('FULL_CONTROL')
        
        # Track owner permissions
        elif grantee.get('Type') == 'CanonicalUser':
            if grantee.get('ID') == owner_id:
                analysis['owner_permissions'].append(permission)
    
    # Calculate risk level
    if analysis['public_write'] or analysis['public_write_acp']:
        analysis['risk_level'] = 'CRITICAL'
    elif analysis['public_read'] or analysis['authenticated_write']:
        analysis['risk_level'] = 'HIGH'
    elif analysis['authenticated_read'] or analysis['public_read_acp']:
        analysis['risk_level'] = 'MEDIUM'
    else:
        analysis['risk_level'] = 'LOW'
    
    return analysis
