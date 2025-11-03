"""
Azure Container Analysis Module
Analyzes container permissions and properties
"""
import logging
from typing import Tuple, Dict
from ...core.worker import AccessLevel

logger = logging.getLogger(__name__)


def analyze_container_permissions(container_client) -> Tuple[AccessLevel, Dict]:
    """
    Analyze container permissions
    
    Args:
        container_client: Azure ContainerClient object
        
    Returns:
        Tuple of (AccessLevel, permission_analysis_dict)
    """
    analysis = {
        'public_read': False,
        'public_write': False,
        'container_access': False,
        'blob_access': False,
        'risk_level': 'LOW',
        'public_access_type': None
    }
    
    try:
        # Get container properties
        properties = container_client.get_container_properties()
        
        # Check public access level
        if hasattr(properties, 'public_access'):
            public_access = properties.public_access
            analysis['public_access_type'] = str(public_access) if public_access else 'None'
            
            if public_access:
                if 'container' in str(public_access).lower():
                    analysis['public_read'] = True
                    analysis['container_access'] = True
                elif 'blob' in str(public_access).lower():
                    analysis['public_read'] = True
                    analysis['blob_access'] = True
    
    except Exception as e:
        logger.debug(f"Error analyzing container permissions: {e}")
    
    # Determine access level
    access_level = _determine_access_level(analysis)
    
    # Calculate risk level
    analysis['risk_level'] = _calculate_risk_level(analysis)
    
    return access_level, analysis


def _determine_access_level(analysis: Dict) -> AccessLevel:
    """Determine AccessLevel from analysis"""
    if analysis['public_write']:
        return AccessLevel.PUBLIC_READ_WRITE
    
    if analysis['public_read']:
        return AccessLevel.PUBLIC_READ
    
    return AccessLevel.PRIVATE


def _calculate_risk_level(analysis: Dict) -> str:
    """Calculate risk level based on permissions"""
    if analysis['public_write']:
        return 'CRITICAL'
    
    if analysis['container_access']:
        return 'HIGH'
    
    if analysis['blob_access']:
        return 'MEDIUM'
    
    return 'LOW'


def get_container_metadata(container_client) -> Dict:
    """
    Get container metadata and properties
    
    Args:
        container_client: Azure ContainerClient object
        
    Returns:
        Dictionary with metadata
    """
    metadata = {
        'account_name': None,
        'container_name': None,
        'last_modified': None,
        'etag': None,
        'lease_status': None,
        'lease_state': None,
        'has_immutability_policy': False,
        'has_legal_hold': False
    }
    
    try:
        properties = container_client.get_container_properties()
        
        # Extract basic info
        if hasattr(container_client, 'account_name'):
            metadata['account_name'] = container_client.account_name
        
        if hasattr(container_client, 'container_name'):
            metadata['container_name'] = container_client.container_name
        
        # Extract properties
        if hasattr(properties, 'last_modified'):
            metadata['last_modified'] = str(properties.last_modified)
        
        if hasattr(properties, 'etag'):
            metadata['etag'] = properties.etag
        
        if hasattr(properties, 'lease'):
            lease = properties.lease
            if hasattr(lease, 'status'):
                metadata['lease_status'] = lease.status
            if hasattr(lease, 'state'):
                metadata['lease_state'] = lease.state
        
        if hasattr(properties, 'has_immutability_policy'):
            metadata['has_immutability_policy'] = properties.has_immutability_policy
        
        if hasattr(properties, 'has_legal_hold'):
            metadata['has_legal_hold'] = properties.has_legal_hold
    
    except Exception as e:
        logger.debug(f"Error getting container metadata: {e}")
    
    return metadata
