"""
Cloud Secrets Scanner
Cross-cloud secrets detection in metadata, environment variables, and user-data
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class SecretType(Enum):
    """Types of secrets detected"""
    AWS_ACCESS_KEY = "aws_access_key"
    AWS_SECRET_KEY = "aws_secret_key"
    AWS_SESSION_TOKEN = "aws_session_token"
    AZURE_CLIENT_SECRET = "azure_client_secret"
    AZURE_CONNECTION_STRING = "azure_connection_string"
    GCP_SERVICE_ACCOUNT = "gcp_service_account"
    GCP_API_KEY = "gcp_api_key"
    PRIVATE_KEY = "private_key"
    SSH_KEY = "ssh_key"
    DATABASE_URL = "database_url"
    GENERIC_PASSWORD = "generic_password"
    GENERIC_API_KEY = "generic_api_key"
    GENERIC_TOKEN = "generic_token"
    JWT_TOKEN = "jwt_token"
    GITHUB_TOKEN = "github_token"
    SLACK_TOKEN = "slack_token"
    STRIPE_KEY = "stripe_key"
    SENDGRID_KEY = "sendgrid_key"


class SecretSeverity(Enum):
    """Severity of secret exposure"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class SecretFinding:
    """Detected secret finding"""
    secret_type: SecretType
    severity: SecretSeverity
    source: str
    location: str
    key_name: str = ""
    masked_value: str = ""
    line_number: int = 0
    context: str = ""
    mitre_techniques: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


# Regex patterns for secret detection
SECRET_PATTERNS = {
    # AWS
    SecretType.AWS_ACCESS_KEY: {
        'pattern': r'(?:^|[^A-Za-z0-9])((AKIA|ASIA)[A-Z0-9]{16})(?:[^A-Za-z0-9]|$)',
        'severity': SecretSeverity.CRITICAL,
        'description': 'AWS Access Key ID'
    },
    SecretType.AWS_SECRET_KEY: {
        'pattern': r'(?:aws_secret_access_key|secret_key|aws_secret)["\'\s:=]+([A-Za-z0-9/+=]{40})',
        'severity': SecretSeverity.CRITICAL,
        'description': 'AWS Secret Access Key'
    },
    
    # Azure
    SecretType.AZURE_CONNECTION_STRING: {
        'pattern': r'DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+',
        'severity': SecretSeverity.CRITICAL,
        'description': 'Azure Storage Connection String'
    },
    SecretType.AZURE_CLIENT_SECRET: {
        'pattern': r'(?:client_secret|clientSecret)["\'\s:=]+([A-Za-z0-9~._-]{34,})',
        'severity': SecretSeverity.CRITICAL,
        'description': 'Azure Client Secret'
    },
    
    # GCP
    SecretType.GCP_SERVICE_ACCOUNT: {
        'pattern': r'"type"\s*:\s*"service_account"',
        'severity': SecretSeverity.CRITICAL,
        'description': 'GCP Service Account JSON'
    },
    SecretType.GCP_API_KEY: {
        'pattern': r'AIza[0-9A-Za-z_-]{35}',
        'severity': SecretSeverity.HIGH,
        'description': 'Google API Key'
    },
    
    # Generic
    SecretType.PRIVATE_KEY: {
        'pattern': r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
        'severity': SecretSeverity.CRITICAL,
        'description': 'Private Key'
    },
    SecretType.SSH_KEY: {
        'pattern': r'-----BEGIN OPENSSH PRIVATE KEY-----',
        'severity': SecretSeverity.CRITICAL,
        'description': 'SSH Private Key'
    },
    SecretType.DATABASE_URL: {
        'pattern': r'(?:mysql|postgres|postgresql|mongodb|redis|mongodb\+srv):\/\/[^\s"\']+:[^\s"\']+@[^\s"\']+',
        'severity': SecretSeverity.CRITICAL,
        'description': 'Database Connection URL'
    },
    SecretType.JWT_TOKEN: {
        'pattern': r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
        'severity': SecretSeverity.HIGH,
        'description': 'JWT Token'
    },
    SecretType.GITHUB_TOKEN: {
        'pattern': r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}',
        'severity': SecretSeverity.CRITICAL,
        'description': 'GitHub Token'
    },
    SecretType.SLACK_TOKEN: {
        'pattern': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}',
        'severity': SecretSeverity.HIGH,
        'description': 'Slack Token'
    },
    SecretType.STRIPE_KEY: {
        'pattern': r'(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}',
        'severity': SecretSeverity.CRITICAL,
        'description': 'Stripe API Key'
    },
    SecretType.SENDGRID_KEY: {
        'pattern': r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
        'severity': SecretSeverity.HIGH,
        'description': 'SendGrid API Key'
    },
    SecretType.GENERIC_PASSWORD: {
        'pattern': r'(?:password|passwd|pwd)["\'\s:=]+["\']?([^\s"\']{8,})["\']?',
        'severity': SecretSeverity.MEDIUM,
        'description': 'Generic Password'
    },
    SecretType.GENERIC_API_KEY: {
        'pattern': r'(?:api[_-]?key|apikey)["\'\s:=]+["\']?([A-Za-z0-9_-]{16,})["\']?',
        'severity': SecretSeverity.MEDIUM,
        'description': 'Generic API Key'
    },
    SecretType.GENERIC_TOKEN: {
        'pattern': r'(?:token|auth[_-]?token|bearer)["\'\s:=]+["\']?([A-Za-z0-9_.-]{20,})["\']?',
        'severity': SecretSeverity.MEDIUM,
        'description': 'Generic Token'
    },
}

# Environment variable names that often contain secrets
SENSITIVE_ENV_PATTERNS = [
    'password', 'passwd', 'pwd', 'secret', 'key', 'token', 'api_key',
    'apikey', 'auth', 'credential', 'private', 'access', 'connection',
    'conn_str', 'database_url', 'db_pass', 'mysql', 'postgres', 'redis'
]

MITRE_SECRETS_TECHNIQUES = {
    'credentials_in_files': 'T1552.001',
    'unsecured_credentials': 'T1552',
    'cloud_instance_metadata': 'T1552.005',
    'steal_application_access_token': 'T1528',
}


def mask_secret(value: str, reveal_chars: int = 4) -> str:
    """Mask a secret value for safe logging"""
    if len(value) <= reveal_chars * 2:
        return '*' * len(value)
    return value[:reveal_chars] + '*' * (len(value) - reveal_chars * 2) + value[-reveal_chars:]


def scan_text(text: str, source: str = "unknown") -> List[SecretFinding]:
    """
    Scan text for secrets using regex patterns.
    
    Args:
        text: Text content to scan
        source: Source identifier (filename, resource ID, etc.)
        
    Returns:
        List of SecretFinding objects
    """
    findings = []
    lines = text.split('\n')
    
    for secret_type, config in SECRET_PATTERNS.items():
        pattern = re.compile(config['pattern'], re.IGNORECASE | re.MULTILINE)
        
        for line_num, line in enumerate(lines, 1):
            matches = pattern.finditer(line)
            
            for match in matches:
                # Get the captured group or full match
                if match.groups():
                    secret_value = match.group(1) if len(match.groups()) >= 1 else match.group(0)
                else:
                    secret_value = match.group(0)
                
                findings.append(SecretFinding(
                    secret_type=secret_type,
                    severity=config['severity'],
                    source=source,
                    location=f"line {line_num}",
                    masked_value=mask_secret(secret_value),
                    line_number=line_num,
                    context=line[:100] if len(line) > 100 else line,
                    mitre_techniques=[
                        MITRE_SECRETS_TECHNIQUES['credentials_in_files'],
                        MITRE_SECRETS_TECHNIQUES['unsecured_credentials']
                    ]
                ))
    
    return findings


def scan_environment_variables(env_vars: Dict[str, str], 
                               source: str = "unknown") -> List[SecretFinding]:
    """
    Scan environment variables for secrets.
    
    Args:
        env_vars: Dictionary of environment variables
        source: Source identifier
        
    Returns:
        List of SecretFinding objects
    """
    findings = []
    
    for key, value in env_vars.items():
        key_lower = key.lower()
        
        # Check if key name suggests sensitive data
        is_sensitive_key = any(p in key_lower for p in SENSITIVE_ENV_PATTERNS)
        
        # Scan value for known patterns
        value_findings = scan_text(value, source=f"{source}:env:{key}")
        
        if value_findings:
            findings.extend(value_findings)
        elif is_sensitive_key and len(value) >= 8:
            # Key name suggests secret but no pattern matched
            findings.append(SecretFinding(
                secret_type=SecretType.GENERIC_PASSWORD,
                severity=SecretSeverity.MEDIUM,
                source=source,
                location=f"env:{key}",
                key_name=key,
                masked_value=mask_secret(value),
                mitre_techniques=[MITRE_SECRETS_TECHNIQUES['unsecured_credentials']],
                metadata={'env_var': key}
            ))
    
    return findings


def scan_user_data(user_data: str, source: str = "unknown") -> List[SecretFinding]:
    """
    Scan EC2 user-data for secrets.
    
    Args:
        user_data: User-data content (may be base64 encoded)
        source: Source identifier
        
    Returns:
        List of SecretFinding objects
    """
    import base64
    
    # Try to decode base64
    decoded = user_data
    try:
        decoded = base64.b64decode(user_data).decode('utf-8', errors='ignore')
    except Exception:
        pass
    
    findings = scan_text(decoded, source=f"{source}:user-data")
    
    # Add cloud metadata technique if found in user-data
    for finding in findings:
        if MITRE_SECRETS_TECHNIQUES['cloud_instance_metadata'] not in finding.mitre_techniques:
            finding.mitre_techniques.append(MITRE_SECRETS_TECHNIQUES['cloud_instance_metadata'])
    
    return findings


class SecretsScanner:
    """
    Cross-cloud secrets scanner.
    
    Scans various sources for exposed credentials:
    - EC2 user-data
    - Lambda environment variables
    - Container environment variables
    - Configuration files
    - Metadata responses
    """
    
    def __init__(self):
        self.findings = []
    
    def scan_ec2_user_data(self, 
                          instances: List[Any],
                          ec2_client: Any) -> List[SecretFinding]:
        """Scan EC2 user-data for secrets"""
        findings = []
        
        for instance in instances:
            instance_id = instance.get('InstanceId', instance.instance_id if hasattr(instance, 'instance_id') else 'unknown')
            
            try:
                # Get user-data
                response = ec2_client.describe_instance_attribute(
                    InstanceId=instance_id,
                    Attribute='userData'
                )
                user_data = response.get('UserData', {}).get('Value', '')
                
                if user_data:
                    instance_findings = scan_user_data(user_data, source=instance_id)
                    findings.extend(instance_findings)
            except Exception as e:
                logger.debug(f"Error getting user-data for {instance_id}: {e}")
        
        return findings
    
    def scan_lambda_env(self, functions: List[Any]) -> List[SecretFinding]:
        """Scan Lambda environment variables for secrets"""
        findings = []
        
        for func in functions:
            env_vars = {}
            if hasattr(func, 'environment'):
                env_vars = func.environment
            elif isinstance(func, dict):
                env_vars = func.get('Environment', {}).get('Variables', {})
            
            if env_vars:
                func_name = getattr(func, 'function_name', func.get('FunctionName', 'unknown'))
                func_findings = scan_environment_variables(env_vars, source=f"lambda:{func_name}")
                findings.extend(func_findings)
        
        return findings
    
    def scan_file(self, filepath: str) -> List[SecretFinding]:
        """Scan a file for secrets"""
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()
            return scan_text(content, source=filepath)
        except Exception as e:
            logger.error(f"Error scanning file {filepath}: {e}")
            return []
    
    def scan_all(self, 
                 text_sources: List[Tuple[str, str]] = None,
                 env_sources: List[Tuple[str, Dict[str, str]]] = None,
                 file_paths: List[str] = None) -> Dict[str, Any]:
        """
        Scan all provided sources for secrets.
        
        Args:
            text_sources: List of (source_name, text_content) tuples
            env_sources: List of (source_name, env_dict) tuples
            file_paths: List of file paths to scan
            
        Returns:
            Dictionary with findings and summary
        """
        all_findings = []
        
        if text_sources:
            for source, text in text_sources:
                findings = scan_text(text, source)
                all_findings.extend(findings)
        
        if env_sources:
            for source, env_vars in env_sources:
                findings = scan_environment_variables(env_vars, source)
                all_findings.extend(findings)
        
        if file_paths:
            for path in file_paths:
                findings = self.scan_file(path)
                all_findings.extend(findings)
        
        self.findings = all_findings
        
        # Build summary
        by_type = {}
        by_severity = {}
        
        for finding in all_findings:
            type_key = finding.secret_type.value
            sev_key = finding.severity.value
            
            by_type[type_key] = by_type.get(type_key, 0) + 1
            by_severity[sev_key] = by_severity.get(sev_key, 0) + 1
        
        return {
            'findings': all_findings,
            'summary': {
                'total': len(all_findings),
                'by_type': by_type,
                'by_severity': by_severity,
                'critical': by_severity.get('critical', 0),
                'high': by_severity.get('high', 0)
            }
        }


__all__ = [
    'SecretsScanner',
    'SecretFinding',
    'SecretType',
    'SecretSeverity',
    'scan_text',
    'scan_environment_variables',
    'scan_user_data',
    'SECRET_PATTERNS'
]
