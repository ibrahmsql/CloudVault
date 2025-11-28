"""
Attack Pattern Definitions
Cloud security attack patterns with MITRE ATT&CK mapping
"""

from dataclasses import dataclass
from typing import List
from ..models import Severity


@dataclass
class AttackPattern:
    """Security attack pattern definition"""
    id: str
    name: str
    description: str
    severity: Severity
    mitre_techniques: List[str]
    mitre_tactics: List[str]
    detection_rules: List[str]
    remediation: str
    references: List[str]


# Define attack patterns
ATTACK_PATTERNS = [
    AttackPattern(
        id="AP001",
        name="Public S3 Bucket with Sensitive Data",
        description="S3 bucket is publicly readable and contains sensitive files",
        severity=Severity.CRITICAL,
        mitre_techniques=["T1530"],
        mitre_tactics=["Collection"],
        detection_rules=["is_public == True", "len(sensitive_data) > 0"],
        remediation="Remove public access and enable bucket encryption",
        references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-policy-language-overview.html"]
    ),
    AttackPattern(
        id="AP002",
        name="Bucket with Write Permissions",
        description="Storage bucket allows public or unauthenticated write access",
        severity=Severity.CRITICAL,
        mitre_techniques=["T1485", "T1565"],
        mitre_tactics=["Impact", "Collection"],
        detection_rules=["'WRITE' in permissions", "is_public == True"],
        remediation="Remove write permissions for public users",
        references=[]
    ),
    AttackPattern(
        id="AP003",
        name="Credentials in Bucket Objects",
        description="Bucket contains files with embedded credentials or API keys",
        severity=Severity.HIGH,
        mitre_techniques=["T1078", "T1552"],
        mitre_tactics=["Credential Access"],
        detection_rules=["any(f.endswith(('.env', '.credentials', '.key')) for f in interesting_files)"],
        remediation="Remove credential files and rotate exposed credentials",
        references=[]
    ),
    AttackPattern(
        id="AP004",
        name="Unencrypted Sensitive Data",
        description="Bucket contains sensitive data without server-side encryption",
        severity=Severity.HIGH,
        mitre_techniques=["T1530"],
        mitre_tactics=["Collection"],
        detection_rules=["encryption_enabled == False", "len(sensitive_data) > 0"],
        remediation="Enable server-side encryption (AES-256 or KMS)",
        references=[]
    ),
    AttackPattern(
        id="AP005",
        name="Cross-Account Access Misconfiguration",
        description="Bucket policy allows access from untrusted AWS accounts",
        severity=Severity.HIGH,
        mitre_techniques=["T1098", "T1199"],
        mitre_tactics=["Persistence", "Lateral Movement"],
        detection_rules=["'Principal' in metadata", "'AWS' in metadata.get('Principal', {})"],
        remediation="Review and restrict cross-account access policies",
        references=[]
    ),
    AttackPattern(
        id="AP006",
        name="Backup Files Exposure",
        description="Bucket contains exposed backup or archive files",
        severity=Severity.MEDIUM,
        mitre_techniques=["T1005"],
        mitre_tactics=["Collection"],
        detection_rules=["any(f.endswith(('.zip', '.tar', '.sql', '.bak')) for f in interesting_files)"],
        remediation="Move backups to private, encrypted storage",
        references=[]
    ),
    AttackPattern(
        id="AP007",
        name="Source Code Exposure",
        description="Bucket contains source code or configuration files",
        severity=Severity.MEDIUM,
        mitre_techniques=["T1213"],
        mitre_tactics=["Collection"],
        detection_rules=["any(f.endswith(('.git', '.svn', '.config')) for f in interesting_files)"],
        remediation="Remove source code from public buckets",
        references=[]
    ),
    AttackPattern(
        id="AP008",
        name="Database Dump Exposure",
        description="Bucket contains database dumps or SQL files",
        severity=Severity.HIGH,
        mitre_techniques=["T1530"],
        mitre_tactics=["Collection"],
        detection_rules=["any('.sql' in f or '.db' in f for f in interesting_files)"],
        remediation="Remove database dumps and enable access logging",
        references=[]
    ),
    AttackPattern(
        id="AP009",
        name="Log Files with Sensitive Data",
        description="Publicly accessible log files containing sensitive information",
        severity=Severity.MEDIUM,
        mitre_techniques=["T1552.001"],
        mitre_tactics=["Credential Access"],
        detection_rules=["any(f.endswith('.log') for f in interesting_files)"],
        remediation="Configure log redaction and restrict access",
        references=[]
    ),
    AttackPattern(
        id="AP010",
        name="PII Data Exposure",
        description="Bucket contains personally identifiable information (PII)",
        severity=Severity.HIGH,
        mitre_techniques=["T1530"],
        mitre_tactics=["Collection"],
        detection_rules=["'pii' in metadata or 'personal' in metadata"],
        remediation="Enable encryption, implement DLP, and restrict access",
        references=[]
    ),
]


def get_attack_patterns() -> List[AttackPattern]:
    """Get all defined attack patterns"""
    return ATTACK_PATTERNS


def match_patterns(finding: dict) -> List[AttackPattern]:
    """
    Match a finding against attack patterns.
    
    Args:
        finding: Finding dictionary
        
    Returns:
        List of matched attack patterns
    """
    matched = []
    
    for pattern in ATTACK_PATTERNS:
        # Simple rule evaluation
        if _evaluate_rules(pattern.detection_rules, finding):
            matched.append(pattern)
    
    return matched


def _evaluate_rules(rules: List[str], finding: dict) -> bool:
    """Evaluate detection rules against finding"""
    for rule in rules:
        try:
            # This is simplified - in production, use a proper rule engine
            if eval(rule, {"__builtins__": {}}, finding):
                return True
        except:
            continue
    return False


__all__ = ['AttackPattern', 'get_attack_patterns', 'match_patterns']
