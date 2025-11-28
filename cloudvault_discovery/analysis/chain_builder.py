"""
Attack Chain Builder
Constructs multi-hop attack paths from findings
"""

from typing import List, Dict, Any
from ..models.attack_chain import AttackChain, AttackStep
from ..models import Severity
from .attack_patterns import match_patterns
import hashlib


def build_attack_chains(findings: List[Dict[str, Any]]) -> List[AttackChain]:
    """
    Build attack chains from findings.
    
    Analyzes findings to construct multi-hop attack paths showing
    privilege escalation opportunities.
    
    Args:
        findings: List of finding dictionaries
        
    Returns:
        List of attack chains
    """
    chains = []
    
    # Group findings by provider and bucket
    by_provider = {}
    for finding in findings:
        provider = finding.get('provider', 'unknown')
        if provider not in by_provider:
            by_provider[provider] = []
        by_provider[provider].append(finding)
    
    # Build chains for each provider
    for provider, provider_findings in by_provider.items():
        # Single-step chains (individual findings)
        for finding in provider_findings:
            chain = _create_single_step_chain(finding)
            if chain:
                chains.append(chain)
        
        # Multi-hop chains (credential → data access)
        multi_hop = _create_multi_hop_chains(provider_findings)
        chains.extend(multi_hop)
    
    return chains


def _create_single_step_chain(finding: Dict[str, Any]) -> AttackChain:
    """Create attack chain from single finding"""
    # Match against attack patterns
    patterns = match_patterns(finding)
    
    if not patterns:
        return None
    
    # Use most severe pattern
    pattern = max(patterns, key=lambda p: p.severity.numeric_value)
    
    chain_id = hashlib.md5(
        f"{finding.get('bucket_name', '')}-{pattern.id}".encode()
    ).hexdigest()[:16]
    
    chain = AttackChain(
        id=chain_id,
        name=pattern.name,
        description=pattern.description,
        severity=pattern.severity,
        start_point=finding.get('bucket_url', ''),
        end_point="Data Exfiltration"
    )
    
    # Add single step
    chain.add_step(
        action="Access Exposed Bucket",
        description=f"Access {finding.get('bucket_name', 'bucket')} via public URL",
        mitre_technique=pattern.mitre_techniques[0] if pattern.mitre_techniques else "T1530",
        mitre_tactic=pattern.mitre_tactics[0] if pattern.mitre_tactics else "Collection"
    )
    
    # Calculate blast radius
    chain.blast_radius = _calculate_blast_radius(finding)
    chain.affected_resources.append(finding.get('bucket_name', 'unknown'))
    
    chain.generate_narrative()
    
    return chain


def _create_multi_hop_chains(findings: List[Dict[str, Any]]) -> List[AttackChain]:
    """Create multi-hop attack chains"""
    chains = []
    
    # Look for credential → access patterns
    credential_findings = [
        f for f in findings
        if any('.env' in file or 'credentials' in file or '.key' in file
             for file in f.get('interesting_files', []))
    ]
    
    data_findings = [
        f for f in findings
        if f.get('is_public', False) and len(f.get('sensitive_data', [])) > 0
    ]
    
    # Create credential → data access chains
    for cred_finding in credential_findings:
        for data_finding in data_findings:
            if cred_finding['bucket_name'] != data_finding['bucket_name']:
                chain = _create_credential_escalation_chain(cred_finding, data_finding)
                if chain:
                    chains.append(chain)
    
    return chains


def _create_credential_escalation_chain(
    cred_finding: Dict[str, Any],
    data_finding: Dict[str, Any]
) -> AttackChain:
    """Create credential escalation attack chain"""
    
    chain_id = hashlib.md5(
        f"{cred_finding['bucket_name']}-{data_finding['bucket_name']}".encode()
    ).hexdigest()[:16]
    
    chain = AttackChain(
        id=chain_id,
        name="Multi-Hop Privilege Escalation via Exposed Credentials",
        description="Attacker obtains credentials from one bucket to access another",
        severity=Severity.CRITICAL,
        start_point=cred_finding.get('bucket_url', ''),
        end_point="Privileged Data Access",
        complexity="MEDIUM"
    )
    
    # Step 1: Access credential bucket
    chain.add_step(
        action="Access Public Bucket",
        description=f"Access {cred_finding['bucket_name']} containing credentials",
        mitre_technique="T1530",
        mitre_tactic="Collection"
    )
    
    # Step 2: Extract credentials
    chain.add_step(
        action="Extract Credentials",
        description="Download and extract AWS credentials or API keys",
        mitre_technique="T1552.001",
        mitre_tactic="Credential Access"
    )
    
    # Step 3: Use credentials
    chain.add_step(
        action="Authenticate with Stolen Credentials",
        description=f"Use stolen credentials to access {data_finding['bucket_name']}",
        mitre_technique="T1078",
        mitre_tactic="Initial Access"
    )
    
    # Step 4: Data exfiltration
    chain.add_step(
        action="Exfiltrate Sensitive Data",
        description="Download sensitive data from authenticated bucket",
        mitre_technique="T1537",
        mitre_tactic="Collection"
    )
    
    # Calculate blast radius
    chain.blast_radius = (
        _calculate_blast_radius(cred_finding) +
        _calculate_blast_radius(data_finding)
    ) / 2 + 20  # Bonus for multi-hop
    
    chain.affected_resources.extend([
        cred_finding['bucket_name'],
        data_finding['bucket_name']
    ])
    
    chain.generate_narrative()
    
    return chain


def _calculate_blast_radius(finding: Dict[str, Any]) -> float:
    """
    Calculate blast radius (0-100) for a finding.
    
    Factors:
    - Severity
    - Number of sensitive files
    - Public access
    - Total size
    """
    score = 0.0
    
    # Severity weight (0-40 points)
    severity_map = {
        'CRITICAL': 40,
        'HIGH': 30,
        'MEDIUM': 20,
        'LOW': 10,
        'INFO': 5
    }
    score += severity_map.get(finding.get('severity', 'INFO'), 5)
    
    # Sensitive data count (0-30 points)
    sensitive_count = len(finding.get('sensitive_data', []))
    score += min(30, sensitive_count * 3)
    
    # Public access (0-20 points)
    if finding.get('is_public', False):
        score += 20
    
    # Size (0-10 points) - larger buckets = more impact
    total_size = finding.get('total_size', 0)
    if total_size > 10_000_000_000:  # 10GB
        score += 10
    elif total_size > 1_000_000_000:  # 1GB
        score += 5
    
    return min(100.0, score)


__all__ = ['build_attack_chains']
