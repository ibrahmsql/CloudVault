"""
Finding Data Model
Represents a security finding with severity, risk score, and MITRE ATT&CK mapping
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any
from . import Severity


@dataclass
class Finding:
    """Security finding discovered during scanning"""
    
    # Core identification
    id: str
    title: str
    description: str
    
    # Classification
    severity: Severity
    risk_score: float  # 0-100
    
    # Target information
    provider: str  # aws, gcp, azure
    bucket_name: str
    bucket_url: str
    
    # Access information
    is_public: bool
    permissions: List[str] = field(default_factory=list)
    
    # Content analysis
    interesting_files: List[str] = field(default_factory=list)
    sensitive_data: List[str] = field(default_factory=list)
    total_files: int = 0
    total_size: int = 0
    
    # Attack chain information
    mitre_techniques: List[str] = field(default_factory=list)  # e.g., ["T1530", "T1078"]
    attack_patterns: List[str] = field(default_factory=list)
    
    # Metadata
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    owner: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Remediation
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for export"""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": str(self.severity),
            "risk_score": self.risk_score,
            "provider": self.provider,
            "bucket_name": self.bucket_name,
            "bucket_url": self.bucket_url,
            "is_public": self.is_public,
            "permissions": self.permissions,
            "interesting_files": self.interesting_files,
            "sensitive_data": self.sensitive_data,
            "total_files": self.total_files,
            "total_size": self.total_size,
            "mitre_techniques": self.mitre_techniques,
            "attack_patterns": self.attack_patterns,
            "discovered_at": self.discovered_at.isoformat(),
            "owner": self.owner,
            "metadata": self.metadata,
            "remediation": self.remediation,
            "references": self.references
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding':
        """Create from dictionary"""
        # Convert severity string to enum
        if isinstance(data.get('severity'), str):
            data['severity'] = Severity[data['severity']]
        
        # Convert timestamp string to datetime
        if isinstance(data.get('discovered_at'), str):
            data['discovered_at'] = datetime.fromisoformat(data['discovered_at'])
        
        return cls(**data)


__all__ = ['Finding']
