"""
Attack Chain Data Model
Represents multi-hop attack paths and privilege escalation chains
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from . import Severity


@dataclass
class AttackStep:
    """Single step in an attack chain"""
    step_number: int
    action: str
    description: str
    mitre_technique: str  # e.g., "T1530"
    mitre_tactic: str  # e.g., "Collection"
    finding_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_number": self.step_number,
            "action": self.action,
            "description": self.description,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
            "finding_id": self.finding_id
        }


@dataclass
class AttackChain:
    """Multi-hop attack chain showing privilege escalation path"""
    
    id: str
    name: str
    description: str
    
    # Chain properties
    steps: List[AttackStep] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    blast_radius: float = 0.0  # 0-100 score
    
    # Target information
    start_point: str = ""  # Initial access point
    end_point: str = ""  # Final objective (e.g., "Admin Access")
    affected_resources: List[str] = field(default_factory=list)
    
    # Attack metadata
    complexity: str = "MEDIUM"  # LOW, MEDIUM, HIGH
    prerequisites: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    
    # Narrative
    narrative: str = ""  # Human-readable step-by-step explanation
    
    def add_step(self, action: str, description: str, 
                 mitre_technique: str, mitre_tactic: str,
                 finding_id: Optional[str] = None):
        """Add a step to the attack chain"""
        step = AttackStep(
            step_number=len(self.steps) + 1,
            action=action,
            description=description,
            mitre_technique=mitre_technique,
            mitre_tactic=mitre_tactic,
            finding_id=finding_id
        )
        self.steps.append(step)
        if mitre_tactic not in self.mitre_tactics:
            self.mitre_tactics.append(mitre_tactic)
    
    @property
    def hop_count(self) -> int:
        """Number of hops in the attack chain"""
        return len(self.steps)
    
    @property
    def is_multi_hop(self) -> bool:
        """Whether this is a multi-hop attack (3+ steps)"""
        return self.hop_count >= 3
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for export"""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "steps": [step.to_dict() for step in self.steps],
            "severity": str(self.severity),
            "blast_radius": self.blast_radius,
            "start_point": self.start_point,
            "end_point": self.end_point,
            "affected_resources": self.affected_resources,
            "complexity": self.complexity,
            "prerequisites": self.prerequisites,
            "mitre_tactics": self.mitre_tactics,
            "narrative": self.narrative,
            "hop_count": self.hop_count,
            "is_multi_hop": self.is_multi_hop
        }
    
    def generate_narrative(self) -> str:
        """Generate human-readable narrative of the attack chain"""
        if not self.steps:
            return "No attack steps defined."
        
        lines = [f"**{self.name}**", "", self.description, ""]
        lines.append(f"**Attack Path ({self.hop_count} steps):**")
        
        for step in self.steps:
            lines.append(f"{step.step_number}. **{step.action}** ({step.mitre_technique})")
            lines.append(f"   {step.description}")
        
        lines.append("")
        lines.append(f"**Blast Radius:** {self.blast_radius:.1f}/100")
        lines.append(f"**Complexity:** {self.complexity}")
        
        self.narrative = "\n".join(lines)
        return self.narrative


__all__ = ['AttackChain', 'AttackStep']
