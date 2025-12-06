"""
Cloud Attack Chain Builder
Automated attack path generation and MITRE ATT&CK mapping
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
from enum import Enum

logger = logging.getLogger(__name__)


class AttackStage(Enum):
    """Attack kill chain stages"""
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class AttackSeverity(Enum):
    """Attack path severity"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class AttackNode:
    """Single step in an attack chain"""
    node_id: str
    title: str
    description: str
    resource_type: str
    resource_id: str
    stage: AttackStage
    technique_id: str = ""
    technique_name: str = ""
    prerequisites: List[str] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackChain:
    """Complete attack path"""
    chain_id: str
    title: str
    description: str
    severity: AttackSeverity
    nodes: List[AttackNode] = field(default_factory=list)
    start_node: str = ""
    end_node: str = ""
    total_steps: int = 0
    mitre_techniques: List[str] = field(default_factory=list)
    affected_resources: List[str] = field(default_factory=list)
    
    def calculate_risk_score(self) -> float:
        """Calculate risk score based on chain characteristics"""
        base_score = {
            AttackSeverity.CRITICAL: 10.0,
            AttackSeverity.HIGH: 7.5,
            AttackSeverity.MEDIUM: 5.0,
            AttackSeverity.LOW: 2.5
        }.get(self.severity, 5.0)
        
        # Shorter chains are more dangerous (easier to execute)
        step_factor = max(0.5, 1.0 - (self.total_steps - 1) * 0.1)
        
        return min(10.0, base_score * step_factor)


# MITRE ATT&CK Cloud Techniques
MITRE_CLOUD_TECHNIQUES = {
    # Initial Access
    'T1190': {'name': 'Exploit Public-Facing Application', 'stage': AttackStage.INITIAL_ACCESS},
    'T1078': {'name': 'Valid Accounts', 'stage': AttackStage.INITIAL_ACCESS},
    'T1078.004': {'name': 'Cloud Accounts', 'stage': AttackStage.INITIAL_ACCESS},
    
    # Execution
    'T1059.009': {'name': 'Cloud API', 'stage': AttackStage.EXECUTION},
    'T1648': {'name': 'Serverless Execution', 'stage': AttackStage.EXECUTION},
    'T1609': {'name': 'Container Administration Command', 'stage': AttackStage.EXECUTION},
    'T1610': {'name': 'Deploy Container', 'stage': AttackStage.EXECUTION},
    
    # Persistence
    'T1098': {'name': 'Account Manipulation', 'stage': AttackStage.PERSISTENCE},
    'T1098.001': {'name': 'Additional Cloud Credentials', 'stage': AttackStage.PERSISTENCE},
    'T1098.003': {'name': 'Additional Cloud Roles', 'stage': AttackStage.PERSISTENCE},
    'T1136.003': {'name': 'Cloud Account', 'stage': AttackStage.PERSISTENCE},
    'T1525': {'name': 'Implant Container Image', 'stage': AttackStage.PERSISTENCE},
    
    # Privilege Escalation
    'T1548': {'name': 'Abuse Elevation Control Mechanism', 'stage': AttackStage.PRIVILEGE_ESCALATION},
    'T1611': {'name': 'Escape to Host', 'stage': AttackStage.PRIVILEGE_ESCALATION},
    
    # Defense Evasion
    'T1578': {'name': 'Modify Cloud Compute Infrastructure', 'stage': AttackStage.DEFENSE_EVASION},
    'T1562.007': {'name': 'Disable Cloud Logs', 'stage': AttackStage.DEFENSE_EVASION},
    
    # Credential Access
    'T1552': {'name': 'Unsecured Credentials', 'stage': AttackStage.CREDENTIAL_ACCESS},
    'T1552.001': {'name': 'Credentials In Files', 'stage': AttackStage.CREDENTIAL_ACCESS},
    'T1552.005': {'name': 'Cloud Instance Metadata API', 'stage': AttackStage.CREDENTIAL_ACCESS},
    'T1528': {'name': 'Steal Application Access Token', 'stage': AttackStage.CREDENTIAL_ACCESS},
    'T1606': {'name': 'Forge Web Credentials', 'stage': AttackStage.CREDENTIAL_ACCESS},
    
    # Discovery
    'T1087.004': {'name': 'Cloud Account', 'stage': AttackStage.DISCOVERY},
    'T1069.003': {'name': 'Cloud Groups', 'stage': AttackStage.DISCOVERY},
    'T1580': {'name': 'Cloud Infrastructure Discovery', 'stage': AttackStage.DISCOVERY},
    'T1046': {'name': 'Network Service Discovery', 'stage': AttackStage.DISCOVERY},
    
    # Lateral Movement
    'T1021': {'name': 'Remote Services', 'stage': AttackStage.LATERAL_MOVEMENT},
    'T1550.001': {'name': 'Application Access Token', 'stage': AttackStage.LATERAL_MOVEMENT},
    
    # Collection
    'T1530': {'name': 'Data from Cloud Storage', 'stage': AttackStage.COLLECTION},
    'T1074.002': {'name': 'Remote Data Staging', 'stage': AttackStage.COLLECTION},
    
    # Exfiltration
    'T1537': {'name': 'Transfer Data to Cloud Account', 'stage': AttackStage.EXFILTRATION},
    'T1567.002': {'name': 'Exfil to Cloud Storage', 'stage': AttackStage.EXFILTRATION},
    
    # Impact
    'T1485': {'name': 'Data Destruction', 'stage': AttackStage.IMPACT},
    'T1486': {'name': 'Data Encrypted for Impact', 'stage': AttackStage.IMPACT},
    'T1491': {'name': 'Defacement', 'stage': AttackStage.IMPACT},
    'T1496': {'name': 'Resource Hijacking', 'stage': AttackStage.IMPACT},
}


class AttackChainBuilder:
    """
    Automated Attack Chain Builder
    
    Analyzes cloud security findings and generates
    potential attack paths with MITRE ATT&CK mapping.
    """
    
    def __init__(self):
        self.nodes: Dict[str, AttackNode] = {}
        self.chains: List[AttackChain] = []
        self._node_counter = 0
    
    def _create_node_id(self) -> str:
        """Generate unique node ID"""
        self._node_counter += 1
        return f"node_{self._node_counter}"
    
    def add_finding(self, 
                   finding_type: str,
                   resource_type: str,
                   resource_id: str,
                   title: str,
                   description: str,
                   technique_id: str = "",
                   metadata: Dict = None) -> str:
        """Add a finding as an attack node"""
        tech = MITRE_CLOUD_TECHNIQUES.get(technique_id, {})
        
        node = AttackNode(
            node_id=self._create_node_id(),
            title=title,
            description=description,
            resource_type=resource_type,
            resource_id=resource_id,
            stage=tech.get('stage', AttackStage.DISCOVERY),
            technique_id=technique_id,
            technique_name=tech.get('name', ''),
            metadata=metadata or {}
        )
        
        self.nodes[node.node_id] = node
        return node.node_id
    
    def link_nodes(self, from_node: str, to_node: str):
        """Link two nodes in an attack path"""
        if from_node in self.nodes and to_node in self.nodes:
            self.nodes[from_node].next_steps.append(to_node)
            self.nodes[to_node].prerequisites.append(from_node)
    
    def build_chains(self) -> List[AttackChain]:
        """Build attack chains from connected nodes"""
        chains = []
        visited: Set[str] = set()
        
        # Find all entry points (nodes with no prerequisites)
        entry_points = [
            node_id for node_id, node in self.nodes.items()
            if not node.prerequisites
        ]
        
        for entry in entry_points:
            paths = self._find_paths(entry, visited.copy())
            
            for path in paths:
                if len(path) >= 2:  # Only chains with 2+ steps
                    chain = self._create_chain(path)
                    chains.append(chain)
        
        self.chains = chains
        return chains
    
    def _find_paths(self, 
                   start: str, 
                   visited: Set[str],
                   current_path: List[str] = None) -> List[List[str]]:
        """Find all paths from a starting node"""
        if current_path is None:
            current_path = []
        
        current_path = current_path + [start]
        visited.add(start)
        
        node = self.nodes.get(start)
        if not node or not node.next_steps:
            return [current_path]
        
        paths = []
        for next_node in node.next_steps:
            if next_node not in visited:
                new_paths = self._find_paths(next_node, visited.copy(), current_path)
                paths.extend(new_paths)
        
        if not paths:
            return [current_path]
        
        return paths
    
    def _create_chain(self, path: List[str]) -> AttackChain:
        """Create an attack chain from a path"""
        nodes = [self.nodes[n] for n in path if n in self.nodes]
        
        if not nodes:
            return None
        
        # Determine severity based on final stage
        final_stage = nodes[-1].stage
        severity = AttackSeverity.LOW
        
        high_impact_stages = [
            AttackStage.PRIVILEGE_ESCALATION,
            AttackStage.CREDENTIAL_ACCESS,
            AttackStage.EXFILTRATION,
            AttackStage.IMPACT
        ]
        
        if final_stage in [AttackStage.IMPACT, AttackStage.EXFILTRATION]:
            severity = AttackSeverity.CRITICAL
        elif final_stage in [AttackStage.CREDENTIAL_ACCESS, AttackStage.PRIVILEGE_ESCALATION]:
            severity = AttackSeverity.HIGH
        elif final_stage in [AttackStage.LATERAL_MOVEMENT, AttackStage.COLLECTION]:
            severity = AttackSeverity.MEDIUM
        
        # Collect MITRE techniques
        techniques = [n.technique_id for n in nodes if n.technique_id]
        
        # Collect affected resources
        resources = [n.resource_id for n in nodes]
        
        chain = AttackChain(
            chain_id=f"chain_{len(self.chains) + 1}",
            title=f"{nodes[0].title} → {nodes[-1].title}",
            description=f"Attack path from {nodes[0].resource_type} to {nodes[-1].resource_type}",
            severity=severity,
            nodes=nodes,
            start_node=nodes[0].node_id,
            end_node=nodes[-1].node_id,
            total_steps=len(nodes),
            mitre_techniques=techniques,
            affected_resources=resources
        )
        
        return chain
    
    def build_from_findings(self, findings: List[Any]) -> List[AttackChain]:
        """
        Build attack chains from a list of security findings.
        
        Automatically connects related findings based on:
        - Resource relationships
        - Attack stage progression
        - Technique prerequisites
        """
        # Add findings as nodes
        node_ids = []
        for finding in findings:
            # Extract info from finding (handles different finding types)
            finding_type = getattr(finding, 'finding_type', finding.get('finding_type', 'unknown'))
            resource_type = getattr(finding, 'resource_type', finding.get('resource_type', 'unknown'))
            resource_id = getattr(finding, 'resource_id', finding.get('resource_id', 'unknown'))
            title = getattr(finding, 'title', finding.get('title', 'Unknown Finding'))
            description = getattr(finding, 'description', finding.get('description', ''))
            
            # Get MITRE technique if available
            mitre = getattr(finding, 'mitre_techniques', finding.get('mitre_techniques', []))
            technique_id = mitre[0] if mitre else ''
            
            node_id = self.add_finding(
                finding_type=finding_type,
                resource_type=resource_type,
                resource_id=resource_id,
                title=title,
                description=description,
                technique_id=technique_id
            )
            node_ids.append(node_id)
        
        # Auto-link nodes based on attack stage progression
        self._auto_link_nodes()
        
        return self.build_chains()
    
    def _auto_link_nodes(self):
        """Automatically link nodes based on attack stage progression"""
        # Define valid stage progressions
        stage_order = [
            AttackStage.INITIAL_ACCESS,
            AttackStage.EXECUTION,
            AttackStage.PERSISTENCE,
            AttackStage.PRIVILEGE_ESCALATION,
            AttackStage.DEFENSE_EVASION,
            AttackStage.CREDENTIAL_ACCESS,
            AttackStage.DISCOVERY,
            AttackStage.LATERAL_MOVEMENT,
            AttackStage.COLLECTION,
            AttackStage.EXFILTRATION,
            AttackStage.IMPACT
        ]
        
        stage_indices = {s: i for i, s in enumerate(stage_order)}
        
        # Group nodes by resource
        by_resource: Dict[str, List[AttackNode]] = {}
        for node in self.nodes.values():
            resource = node.resource_id
            if resource not in by_resource:
                by_resource[resource] = []
            by_resource[resource].append(node)
        
        # Link nodes on same resource with stage progression
        for resource, nodes in by_resource.items():
            sorted_nodes = sorted(nodes, key=lambda n: stage_indices.get(n.stage, 99))
            
            for i in range(len(sorted_nodes) - 1):
                current = sorted_nodes[i]
                next_node = sorted_nodes[i + 1]
                
                # Only link if there's stage progression
                current_idx = stage_indices.get(current.stage, 99)
                next_idx = stage_indices.get(next_node.stage, 99)
                
                if next_idx > current_idx:
                    self.link_nodes(current.node_id, next_node.node_id)
        
        # Cross-resource links for credential/token theft
        credential_nodes = [n for n in self.nodes.values() 
                          if n.stage == AttackStage.CREDENTIAL_ACCESS]
        lateral_nodes = [n for n in self.nodes.values()
                        if n.stage in [AttackStage.LATERAL_MOVEMENT, AttackStage.INITIAL_ACCESS]]
        
        for cred_node in credential_nodes:
            for lat_node in lateral_nodes:
                if cred_node.resource_id != lat_node.resource_id:
                    self.link_nodes(cred_node.node_id, lat_node.node_id)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of attack chains"""
        if not self.chains:
            self.build_chains()
        
        return {
            'total_nodes': len(self.nodes),
            'total_chains': len(self.chains),
            'critical_chains': len([c for c in self.chains if c.severity == AttackSeverity.CRITICAL]),
            'high_chains': len([c for c in self.chains if c.severity == AttackSeverity.HIGH]),
            'average_chain_length': sum(c.total_steps for c in self.chains) / len(self.chains) if self.chains else 0,
            'unique_techniques': len(set(t for c in self.chains for t in c.mitre_techniques)),
            'chains': [
                {
                    'id': c.chain_id,
                    'title': c.title,
                    'severity': c.severity.value,
                    'steps': c.total_steps,
                    'risk_score': c.calculate_risk_score()
                }
                for c in sorted(self.chains, key=lambda x: x.calculate_risk_score(), reverse=True)
            ]
        }


__all__ = [
    'AttackChainBuilder',
    'AttackChain',
    'AttackNode',
    'AttackStage',
    'AttackSeverity',
    'MITRE_CLOUD_TECHNIQUES'
]
