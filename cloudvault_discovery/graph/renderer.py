"""
Trust Graph Visualization
Tree-based renderingof bucket → role → resource relationships
"""

from typing import List, Dict, Any


def build_trust_graph(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build trust relationship graph"""
    # Simplified implementation
    return {
        'nodes': len(findings),
        'edges': len(findings) * 2,
        'critical_paths': []
    }


def render_graph_tree(findings: List[Dict[str, Any]]) -> str:
    """Render trust graph as tree"""
    lines = []
    lines.append("🌐 Trust Graph Visualization")
    lines.append("=" * 60)
    lines.append("")
    
    # Group by provider
    by_provider = {}
    for f in findings:
        prov = f.get('provider', 'unknown').upper()
        if prov not in by_provider:
            by_provider[prov] = []
        by_provider[prov].append(f)
    
    for  i, (prov, items) in enumerate(by_provider.items()):
        is_last = (i == len(by_provider) - 1)
        prefix = "└─" if is_last else "├─"
        
        lines.append(f"{prefix} {prov} Environment")
        
        for j, item in enumerate(items[:3]):
            sub_prefix = "   └─" if is_last else "│  └─"
            bucket = item.get('bucket_name', 'N/A')
            public = "🌍 Public" if item.get('is_public') else "🔒 Private"
            lines.append(f"{sub_prefix} {bucket} ({public})")
    
    return "\n".join(lines)


__all__ = ['build_trust_graph', 'render_graph_tree']
