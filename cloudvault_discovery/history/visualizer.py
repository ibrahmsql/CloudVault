"""
History Visualizer
Tree-formatted history and trend visualization
"""

from typing import List, Dict, Any
from rich.tree import Tree
from rich.table import Table
from rich.console import Console

console = Console()


def visualize_trends(trends: Dict[str, List], days: int = 30) -> str:
    """
    Visualize trends as tree with ASCII sparklines.
    
    Args:
        trends: Trends data from database
        days: Number of days
        
    Returns:
        Tree-formatted string
    """
    lines = []
    lines.append(f"📈 CloudVault Trends (Last {days} Days)")
    lines.append("=" * 60)
    lines.append("")
    
    for metric, data in trends.items():
        lines.append(f"├─ {metric.replace('_', ' ').title()}")
        
        if not data:
            lines.append("│  └─ No data")
            continue
        
        # Show last 10 points
        recent = data[:10]
        values = [d['value'] for d in recent]
        
        if values:
            latest = values[0]
            avg = sum(values) / len(values)
            min_val = min(values)
            max_val = max(values)
            
            lines.append(f"│  ├─ Latest: {latest:.1f}")
            lines.append(f"│  ├─ Average: {avg:.1f}")
            lines.append(f"│  ├─ Min: {min_val:.1f}")
            lines.append(f"│  └─ Max: {max_val:.1f}")
            
            # ASCII sparkline
            sparkline = _create_sparkline(values)
            lines.append(f"│     {sparkline}")
        
        lines.append("│")
    
    return "\n".join(lines)


def render_history_tree(scans: List[Dict[str, Any]]) -> str:
    """
    Render scan history as tree.
    
    Args:
        scans: List of scan summaries
        
    Returns:
        Tree-formatted string
    """
    lines = []
    lines.append("📜 Scan History")
    lines.append("=" * 60)
    lines.append("")
    
    for i, scan in enumerate(scans):
        is_last = (i == len(scans) - 1)
        prefix = "└─" if is_last else "├─"
        detail_prefix = "   " if is_last else "│  "
        
        timestamp = scan.get('timestamp', 'Unknown')[:19]  # Remove milliseconds
        total = scan.get('total_findings', 0)
        critical = scan.get('critical_count', 0)
        high = scan.get('high_count', 0)
        risk = scan.get('avg_risk_score', 0)
        
        lines.append(f"{prefix} Scan #{scan.get('id', 0)} - {timestamp}")
        lines.append(f"{detail_prefix}├─ Total: {total} findings")
        
        if critical > 0 or high > 0:
            lines.append(f"{detail_prefix}├─ 🔴 Critical: {critical}, 🟠 High: {high}")
        
        lines.append(f"{detail_prefix}└─ Avg Risk: {risk:.1f}/100")
        
        if not is_last:
            lines.append("│")
    
    return "\n".join(lines)


def _create_sparkline(values: List[float]) -> str:
    """Create ASCII sparkline"""
    if not values:
        return ""
    
    # Normalize values to 0-7 range for Unicode block characters
    min_val = min(values)
    max_val = max(values)
    
    if max_val == min_val:
        return "▄" * len(values)
    
    # Unicode block characters (ascending height)
    blocks = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█']
    
    normalized = []
    for v in values:
        # Normalize to 0-8 range
        norm = int(((v - min_val) / (max_val - min_val)) * 8)
        normalized.append(blocks[norm])
    
    return ''.join(normalized)


__all__ = ['visualize_trends', 'render_history_tree']
