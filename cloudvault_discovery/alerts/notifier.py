"""
Base Notifier
Abstract base class for all notification channels
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from ..models import Severity


class BaseNotifier(ABC):
    """Base class for all notifiers"""
    
    def __init__(self, severity_filter: Optional[List[str]] = None):
        """
        Initialize notifier.
        
        Args:
            severity_filter: List of severity levels to notify about
                           e.g., ['CRITICAL', 'HIGH']
        """
        self.severity_filter = [s.upper() for s in (severity_filter or [])]
    
    def should_notify(self, finding: Dict[str, Any]) -> bool:
        """Check if finding should trigger notification"""
        if not self.severity_filter:
            return True
        
        severity = finding.get('severity', 'INFO').upper()
        return severity in self.severity_filter
    
    @abstractmethod
    async def send(self, findings: List[Dict[str, Any]], summary: Dict[str, Any]):
        """
        Send notification.
        
        Args:
            findings: List of findings to notify about
            summary: Summary statistics
        """
        pass
    
    def format_tree_message(self, findings: List[Dict[str, Any]], 
                           summary: Dict[str, Any]) -> str:
        """
        Format findings as tree-style message.
        
        Args:
            findings: List of findings
            summary: Summary stats
            
        Returns:
            Tree-formatted string
        """
        lines = []
        
        # Header
        lines.append("🚨 CloudVault Security Alert")
        lines.append("=" * 50)
        lines.append("")
        
        # Summary
        total = summary.get('total_findings', len(findings))
        critical = summary.get('critical', 0)
        high = summary.get('high', 0)
        
        lines.append(f"📊 Summary: {total} findings")
        if critical > 0:
            lines.append(f"   ├─ 🔴 Critical: {critical}")
        if high > 0:
            lines.append(f"   ├─ 🟠 High: {high}")
        lines.append("")
        
        # Group by provider
        by_provider = {}
        for finding in findings[:10]:  # Limit to 10
            provider = finding.get('provider', 'unknown').upper()
            if provider not in by_provider:
                by_provider[provider] = []
            by_provider[provider].append(finding)
        
        # Tree structure
        lines.append("📋 Findings:")
        providers = list(by_provider.keys())
        for i, (provider, provider_findings) in enumerate(by_provider.items()):
            is_last_provider = (i == len(providers) - 1)
            provider_prefix = "└─" if is_last_provider else "├─"
            
            lines.append(f"{provider_prefix} {provider} ({len(provider_findings)})")
            
            for j, finding in enumerate(provider_findings):
                is_last_finding = (j == len(provider_findings) - 1)
                
                if is_last_provider:
                    finding_prefix = "   └─"
                else:
                    finding_prefix = "│  └─" if is_last_finding else "│  ├─"
                
                severity = finding.get('severity', 'INFO')
                icon = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠',
                    'MEDIUM': '🟡',
                    'LOW': '🔵',
                    'INFO': '⚪'
                }.get(severity.upper(), '⚪')
                
                title = finding.get('title', 'Unknown')[:60]
                bucket = finding.get('bucket_name', 'N/A')
                
                lines.append(f"{finding_prefix} {icon} [{severity}] {title}")
                
                if is_last_provider:
                    detail_prefix = "      "
                else:
                    detail_prefix = "│     " if is_last_finding else "│  │  "
                
                lines.append(f"{detail_prefix}🗄️  {bucket}")
        
        if len(findings) > 10:
            lines.append(f"... and {len(findings) - 10} more findings")
        
        return "\n".join(lines)


async def send_alert(findings: List[Dict[str, Any]], 
                     notifiers: List[BaseNotifier],
                     summary: Optional[Dict[str, Any]] = None):
    """
    Send alerts via all configured notifiers.
    
    Args:
        findings: Findings to notify about
        notifiers: List of notifier instances
        summary: Optional summary statistics
    """
    if not findings or not notifiers:
        return
    
    # Calculate summary if not provided
    if summary is None:
        summary = {
            'total_findings': len(findings),
            'critical': sum(1 for f in findings if f.get('severity') == 'CRITICAL'),
            'high': sum(1 for f in findings if f.get('severity') == 'HIGH'),
            'medium': sum(1 for f in findings if f.get('severity') == 'MEDIUM'),
        }
    
    # Send via each notifier
    for notifier in notifiers:
        # Filter findings based on notifier's severity filter
        filtered = [f for f in findings if notifier.should_notify(f)]
        
        if filtered:
            await notifier.send(filtered, summary)


__all__ = ['BaseNotifier', 'send_alert']
