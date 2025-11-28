"""
Discord Notifier
Send beautiful embed alerts to Discord
"""

import aiohttp
from typing import List, Dict, Any, Optional
from .notifier import BaseNotifier


class DiscordNotifier(BaseNotifier):
    """Discord webhook notifier"""
    
    def __init__(self, webhook_url: str,
                 severity_filter: Optional[List[str]] = None,
                 username: str = "CloudVault Security"):
        """
        Initialize Discord notifier.
        
        Args:
            webhook_url: Discord webhook URL
            severity_filter: Filter by severity
            username: Bot username
        """
        super().__init__(severity_filter)
        self.webhook_url = webhook_url
        self.username = username
    
    async def send(self, findings: List[Dict[str, Any]], summary: Dict[str, Any]):
        """Send Discord notification"""
        # Create tree message
        tree_message = self.format_tree_message(findings, summary)
        
        # Determine color based on severity
        critical_count = summary.get('critical', 0)
        high_count = summary.get('high', 0)
        
        if critical_count > 0:
            color = 0xDC3545  # Red
        elif high_count > 0:
            color = 0xFD7E14  # Orange
        else:
            color = 0xFFC107  # Yellow
        
        # Build Discord embed
        embed = {
            "title": "🛡️ CloudVault Security Alert",
            "description": f"```\n{tree_message}\n```",
            "color": color,
            "footer": {
                "text": "CloudVault Scanner"
            },
            "fields": [
                {
                    "name": "📊 Total Findings",
                    "value": str(summary.get('total_findings', 0)),
                    "inline": True
                }
            ]
        }
        
        # Add severity counts
        if critical_count > 0:
            embed["fields"].append({
                "name": "🔴 Critical",
                "value": str(critical_count),
                "inline": True
            })
        
        if high_count > 0:
            embed["fields"].append({
                "name": "🟠 High",
                "value": str(high_count),
                "inline": True
            })
        
        payload = {
            "username": self.username,
            "embeds": [embed]
        }
        
        # Send to Discord
        async with aiohttp.ClientSession() as session:
            async with session.post(self.webhook_url, json=payload) as response:
                if response.status not in [200, 204]:
                    error_text = await response.text()
                    raise Exception(f"Discord notification failed: {error_text}")


__all__ = ['DiscordNotifier']
