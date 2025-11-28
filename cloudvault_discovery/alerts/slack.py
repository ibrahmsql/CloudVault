"""
Slack Notifier
Send beautiful tree-formatted alerts to Slack
"""

import aiohttp
from typing import List, Dict, Any, Optional
from .notifier import BaseNotifier


class SlackNotifier(BaseNotifier):
    """Slack webhook notifier"""
    
    def __init__(self, webhook_url: str, 
                 severity_filter: Optional[List[str]] = None,
                 channel: Optional[str] = None,
                 username: str = "CloudVault Security"):
        """
        Initialize Slack notifier.
        
        Args:
            webhook_url: Slack webhook URL
            severity_filter: Filter by severity
            channel: Override channel
            username: Bot username
        """
        super().__init__(severity_filter)
        self.webhook_url = webhook_url
        self.channel = channel
        self.username = username
    
    async def send(self, findings: List[Dict[str, Any]], summary: Dict[str, Any]):
        """Send Slack notification"""
        # Create tree message
        tree_message = self.format_tree_message(findings, summary)
        
        # Determine color based on severity
        critical_count = summary.get('critical', 0)
        high_count = summary.get('high', 0)
        
        if critical_count > 0:
            color = "#dc3545"  # Red
            emoji = "🚨"
        elif high_count > 0:
            color = "#fd7e14"  # Orange
            emoji = "⚠️"
        else:
            color = "#ffc107"  # Yellow
            emoji = "ℹ️"
        
        # Build Slack message
        payload = {
            "username": self.username,
            "icon_emoji": ":shield:",
            "attachments": [
                {
                    "color": color,
                    "title": f"{emoji} CloudVault Security Alert",
                    "text": f"```\n{tree_message}\n```",
                    "footer": "CloudVault Scanner",
                    "footer_icon": "https://platform.slack-edge.com/img/default_application_icon.png",
                    "mrkdwn_in": ["text"]
                }
            ]
        }
        
        if self.channel:
            payload["channel"] = self.channel
        
        # Send to Slack
        async with aiohttp.ClientSession() as session:
            async with session.post(self.webhook_url, json=payload) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"Slack notification failed: {error_text}")


__all__ = ['SlackNotifier']
