"""
Email Notifier
Send HTML email alerts with tree-formatted content
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Any, Optional
from .notifier import BaseNotifier


class EmailNotifier(BaseNotifier):
    """Email SMTP notifier"""
    
    def __init__(self,
                 smtp_host: str,
                 smtp_port: int,
                 from_email: str,
                 to_emails: List[str],
                 username: Optional[str] = None,
                 password: Optional[str] = None,
                 severity_filter: Optional[List[str]] = None,
                 use_tls: bool = True):
        """
        Initialize Email notifier.
        
        Args:
            smtp_host: SMTP server hostname
            smtp_port: SMTP port (587 for TLS, 465 for SSL)
            from_email: Sender email address
            to_emails: List of recipient emails
            username: SMTP username (if required)
            password: SMTP password (if required)
            severity_filter: Filter by severity
            use_tls: Use TLS encryption
        """
        super().__init__(severity_filter)
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.from_email = from_email
        self.to_emails = to_emails
        self.username = username
        self.password = password
        self.use_tls = use_tls
    
    async def send(self, findings: List[Dict[str, Any]], summary: Dict[str, Any]):
        """Send email notification"""
        # Create tree message for text part
        tree_message = self.format_tree_message(findings, summary)
        
        # Create HTML version
        html_message = self._create_html_message(findings, summary, tree_message)
        
        # Build email
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"🚨 CloudVault Alert: {summary.get('total_findings', 0)} findings"
        msg['From'] = self.from_email
        msg['To'] = ', '.join(self.to_emails)
        
        # Add text and HTML parts
        text_part = MIMEText(tree_message, 'plain')
        html_part = MIMEText(html_message, 'html')
        
        msg.attach(text_part)
        msg.attach(html_part)
        
        # Send email
        try:
            if self.use_tls:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port)
                server.starttls()
            else:
                server = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port)
            
            if self.username and self.password:
                server.login(self.username, self.password)
            
            server.sendmail(self.from_email, self.to_emails, msg.as_string())
            server.quit()
            
        except Exception as e:
            raise Exception(f"Email notification failed: {e}")
    
    def _create_html_message(self, findings: List[Dict[str, Any]],
                            summary: Dict[str, Any],
                            tree_message: str) -> str:
        """Create HTML version of the message"""
        critical = summary.get('critical', 0)
        high = summary.get('high', 0)
        
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: 'Courier New', monospace; background: #f5f5f5; padding: 20px; }}
                .container {{ background: white; padding: 20px; border-radius: 8px; max-width: 800px; margin: 0 auto; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 5px; }}
                .tree {{ background: #1e1e1e; color: #d4d4d4; padding: 20px; border-radius: 5px; margin: 20px 0; overflow-x: auto; }}
                pre {{ margin: 0; white-space: pre-wrap; }}
                .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
                .stat {{ background: #f8f9fa; padding: 15px; border-radius: 5px; flex: 1; text-align: center; }}
                .stat-critical {{ border-left: 4px solid #dc3545; }}
                .stat-high {{ border-left: 4px solid #fd7e14; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ CloudVault Security Alert</h1>
                    <p>New security findings detected</p>
                </div>
                
                <div class="stats">
                    <div class="stat">
                        <h3>📊 Total</h3>
                        <h2>{summary.get('total_findings', 0)}</h2>
                    </div>
                    {f'<div class="stat stat-critical"><h3>🔴 Critical</h3><h2>{critical}</h2></div>' if critical > 0 else ''}
                    {f'<div class="stat stat-high"><h3>🟠 High</h3><h2>{high}</h2></div>' if high > 0 else ''}
                </div>
                
                <div class="tree">
                    <pre>{tree_message}</pre>
                </div>
                
                <p style="text-align: center; color: #666;">
                    CloudVault Scanner - Cloud Security Monitoring
                </p>
            </div>
        </body>
        </html>
        """
        
        return html


__all__ = ['EmailNotifier']
