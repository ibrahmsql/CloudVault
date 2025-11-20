"""
Result handlers for CloudVault CLI
Handles bucket results, logging, and notifications
"""
import json
import logging
import requests
from termcolor import cprint
from typing import List
from ..core.worker import WorkerResult

logger = logging.getLogger(__name__)


class BucketResultHandler:
    """Handles results from bucket discovery workers"""
    
    def __init__(self, config, vuln_scanner, content_analyzer, downloader=None, exploiter=None):
        self.config = config
        self.vuln_scanner = vuln_scanner
        self.content_analyzer = content_analyzer
        self.downloader = downloader
        self.exploiter = exploiter
        self.found_buckets = []
        self.vulnerability_findings = []
    
    def handle_found_bucket(self, result: WorkerResult):
        """
        Process a found bucket result
        
        Args:
            result: WorkerResult object containing bucket information
        """
        self.found_buckets.append(result)
        
        # Scan for vulnerabilities and analyze content
        vulnerabilities = []
        content_summary = ""
        
        if result.is_public and result.sample_objects:
            vulnerabilities = self._scan_vulnerabilities(result)
            content_summary = self._analyze_content(result)
            
            if self.downloader:
                self._download_and_exploit(result)
        
        # Display result
        self._display_result(result, vulnerabilities, content_summary)
        
        # Log to file if enabled
        if self.config.log_to_file:
            self._log_to_file(result, vulnerabilities)
        
        # Send to Slack if configured
        if self.config.slack_webhook:
            message = self._format_message(result, vulnerabilities, content_summary)
            self._send_to_slack(message)
    
    def _scan_vulnerabilities(self, result: WorkerResult) -> List:
        """Scan bucket contents for vulnerabilities"""
        vulnerabilities = self.vuln_scanner.scan_bucket_contents(
            result.sample_objects, result.bucket_url
        )
        self.vulnerability_findings.extend(vulnerabilities)
        return vulnerabilities
    
    def _analyze_content(self, result: WorkerResult) -> str:
        """Analyze and categorize bucket content"""
        categorized = self.content_analyzer.analyze_content_types(result.sample_objects)
        content_summary = self.content_analyzer.generate_content_summary(categorized)
        sensitivity = self.content_analyzer.estimate_data_sensitivity(categorized)
        return content_summary
    
    def _download_and_exploit(self, result: WorkerResult):
        """Download files and attempt credential exploitation"""
        try:
            downloaded_files = self.downloader.download_sample_files(
                result.bucket_url, result.sample_objects[:5]
            )
            
            if downloaded_files:
                cprint(f"  └─ Downloaded {len(downloaded_files)} files for analysis", "blue")
                
                if self.exploiter:
                    credentials = self.downloader.extract_credentials_from_files(downloaded_files)
                    if credentials:
                        cprint(f"  └─ Found {len(credentials)} potential credentials", "red", attrs=["bold"])
                        validated = self.exploiter.validate_credentials(credentials)
                        
                        for valid_cred in validated:
                            cprint(
                                f"  └─ ⚠️  VALID CREDENTIAL: {valid_cred['type']} -> {valid_cred['service']}",
                                "red", attrs=["bold", "blink"]
                            )
        except Exception as e:
            logger.debug(f"Error during download/analysis: {e}")
    
    def _display_result(self, result: WorkerResult, vulnerabilities: List, content_summary: str):
        """Display bucket result to console"""
        color = self._determine_color(result, vulnerabilities)
        message = self._format_message(result, vulnerabilities, content_summary)
        
        cprint(message, color, attrs=["bold"])
        
        # Display top vulnerabilities
        for vuln in vulnerabilities[:3]:
            vuln_color = "red" if vuln.severity == "CRITICAL" else "yellow"
            cprint(f"  └─ {vuln.severity}: {vuln.title} - {vuln.evidence}", vuln_color)
    
    def _determine_color(self, result: WorkerResult, vulnerabilities: List) -> str:
        """Determine console color based on result severity"""
        if vulnerabilities:
            if any(v.severity == "CRITICAL" for v in vulnerabilities):
                return "red"
            elif any(v.severity == "HIGH" for v in vulnerabilities):
                return "yellow"
        elif not result.is_public:
            return "magenta"
        return "green"
    
    def _format_message(self, result: WorkerResult, vulnerabilities: List, content_summary: str) -> str:
        """Format result message for display"""
        access_info = f"[{result.access_level.value.upper()}]"
        message = f"Found {result.provider.upper()} bucket: {result.bucket_url} {access_info}"
        
        if result.owner:
            message += f" (Owner: {result.owner})"
        
        # Add permission analysis
        if hasattr(result, 'permission_analysis') and result.permission_analysis:
            message += self._format_permissions(result)
        
        # Add content summary
        if content_summary and content_summary != "No sensitive content detected":
            message += f" - Contains: {content_summary}"
        
        # Add vulnerability counts
        if vulnerabilities:
            critical_count = sum(1 for v in vulnerabilities if v.severity == "CRITICAL")
            high_count = sum(1 for v in vulnerabilities if v.severity == "HIGH")
            
            if critical_count > 0:
                message += f" ⚠️  {critical_count} CRITICAL vulnerabilities!"
            elif high_count > 0:
                message += f" ⚠️  {high_count} HIGH risk findings!"
        
        return message
    
    def _format_permissions(self, result: WorkerResult) -> str:
        """Format permission analysis for display"""
        perm_analysis = result.permission_analysis
        permissions = []
        risk_indicators = []
        
        # Collect permission details
        if perm_analysis.get('public_read'):
            permissions.append("🌐 PUBLIC_READ")
        if perm_analysis.get('public_write'):
            permissions.append("🔓 PUBLIC_WRITE")
            risk_indicators.append("WRITE_ACCESS")
        if perm_analysis.get('authenticated_read'):
            permissions.append("🔐 AUTH_READ")
        if perm_analysis.get('public_read_acp'):
            permissions.append("📋 PUBLIC_READ_ACP")
        if perm_analysis.get('public_write_acp'):
            permissions.append("⚠️ PUBLIC_WRITE_ACP")
            risk_indicators.append("ACP_WRITE")
        
        message = ""
        if permissions:
            message += f"\n    └─ Permissions: {' | '.join(permissions)}"
        
        # Add risk level
        risk_level = perm_analysis.get('risk_level', 'LOW')
        risk_emoji = {'CRITICAL': '🚨', 'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}
        
        if risk_level in ['CRITICAL', 'HIGH', 'MEDIUM']:
            risk_context = ""
            if 'WRITE_ACCESS' in risk_indicators:
                risk_context = " (Public Write Enabled)"
            elif 'ACP_WRITE' in risk_indicators:
                risk_context = " (ACL Modification Allowed)"
            
            message += f"\n    └─ Risk Level: {risk_emoji.get(risk_level, '❓')} {risk_level}{risk_context}"
        
        return message
    
    def _log_to_file(self, result: WorkerResult, vulnerabilities: List = None):
        """Log result to file"""
        try:
            with open(self.config.log_file, 'a') as f:
                f.write(f"{result.bucket_url}\n")
            
            if vulnerabilities:
                vuln_file = self.config.log_file.replace('.log', '_vulnerabilities.log')
                with open(vuln_file, 'a') as vf:
                    for vuln in vulnerabilities:
                        vf.write(f"{result.bucket_url},{vuln.severity},{vuln.title},{vuln.evidence}\n")
        except Exception as e:
            logger.error(f"Error writing to log file: {e}")
    
    def _send_to_slack(self, message: str):
        """Send notification to Slack"""
        try:
            payload = {'text': message}
            response = requests.post(
                self.config.slack_webhook,
                data=json.dumps(payload),
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            if response.status_code != 200:
                logger.warning(f"Slack webhook returned {response.status_code}")
        except Exception as e:
            logger.error(f"Error sending to Slack: {e}")
