"""
Statistics and reporting for CloudVault CLI
Handles final statistics and vulnerability reports
"""
from termcolor import cprint
from typing import List
from ..core.worker import BaseWorker, WorkerResult


class StatsReporter:
    """Generates and displays final statistics and reports"""
    
    def __init__(self, workers: List[BaseWorker], found_buckets: List[WorkerResult], 
                 vulnerability_findings: List, config):
        self.workers = workers
        self.found_buckets = found_buckets
        self.vulnerability_findings = vulnerability_findings
        self.config = config
    
    def print_final_stats(self):
        """Print comprehensive final statistics"""
        # Calculate statistics
        total_checked = sum(w.get_stats()['checked'] for w in self.workers)
        total_found = len(self.found_buckets)
        public_found = sum(1 for r in self.found_buckets if r.is_public)
        interesting_found = sum(1 for r in self.found_buckets if r.has_interesting_content)
        
        # Vulnerability counts
        critical_vulns = sum(1 for v in self.vulnerability_findings if v.severity == "CRITICAL")
        high_vulns = sum(1 for v in self.vulnerability_findings if v.severity == "HIGH")
        medium_vulns = sum(1 for v in self.vulnerability_findings if v.severity == "MEDIUM")
        low_vulns = sum(1 for v in self.vulnerability_findings if v.severity == "LOW")
        total_vulns = len(self.vulnerability_findings)
        
        # Print scan statistics
        self._print_scan_statistics(total_checked, total_found, public_found, interesting_found)
        
        # Print security assessment if vulnerabilities found
        if total_vulns > 0:
            self._print_security_assessment(
                critical_vulns, high_vulns, medium_vulns, low_vulns, total_vulns
            )
        else:
            cprint("\n✅ No security vulnerabilities detected in this scan", "green", attrs=["bold"])
        
        # Print output file locations
        self._print_output_files()
    
    def _print_scan_statistics(self, total_checked: int, total_found: int, 
                               public_found: int, interesting_found: int):
        """Print basic scan statistics"""
        cprint("\n" + "═" * 70, "cyan")
        cprint("📊 CLOUDVAULT DISCOVERY - SCAN RESULTS", "cyan", attrs=["bold"])
        cprint("═" * 70, "cyan")
        
        cprint(f"🔍 Targets Scanned:     {total_checked:>8}", "white")
        cprint(f"✅ Buckets Found:       {total_found:>8}", "green", attrs=["bold"])
        cprint(f"🌐 Public Access:       {public_found:>8}", "yellow")
        cprint(f"⚠️  Sensitive Content:   {interesting_found:>8}", "red")
    
    def _print_security_assessment(self, critical_vulns: int, high_vulns: int, 
                                   medium_vulns: int, low_vulns: int, total_vulns: int):
        """Print security vulnerability assessment"""
        cprint("\n" + "═" * 70, "red")
        cprint("🛡️  SECURITY THREAT ASSESSMENT", "red", attrs=["bold"])
        cprint("═" * 70, "red")
        
        # Risk level breakdown
        if critical_vulns > 0:
            cprint(f"🚨 CRITICAL THREATS:    {critical_vulns:>8} issues", 
                   "red", attrs=["bold", "blink"])
        if high_vulns > 0:
            cprint(f"🔴 HIGH RISK:           {high_vulns:>8} issues", 
                   "red", attrs=["bold"])
        if medium_vulns > 0:
            cprint(f"🟡 MEDIUM RISK:         {medium_vulns:>8} issues", "yellow")
        if low_vulns > 0:
            cprint(f"🟢 LOW RISK:            {low_vulns:>8} issues", "green")
        
        cprint("─" * 70, "white")
        
        # Risk summary
        if critical_vulns > 0:
            cprint("⚡ IMMEDIATE ACTION REQUIRED - Critical vulnerabilities detected!", 
                   "red", attrs=["bold", "blink"])
        elif high_vulns > 0:
            cprint("⚠️  HIGH PRIORITY - Significant security risks identified!", 
                   "yellow", attrs=["bold"])
        else:
            cprint("ℹ️  Review recommended for identified security issues", "cyan")
        
        # Permission analysis summary
        self._print_permission_analysis()
        
        cprint(f"\n📈 Total Security Issues: {total_vulns}", "white", attrs=["bold"])
        cprint("═" * 70, "red")
    
    def _print_permission_analysis(self):
        """Print permission analysis summary"""
        public_write_buckets = sum(
            1 for r in self.found_buckets 
            if hasattr(r, 'permission_analysis') and r.permission_analysis 
            and r.permission_analysis.get('public_write', False)
        )
        public_read_buckets = sum(
            1 for r in self.found_buckets 
            if hasattr(r, 'permission_analysis') and r.permission_analysis 
            and r.permission_analysis.get('public_read', False)
        )
        
        if public_write_buckets > 0 or public_read_buckets > 0:
            cprint("\n📋 Permission Analysis:", "cyan", attrs=["bold"])
            if public_write_buckets > 0:
                cprint(f"   🔓 Public Write Access: {public_write_buckets} buckets", 
                       "red", attrs=["bold"])
            if public_read_buckets > 0:
                cprint(f"   👁️  Public Read Access:  {public_read_buckets} buckets", "yellow")
    
    def _print_output_files(self):
        """Print output file locations"""
        if self.found_buckets:
            cprint(f"\n📁 Results saved to: {self.config.log_file}", "cyan")
            if self.vulnerability_findings:
                vuln_file = self.config.log_file.replace('.log', '_vulnerabilities.log')
                cprint(f"📁 Vulnerabilities saved to: {vuln_file}", "cyan")
