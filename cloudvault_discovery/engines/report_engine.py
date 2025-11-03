"""
Advanced Report Engine
Generates comprehensive reports in multiple formats with customizable templates
"""
import logging
import json
import csv
from datetime import datetime
from enum import Enum
from typing import List, Dict, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class ReportFormat(Enum):
    """Report output formats"""
    JSON = "json"
    CSV = "csv"
    HTML = "html"
    MARKDOWN = "markdown"
    PDF = "pdf"
    XML = "xml"


class ReportEngine:
    """
    Advanced reporting engine with multiple output formats
    """
    
    def __init__(self, output_dir: str = "reports"):
        """
        Initialize report engine
        
        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.report_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        logger.info(f"Report engine initialized, output: {self.output_dir}")
    
    def generate_report(self, findings: List[Dict], format: ReportFormat,
                       filename: Optional[str] = None) -> str:
        """
        Generate report in specified format
        
        Args:
            findings: List of bucket findings
            format: Report format
            filename: Optional custom filename
            
        Returns:
            Path to generated report
        """
        if filename is None:
            filename = f"cloudvault_report_{self.report_id}.{format.value}"
        
        output_path = self.output_dir / filename
        
        if format == ReportFormat.JSON:
            self._generate_json_report(findings, output_path)
        
        elif format == ReportFormat.CSV:
            self._generate_csv_report(findings, output_path)
        
        elif format == ReportFormat.HTML:
            self._generate_html_report(findings, output_path)
        
        elif format == ReportFormat.MARKDOWN:
            self._generate_markdown_report(findings, output_path)
        
        elif format == ReportFormat.XML:
            self._generate_xml_report(findings, output_path)
        
        logger.info(f"Report generated: {output_path}")
        return str(output_path)
    
    def _generate_json_report(self, findings: List[Dict], output_path: Path):
        """Generate JSON report"""
        report = {
            'metadata': self._get_metadata(),
            'summary': self._get_summary(findings),
            'findings': findings
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
    
    def _generate_csv_report(self, findings: List[Dict], output_path: Path):
        """Generate CSV report"""
        if not findings:
            return
        
        # Extract all keys from findings
        fieldnames = set()
        for finding in findings:
            fieldnames.update(finding.keys())
        
        fieldnames = sorted(list(fieldnames))
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for finding in findings:
                # Flatten nested dicts
                flat_finding = self._flatten_dict(finding)
                writer.writerow(flat_finding)
    
    def _generate_html_report(self, findings: List[Dict], output_path: Path):
        """Generate HTML report"""
        summary = self._get_summary(findings)
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>CloudVault Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                   color: white; padding: 30px; border-radius: 10px; }}
        .summary {{ background: white; padding: 20px; margin: 20px 0; border-radius: 8px; 
                   box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .finding {{ background: white; margin: 10px 0; padding: 15px; border-radius: 8px;
                   border-left: 4px solid #667eea; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .critical {{ border-left-color: #dc3545; }}
        .high {{ border-left-color: #fd7e14; }}
        .medium {{ border-left-color: #ffc107; }}
        .low {{ border-left-color: #28a745; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #667eea; color: white; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #fd7e14; color: white; }}
        .badge-medium {{ background: #ffc107; color: black; }}
        .badge-low {{ background: #28a745; color: white; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ CloudVault Security Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Summary</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Total Buckets Found</td><td><strong>{summary['total_found']}</strong></td></tr>
            <tr><td>Public Buckets</td><td><strong>{summary['public_buckets']}</strong></td></tr>
            <tr><td>Sensitive Content</td><td><strong>{summary['interesting_buckets']}</strong></td></tr>
            <tr><td>Critical Issues</td><td><span class="badge badge-critical">{summary['critical_issues']}</span></td></tr>
            <tr><td>High Risk</td><td><span class="badge badge-high">{summary['high_risk']}</span></td></tr>
        </table>
    </div>
    
    <div class="findings-section">
        <h2>🔍 Detailed Findings</h2>
        {''.join([self._format_finding_html(f) for f in findings])}
    </div>
</body>
</html>
"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def _generate_markdown_report(self, findings: List[Dict], output_path: Path):
        """Generate Markdown report"""
        summary = self._get_summary(findings)
        
        md = f"""# 🛡️ CloudVault Security Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## 📊 Executive Summary

| Metric | Value |
|--------|-------|
| Total Buckets Found | **{summary['total_found']}** |
| Public Access | **{summary['public_buckets']}** |
| Sensitive Content | **{summary['interesting_buckets']}** |
| Critical Issues | 🚨 **{summary['critical_issues']}** |
| High Risk | 🔴 **{summary['high_risk']}** |

## 🔍 Detailed Findings

"""
        
        for finding in findings:
            md += self._format_finding_markdown(finding)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md)
    
    def _generate_xml_report(self, findings: List[Dict], output_path: Path):
        """Generate XML report"""
        import xml.etree.ElementTree as ET
        
        root = ET.Element("cloudvault_report")
        
        # Metadata
        metadata = ET.SubElement(root, "metadata")
        ET.SubElement(metadata, "generated").text = datetime.now().isoformat()
        ET.SubElement(metadata, "version").text = "2.0.0"
        
        # Summary
        summary = self._get_summary(findings)
        summary_elem = ET.SubElement(root, "summary")
        for key, value in summary.items():
            ET.SubElement(summary_elem, key).text = str(value)
        
        # Findings
        findings_elem = ET.SubElement(root, "findings")
        for finding in findings:
            finding_elem = ET.SubElement(findings_elem, "finding")
            for key, value in finding.items():
                ET.SubElement(finding_elem, key).text = str(value)
        
        tree = ET.ElementTree(root)
        tree.write(output_path, encoding='utf-8', xml_declaration=True)
    
    def _get_metadata(self) -> Dict:
        """Get report metadata"""
        return {
            'generated_at': datetime.now().isoformat(),
            'tool': 'CloudVault',
            'version': '2.0.0',
            'report_id': self.report_id
        }
    
    def _get_summary(self, findings: List[Dict]) -> Dict:
        """Generate summary statistics"""
        return {
            'total_found': len(findings),
            'public_buckets': sum(1 for f in findings if f.get('is_public', False)),
            'interesting_buckets': sum(1 for f in findings if f.get('has_interesting_content', False)),
            'critical_issues': sum(1 for f in findings if f.get('risk_level') == 'CRITICAL'),
            'high_risk': sum(1 for f in findings if f.get('risk_level') == 'HIGH'),
            'medium_risk': sum(1 for f in findings if f.get('risk_level') == 'MEDIUM'),
            'low_risk': sum(1 for f in findings if f.get('risk_level') == 'LOW')
        }
    
    def _flatten_dict(self, d: Dict, parent_key: str = '', sep: str = '_') -> Dict:
        """Flatten nested dictionary"""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                items.append((new_key, ', '.join(map(str, v))))
            else:
                items.append((new_key, v))
        return dict(items)
    
    def _format_finding_html(self, finding: Dict) -> str:
        """Format single finding as HTML"""
        risk = finding.get('risk_level', 'LOW').lower()
        return f"""
        <div class="finding {risk}">
            <h3>{finding.get('bucket_url', 'Unknown')}</h3>
            <p><strong>Provider:</strong> {finding.get('provider', 'Unknown').upper()}</p>
            <p><strong>Access Level:</strong> {finding.get('access_level', 'Unknown')}</p>
            <p><strong>Risk:</strong> <span class="badge badge-{risk}">{finding.get('risk_level', 'Unknown')}</span></p>
        </div>
        """
    
    def _format_finding_markdown(self, finding: Dict) -> str:
        """Format single finding as Markdown"""
        risk_emoji = {'CRITICAL': '🚨', 'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}
        risk = finding.get('risk_level', 'LOW')
        
        return f"""
### {risk_emoji.get(risk, '❓')} {finding.get('bucket_url', 'Unknown')}

- **Provider:** {finding.get('provider', 'Unknown').upper()}
- **Access Level:** {finding.get('access_level', 'Unknown')}
- **Risk Level:** {risk}
- **Owner:** {finding.get('owner', 'Unknown')}

---

"""
