"""
HTML Export Format
Interactive web report with charts
"""

from typing import List, Dict, Any
from datetime import datetime


def export_html(findings: List[Dict[str, Any]], output_path: str):
    """
    Export findings as HTML report.
    
    Args:
        findings: List of finding dictionaries
        output_path: Path to output HTML file
    """
    # Calculate statistics
    total = len(findings)
    severity_counts = _count_severities(findings)
    provider_counts = _count_providers(findings)
    public_count = sum(1 for f in findings if f.get('is_public', False))
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudVault Security Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        header p {{ opacity: 0.9; }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .stat-card h3 {{ color: #666; font-size: 0.9em; margin-bottom: 10px; }}
        .stat-card .number {{ font-size: 2.5em; font-weight: bold; color: #2a5298; }}
        .findings {{
            padding: 30px;
        }}
        .finding {{
            background: white;
            border-left: 4px solid #ddd;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .finding.critical {{ border-left-color: #dc3545; }}
        .finding.high {{ border-left-color: #fd7e14; }}
        .finding.medium {{ border-left-color: #ffc107; }}
        .finding.low {{ border-left-color: #0dcaf0; }}
        .finding.info {{ border-left-color: #6c757d; }}
        .finding h3 {{ margin-bottom: 10px; color: #333; }}
        .finding .meta {{ display: flex; gap: 15px; margin: 10px 0; flex-wrap: wrap; }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }}
        .badge.critical {{ background: #dc3545; color: white; }}
        .badge.high {{ background: #fd7e14; color: white; }}
        .badge.medium {{ background: #ffc107; color: #333; }}
        .badge.low {{ background: #0dcaf0; color: white; }}
        .badge.info {{ background: #6c757d; color: white; }}
        .badge.provider {{ background: #e9ecef; color: #495057; }}
        footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #dee2e6;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ CloudVault Security Report</h1>
            <p>Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
        </header>
        
        <div class="summary">
            <div class="stat-card">
                <h3>Total Findings</h3>
                <div class="number">{total}</div>
            </div>
            <div class="stat-card">
                <h3>Public Buckets</h3>
                <div class="number" style="color: #dc3545;">{public_count}</div>
            </div>
            <div class="stat-card">
                <h3>Critical Issues</h3>
                <div class="number" style="color: #dc3545;">{severity_counts.get('CRITICAL', 0)}</div>
            </div>
            <div class="stat-card">
                <h3>High Severity</h3>
                <div class="number" style="color: #fd7e14;">{severity_counts.get('HIGH', 0)}</div>
            </div>
        </div>
        
        <div class="findings">
            <h2 style="margin-bottom: 20px; color: #333;">Findings</h2>
"""
    
    # Add findings
    for finding in findings:
        severity = finding.get('severity', 'INFO').lower()
        title = finding.get('title', 'Unknown Finding')
        description = finding.get('description', 'No description available')
        provider = finding.get('provider', 'unknown').upper()
        bucket_name = finding.get('bucket_name', 'N/A')
        is_public = finding.get('is_public', False)
        mitre = ', '.join(finding.get('mitre_techniques', []))
        
        html += f"""
            <div class="finding {severity}">
                <h3>{title}</h3>
                <p>{description}</p>
                <div class="meta">
                    <span class="badge {severity}">{severity.upper()}</span>
                    <span class="badge provider">{provider}</span>
                    <span class="badge provider">{bucket_name}</span>
                    {f'<span class="badge critical">PUBLIC</span>' if is_public else ''}
                    {f'<span class="badge provider">MITRE: {mitre}</span>' if mitre else ''}
                </div>
            </div>
"""
    
    html += """
        </div>
        
        <footer>
            <p>CloudVault v1.0.1 - Cloud Security Scanner</p>
            <p>For more information, visit <a href="https://github.com/ibrahmsql/CloudVault">GitHub</a></p>
        </footer>
    </div>
</body>
</html>
"""
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)


def _count_severities(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count findings by severity"""
    counts = {}
    for finding in findings:
        sev = finding.get('severity', 'INFO').upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _count_providers(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count findings by provider"""
    counts = {}
    for finding in findings:
        provider = finding.get('provider', 'unknown').upper()
        counts[provider] = counts.get(provider, 0) + 1
    return counts


__all__ = ['export_html']
