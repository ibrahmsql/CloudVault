"""
Remediation Templates Module
Auto-generate remediation scripts
"""

from typing import Dict, Any, List


TERRAFORM_TEMPLATE_S3_PRIVATE = '''
# Make S3 bucket private
resource "aws_s3_bucket_public_access_block" "{bucket_name}_block" {{
  bucket = "{bucket_name}"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}
'''

AWS_CLI_TEMPLATE_S3_PRIVATE = '''
# Remove public access from S3 bucket
aws s3api put-public-access-block \\
  --bucket {bucket_name} \\
  --public-access-block-configuration \\
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
'''


def generate_remediation(finding: Dict[str, Any], format: str = 'terraform') -> str:
    """
    Generate remediation script for finding.
    
    Args:
        finding: Finding dictionary
        format: Output format ('terraform', 'awscli', 'policy')
        
    Returns:
        Remediation script
    """
    provider = finding.get('provider', '').lower()
    bucket_name = finding.get('bucket_name', 'BUCKET_NAME')
    
    if provider == 'aws':
        if format == 'terraform':
            return TERRAFORM_TEMPLATE_S3_PRIVATE.format(bucket_name=bucket_name)
        elif format == 'awscli':
            return AWS_CLI_TEMPLATE_S3_PRIVATE.format(bucket_name=bucket_name)
    
    return "# No remediation template available"


def generate_remediation_tree(findings: List[Dict[str, Any]], format: str = 'terraform') -> str:
    """Generate tree-formatted remediation suggestions"""
    lines = []
    lines.append(f"🔧 Auto-Remediation ({format.upper()})")
    lines.append("=" * 60)
    lines.append("")
    
    for i, finding in enumerate(findings[:5]):  # Limit to 5
        is_last = (i == len(findings[:5]) - 1)
        prefix = "└─" if is_last else "├─"
        detail_prefix = "   " if is_last else "│  "
        
        title = finding.get('title', 'Unknown')
        severity = finding.get('severity', 'INFO')
        
        lines.append(f"{prefix} [{severity}] {title}")
        lines.append(f"{detail_prefix}")
        
        # Generate script
        script = generate_remediation(finding, format)
        for line in script.strip().split('\n'):
            lines.append(f"{detail_prefix}{line}")
        
        if not is_last:
            lines.append("│")
    
    return "\n".join(lines)


__all__ = ['generate_remediation', 'generate_remediation_tree']
