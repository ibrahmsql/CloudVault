# CloudVault - Multi-Cloud Storage Security Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![GitHub Actions](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF)](https://github.com/features/actions)

> **Enterprise-grade cloud storage security scanner with advanced attack chain analysis, MITRE ATT&CK mapping, and comprehensive reporting**

CloudVault discovers exposed AWS S3, Google Cloud Storage, and Azure Blob containers through certificate transparency monitoring and provides actionable security insights with tree-formatted visualizations.

## 🚀 Features

### Core Capabilities
- 🔍 **Real-time Discovery** - Certificate transparency log monitoring
- ☁️ **Multi-Provider** - AWS S3, GCP Storage, Azure Blob
- 🎯 **Smart Detection** - Automated permission checking
- 📊 **Risk Scoring** - Advanced multi-factor algorithm (0-100)
- 🔗 **Attack Chains** - Multi-hop privilege escalation paths
- 🎨 **Tree Visualizations** - Beautiful ASCII output everywhere

### Advanced Features (Beyond Heimdall)
- 🔔 **Alerts** - Slack, Discord, Email notifications
- 🔍 **Advanced Filtering** - Boolean logic + regex queries
- 📈 **Historical Tracking** - SQLite database with trend sparklines
- 🔧 **Auto-Remediation** - Terraform/AWS CLI script generation
- 🌐 **Trust Graphs** - Relationship visualization
- 📋 **Compliance** - CIS Benchmarks, PCI-DSS mapping
- 🎨 **Interactive TUI** - Textual framework interface
- 📤 **Multi-Format Export** - SARIF, CSV, JSON, HTML, ASCII Tree

## 📦 Installation

```bash
# Clone repository
git clone https://github.com/yourusername/CloudVault.git
cd CloudVault

# Install dependencies
pip install -e .

# Install optional dependencies
pip install aiosqlite websockets  # For history & real-time scanning
```

## 🎯 Quick Start

### Basic Scan (Static Domain List)

```bash
# Create domain list
echo "example.com" > domains.txt
echo "company.com" >> domains.txt

# Scan
cloudvault scan --source domains.txt --output findings.json
```

### Real-Time Monitoring (Certificate Transparency)

```bash
# Monitor CT logs
cloudvault scan --only-interesting --save-history

# With keywords filter
cloudvault scan --keywords-file keywords.txt

# With alerts
cloudvault scan \
  --notify slack \
  --slack-webhook https://hooks.slack.com/... \
  --alert-on critical,high
```

### Dashboard & Analysis

```bash
# Security dashboard
cloudvault dashboard -i findings.json

# With filters
cloudvault dashboard -i findings.json \
  --filter "severity=CRITICAL,HIGH" \
  --only-public \
  --min-risk-score 75

# Attack chain analysis
cloudvault analyze -i findings.json -f tree

# Filter before analysis
cloudvault analyze -i findings.json \
  --filter "provider=aws" \
  --min-blast-radius 70
```

### Export & Reporting

```bash
# SARIF for GitHub Security
cloudvault export -i findings.json -f sarif -o report.sarif

# HTML report
cloudvault export -i findings.json -f html -o report.html

# Tree visualization
cloudvault export -i findings.json -f tree -o report.txt

# CSV for spreadsheets
cloudvault export -i findings.json -f csv -o report.csv
```

### Auto-Remediation

```bash
# Generate Terraform
cloudvault remediate -i findings.json -f terraform --dry-run

# Generate AWS CLI commands
cloudvault remediate -i findings.json -f awscli
```

### Compliance Audit

```bash
# CIS Benchmarks
cloudvault compliance -i findings.json --framework CIS

# PCI-DSS
cloudvault compliance -i findings.json --framework PCI-DSS
```

### History & Trends

```bash
# View scan history
cloudvault history list --limit 20

# Trend analysis with sparklines
cloudvault history trends --days 30

# Compare scans
cloudvault history compare --from-scan 1 --to-scan 5
```

## 📋 Commands Reference

| Command | Description |
|---------|-------------|
| `scan` | Discover exposed buckets (CT logs or domain list) |
| `dashboard` | Security overview with risk scoring |
| `analyze` | Attack chain and privilege escalation analysis |
| `export` | Multi-format export (SARIF/CSV/JSON/HTML/Tree) |
| `remediate` | Generate auto-fix scripts (Terraform/AWS CLI) |
| `compliance` | Framework mapping (CIS/PCI-DSS/HIPAA) |
| `history` | Scan history, trends, and comparison |
| `graph` | Trust relationship visualization |
| `tui` | Interactive terminal UI |
| `baseline` | Delta reporting and ignore patterns |
| `test-alerts` | Test notification channels |
| `init-config` | Create default configuration |

## 🔧 Advanced Usage

### Filtering Syntax

```bash
# Equality
--filter "severity=CRITICAL"

# Multiple values (OR)
--filter "severity=CRITICAL,HIGH"

# Comparison operators
--filter "risk_score>=75"

# Regex
--filter "bucket_name~regex:.*-prod-.*"

# Boolean AND
--filter "severity=CRITICAL AND provider=aws"

# Exclude
--exclude "bucket_name~.*-test-.*"

# Combine filters
--filter "severity=CRITICAL,HIGH" \
--only-public \
--min-risk-score 80
```

### Alert Configuration

```bash
# Slack
--notify slack \
--slack-webhook https://hooks.slack.com/... \
--alert-on critical,high

# Discord
--notify discord \
--discord-webhook https://discord.com/api/webhooks/...

# Email (SMTP)
--notify email \
--email-to security@company.com \
--smtp-host smtp.gmail.com \
--smtp-user alerts@company.com \
--smtp-password "..."

# Multiple channels
--notify slack discord email
```

### CI/CD Integration

```yaml
# .github/workflows/cloudvault.yml
- name: Run CloudVault
  run: |
    cloudvault scan --source domains.txt --output findings.json
    cloudvault export -i findings.json -f sarif -o cloudvault.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: cloudvault.sarif
```

## 📊 Output Examples

### Dashboard
```
╔═══════════════════════════════════════════════════════════╗
║                  CloudVault Dashboard                     ║
║              Cloud Security Risk Analysis                 ║
╚═══════════════════════════════════════════════════════════╝

╔════ Security Risk Score ═════╗
║ Risk Score: 64.0/100         ║
║ Status: HIGH                 ║
╚══════════════════════════════╝

      Findings by Severity      
  CRITICAL: 2 (40.0%)  ████████
  HIGH:     2 (40.0%)  ████████
  MEDIUM:   1 (20.0%)  ████

Top Security Risks:
  1. Public S3 Bucket with Sensitive Data
  2. Credentials in Bucket Objects
  3. Database Dump Exposure
```

### Attack Chain Analysis
```
Multi-Hop Privilege Escalation (Blast Radius: 90.0)
├── Access Public Bucket (T1530)
├── Extract Credentials (T1552.001)
├── Authenticate with Stolen Credentials (T1078)
└── Exfiltrate Sensitive Data (T1537)
```

### Compliance Report
```
📋 CIS Compliance Report
============================================================

├─ Total Controls: 2
├─ ✓ Passed: 0
└─ ✗ Failed: 4

├─ CIS-2.1.5: Ensure S3 buckets are not publicly accessible
   └─ ✗ company-prod-backups
```

## 🏗️ Architecture

```
cloudvault_discovery/
├── cli/              # Click command-line interface
├── core/             # Scanning engine (certstream, scanner)
├── models/           # Data models (Finding, AttackChain)
├── analysis/         # Risk scoring, MITRE mapping, attack chains
├── dashboard/        #Rich visualization and metrics
├── export/           # Multi-format exporters
├── alerts/           # Notification channels
├── filtering/        # Advanced query parser
├── history/          # SQLite database & trends
├── remediation/      # Auto-fix templates
├── compliance/       # Framework mappers
├── graph/            # Trust visualization
└── tui/              # Textual UI
```

## 🧪 Testing

```bash
# Run tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=cloudvault_discovery
```

## 📝 Configuration

```yaml
# config.yaml
scan:
  providers:
    aws: true
    gcp: true
    azure: true
  skip_lets_encrypt: true
  
alerts:
  slack_webhook: "https://hooks.slack.com/..."
  severity_filter: ["CRITICAL", "HIGH"]

filters:
  exclude_patterns:
    - "*-test-*"
    - "*-dev-*"
```

## 🤝 Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- Inspired by [Heimdall](https://github.com/DenizParlak/heimdall)
- Certificate transparency via [Certstream](https://certstream.calidog.io/)
- MITRE ATT&CK Framework

## 📞 Support

- 🐛 [Report bugs](https://github.com/yourusername/CloudVault/issues)
- 💡 [Request features](https://github.com/yourusername/CloudVault/issues)
- 📖 [Documentation](https://cloudvault.readthedocs.io/)

---

**Made with ❤️ for cloud security**
