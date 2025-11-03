"""
Argument parser configuration for CloudVault CLI
Defines all command-line arguments and options
"""
import argparse


def create_argument_parser():
    """Create and configure the argument parser for CloudVault"""
    parser = argparse.ArgumentParser(
        description="CloudVault - Multi-cloud storage bucket discovery via certificate transparency",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  cloudvault                              # Monitor certificate transparency logs
  cloudvault --source domains.txt        # Process static domain list
  cloudvault --only-interesting          # Only report buckets with interesting content
  cloudvault --init-config               # Create default configuration
        """
    )
    
    # Configuration
    config_group = parser.add_argument_group('Configuration')
    config_group.add_argument(
        "-c", "--config", 
        default="config.yaml",
        help="Configuration file path (default: config.yaml)"
    )
    config_group.add_argument(
        "--init-config", 
        action="store_true",
        help="Create a default configuration file and exit"
    )
    
    # Input sources
    input_group = parser.add_argument_group('Input')
    input_group.add_argument(
        "-s", "--source",
        help="Static domain list file instead of live certificate stream"
    )
    input_group.add_argument(
        "-p", "--permutations",
        help="Permutation patterns file (overrides config)"
    )
    input_group.add_argument(
        "--keywords-file",
        help="Keywords file for interesting content detection (overrides config)"
    )
    
    # Worker configuration
    worker_group = parser.add_argument_group('Workers')
    worker_group.add_argument(
        "-t", "--threads", 
        type=int,
        help="Override number of worker threads per provider"
    )
    
    # Filtering options
    filter_group = parser.add_argument_group('Filtering')
    filter_group.add_argument(
        "--only-interesting", 
        action="store_true",
        help="Only report buckets with interesting content"
    )
    filter_group.add_argument(
        "--skip-lets-encrypt", 
        action="store_true",
        help="Skip certificates issued by Let's Encrypt"
    )
    
    # Output options
    output_group = parser.add_argument_group('Output')
    output_group.add_argument(
        "-l", "--log-to-file", 
        action="store_true",
        help="Log found buckets to file"
    )
    output_group.add_argument(
        "-v", "--verbose", 
        action="store_true",
        help="Enable verbose logging"
    )
    
    # Provider selection
    provider_group = parser.add_argument_group('Providers')
    provider_group.add_argument(
        "--aws-only", 
        action="store_true",
        help="Only check AWS S3 buckets"
    )
    provider_group.add_argument(
        "--gcp-only", 
        action="store_true",
        help="Only check Google Cloud Storage buckets"
    )
    provider_group.add_argument(
        "--azure-only", 
        action="store_true",
        help="Only check Azure Blob Storage containers"
    )
    
    # Advanced features
    advanced_group = parser.add_argument_group('Advanced Features')
    advanced_group.add_argument(
        "--download", 
        action="store_true",
        help="Enable real-time bucket content downloading and analysis"
    )
    advanced_group.add_argument(
        "--exploit", 
        action="store_true",
        help="Enable credential exploitation and validation"
    )
    advanced_group.add_argument(
        "--exploit-timeout", 
        type=int, 
        default=300,
        help="Exploitation timeout in seconds (default: 300)"
    )
    
    # Stealth options
    stealth_group = parser.add_argument_group('Stealth Options')
    stealth_group.add_argument(
        "--stealth", 
        action="store_true",
        help="Enable advanced stealth and evasion techniques"
    )
    stealth_group.add_argument(
        "--proxy-rotation", 
        action="store_true",
        help="Enable proxy rotation for anonymity"
    )
    stealth_group.add_argument(
        "--traffic-shaping",
        choices=['residential', 'mobile', 'corporate', 'satellite'],
        default='residential',
        help="Traffic pattern simulation (default: residential)"
    )
    stealth_group.add_argument(
        "--geo-country", 
        type=str, 
        default='US',
        help="Geographic location simulation (default: US)"
    )
    stealth_group.add_argument(
        "--anti-forensics", 
        action="store_true",
        help="Enable evidence elimination and anti-forensics"
    )
    stealth_group.add_argument(
        '--process-masking', 
        action='store_true',
        help='Enable process masking to hide from monitoring tools'
    )
    
    # Database testing
    db_group = parser.add_argument_group('Database Testing')
    db_group.add_argument(
        '--db-wordlist', 
        type=str,
        help='Wordlist file for database brute-forcing'
    )
    
    return parser
