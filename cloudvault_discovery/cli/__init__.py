"""
CloudVault CLI Module
Provides the command-line interface for CloudVault bucket discovery tool.
"""
import sys
from termcolor import cprint
from .app import CloudVaultDiscovery
from .arguments import create_argument_parser
from .config_helper import create_default_config

__all__ = ['main', 'CloudVaultDiscovery']


def main():
    """Main entry point for CloudVault CLI"""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Handle --init-config flag
    if args.init_config:
        if create_default_config():
            sys.exit(0)
        else:
            sys.exit(1)
    
    # Create and configure application
    app = CloudVaultDiscovery()
    
    # Load configuration
    if not app.load_config(args.config):
        sys.exit(1)
    
    # Apply command-line overrides
    _apply_config_overrides(app, args)
    
    try:
        app.initialize_components(args)
        app.run(args)
    except KeyboardInterrupt:
        cprint("\nInterrupted by user", "yellow")
    except Exception as e:
        cprint(f"Fatal error: {e}", "red")
        import logging
        logging.getLogger(__name__).exception("Fatal error occurred")
        sys.exit(1)


def _apply_config_overrides(app, args):
    """Apply command-line argument overrides to configuration"""
    if args.only_interesting:
        app.config.only_interesting = True
    if args.skip_lets_encrypt:
        app.config.skip_lets_encrypt = True
    if args.log_to_file:
        app.config.log_to_file = True
    if args.verbose:
        app.config.log_level = "DEBUG"
    
    # Provider filtering
    if args.aws_only:
        app.config.gcp.enabled = False
        app.config.azure.enabled = False
    elif args.gcp_only:
        app.config.aws.enabled = False
        app.config.azure.enabled = False
    elif args.azure_only:
        app.config.aws.enabled = False
        app.config.gcp.enabled = False


if __name__ == "__main__":
    main()
