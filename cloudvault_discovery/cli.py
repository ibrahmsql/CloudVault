#!/usr/bin/env python3
"""
CloudVault CLI - Main Entry Point
Legacy compatibility wrapper that imports from new modular cli package

This file maintains backward compatibility while using the new modular structure:
- cli/app.py - Main application class
- cli/arguments.py - Command-line argument parsing
- cli/handlers.py - Result handling and notifications
- cli/stats.py - Statistics and reporting  
- cli/stealth.py - Stealth system management
- cli/config_helper.py - Configuration helpers
"""

# Import main entry point from new modular CLI package
from .cli import main

# For backward compatibility, expose key components
from .cli.app import CloudVaultDiscovery
from .cli.config_helper import create_default_config

__all__ = ['main', 'CloudVaultDiscovery', 'create_default_config']

# Entry point
if __name__ == "__main__":
    main()
