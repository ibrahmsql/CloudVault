"""
Configuration helper functions for CloudVault CLI
Handles config file creation and management
"""
from termcolor import cprint
from ..core.config import Config


def create_default_config():
    """
    Create a default configuration file
    
    Returns:
        bool: True if successful, False otherwise
    """
    config_path = "config.yaml"
    try:
        Config.create_default_config(config_path)
        cprint(f"Default configuration created: {config_path}", "green")
        cprint("Please edit the configuration file and add your cloud credentials.", "yellow")
        return True
    except Exception as e:
        cprint(f"Error creating default config: {e}", "red")
        return False
