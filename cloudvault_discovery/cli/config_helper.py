"""
Configuration helper functions
"""

from pathlib import Path
from rich.console import Console
import yaml

console = Console()


def create_default_config():
    """
    Create a default configuration file
    
    Returns:
        bool: True if successful, False otherwise
    """
    config_path = "config.yaml"
    
    default_config = {
        'scan': {
            'providers': {
                'aws': True,
                'gcp': True,
                'azure': True
            },
            'skip_lets_encrypt': True,
            'only_interesting': False
        },
        'alerts': {
            'enabled': False
        }
    }
    
    try:
        with open(config_path, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False)
        
        console.print(f"[green]✓[/green] Created default configuration: {config_path}")
        console.print("[yellow]Please edit the configuration file as needed.[/yellow]")
        return True
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")
        return False
