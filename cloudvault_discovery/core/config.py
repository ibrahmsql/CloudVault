"""
Config loading utilities for new CLI
"""

import yaml
from pathlib import Path
from types import SimpleNamespace


def load_config(config_path: str) -> SimpleNamespace:
    """
    Load configuration from YAML file.
    
    Args:
        config_path: Path to config file
        
    Returns:
        Configuration object
    """
    config_file = Path(config_path)
    
    if not config_file.exists():
        # Return default config
        return _get_default_config()
    
    try:
        with open(config_file, 'r') as f:
            config_dict = yaml.safe_load(f) or {}
        
        # Convert dict to SimpleNamespace recursively
        return _dict_to_namespace(config_dict)
    except Exception as e:
        print(f"Error loading config: {e}")
        return _get_default_config()


def _dict_to_namespace(d: dict) -> SimpleNamespace:
    """Convert dictionary to SimpleNamespace recursively"""
    if not isinstance(d, dict):
        return d
    
    namespace = SimpleNamespace()
    for key, value in d.items():
        if isinstance(value, dict):
            setattr(namespace, key, _dict_to_namespace(value))
        else:
            setattr(namespace, key, value)
    
    return namespace


def _get_default_config() -> SimpleNamespace:
    """Get default configuration"""
    return SimpleNamespace(
        queue_size=1000,
        update_interval=30,
        log_level="INFO",
        only_interesting=False,
        skip_lets_encrypt=True,
        log_to_file=False,
        aws=SimpleNamespace(
            enabled=True,
            max_threads=20,
            region='us-east-1'
        ),
        gcp=SimpleNamespace(
            enabled=True,
            max_threads=15
        ),
        azure=SimpleNamespace(
            enabled=True,
            max_threads=15
        )
    )


__all__ = ['load_config']
