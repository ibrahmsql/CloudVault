"""Dashboard module initialization"""

from .generator import generate_dashboard_data
from .renderer import render_dashboard

__all__ = ['generate_dashboard_data', 'render_dashboard']
