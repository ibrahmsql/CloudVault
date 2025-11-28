"""History Module - Scan History and Trend Tracking"""

from .database import init_database, save_scan, get_scan_history, get_trends
from .tracker import track_scan, compare_scans
from .visualizer import visualize_trends, render_history_tree

__all__ = [
    'init_database',
    'save_scan',
    'get_scan_history',
    'get_trends',
    'track_scan',
    'compare_scans',
    'visualize_trends',
    'render_history_tree'
]
