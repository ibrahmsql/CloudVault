"""
Stealth system management for CloudVault CLI
Coordinates stealth, evasion, and anti-forensics features
"""
from ..core.stealth import StealthSession, DistributedScanner, AntiDetection
from ..core.network import NetworkObfuscator, TrafficShaping, GeoEvasion
from ..core.forensics import (
    EvidenceShredder, ProcessObfuscation, AntiAnalysis, 
    LogManipulator, NetworkFootprintReducer
)


class StealthManager:
    """Manages all stealth and evasion components"""
    
    def __init__(self):
        self.components = {}
        self._active = False
    
    def initialize(self, args):
        """
        Initialize stealth systems based on arguments
        
        Args:
            args: Parsed command-line arguments
        """
        # Anti-forensics systems
        if getattr(args, 'anti_forensics', False):
            self.components['evidence_shredder'] = EvidenceShredder()
            self.components['log_manipulator'] = LogManipulator()
            print("[STEALTH] Anti-forensics systems activated")
            self._active = True
        
        # Process masking
        if getattr(args, 'process_masking', False):
            self.components['process_obfuscator'] = ProcessObfuscation()
            self.components['process_obfuscator'].mask_process_name()
            self.components['decoy_processes'] = self.components['process_obfuscator'].create_decoy_processes()
            print("[STEALTH] Process masking enabled")
            self._active = True
        
        # Full stealth mode
        if getattr(args, 'stealth', False):
            self._initialize_full_stealth(args)
            self._active = True
    
    def _initialize_full_stealth(self, args):
        """Initialize full stealth mode with all features"""
        # Anti-analysis
        self.components['anti_analysis'] = AntiAnalysis()
        if self.components['anti_analysis'].detect_virtualization():
            print("[STEALTH] Virtualization detected - activating countermeasures")
            self.components['anti_analysis'].anti_debugging_sleep()
        
        # Network stealth
        self.components['stealth_session'] = StealthSession()
        self.components['network_obfuscator'] = NetworkObfuscator()
        self.components['traffic_shaping'] = TrafficShaping()
        self.components['traffic_shaping'].set_profile(
            getattr(args, 'traffic_shaping', 'residential')
        )
        
        # Geo evasion
        self.components['geo_evasion'] = GeoEvasion()
        self.components['geo_evasion'].set_exit_country(
            getattr(args, 'geo_country', 'US')
        )
        
        # Proxy rotation
        if getattr(args, 'proxy_rotation', False):
            self.components['distributed_scanner'] = DistributedScanner()
            self.components['distributed_scanner'].setup_infrastructure()
            print("[STEALTH] Proxy rotation and distributed scanning enabled")
        
        # Network footprint reduction
        self.components['network_reducer'] = NetworkFootprintReducer()
        cover_thread = self.components['network_reducer'].generate_cover_traffic()
        self.components['cover_traffic_thread'] = cover_thread
        
        country = getattr(args, 'geo_country', 'US')
        profile = getattr(args, 'traffic_shaping', 'residential')
        print(f"[STEALTH] Full stealth mode activated - Country: {country}, Profile: {profile}")
    
    def is_active(self) -> bool:
        """Check if stealth mode is active"""
        return self._active
    
    def has_log_manipulator(self) -> bool:
        """Check if log manipulator is available"""
        return 'log_manipulator' in self.components
    
    def suppress_logging(self):
        """Suppress logging if log manipulator is available"""
        if 'log_manipulator' in self.components:
            self.components['log_manipulator'].suppress_logging()
    
    def cleanup(self):
        """Cleanup all stealth components"""
        if not self.components:
            return
        
        # Evidence elimination
        if 'evidence_shredder' in self.components:
            self.components['evidence_shredder'].emergency_cleanup()
            print("[STEALTH] Evidence elimination completed")
        
        # Decoy processes
        if 'decoy_processes' in self.components and 'process_obfuscator' in self.components:
            self.components['process_obfuscator'].cleanup_decoy_processes(
                self.components['decoy_processes']
            )
            print("[STEALTH] Decoy processes terminated")
        
        # Logging restoration
        if 'log_manipulator' in self.components:
            self.components['log_manipulator'].restore_logging()
            print("[STEALTH] Logging restored")
        
        # Cover traffic
        if 'cover_traffic_thread' in self.components:
            print("[STEALTH] Background cover traffic terminated")
