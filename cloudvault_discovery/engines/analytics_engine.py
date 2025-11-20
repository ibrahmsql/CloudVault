"""
Advanced Analytics Engine
Real-time metrics, statistics, and trend analysis
"""
import logging
from typing import List, Dict, Optional
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import json

logger = logging.getLogger(__name__)


class AnalyticsEngine:
    """
    Advanced analytics with real-time dashboards and trends
    """
    
    def __init__(self):
        """Initialize analytics engine"""
        self.metrics = defaultdict(lambda: defaultdict(int))
        self.time_series = defaultdict(list)
        self.provider_stats = defaultdict(dict)
        self.session_start = datetime.now()
        logger.info("Analytics engine initialized")
    
    def record_finding(self, finding: Dict):
        """
        Record a finding for analytics
        
        Args:
            finding: Bucket finding dictionary
        """
        provider = finding.get('provider', 'unknown')
        risk_level = finding.get('risk_level', 'LOW')
        
        # Update counters
        self.metrics[provider]['total'] += 1
        self.metrics[provider][risk_level.lower()] += 1
        
        if finding.get('is_public'):
            self.metrics[provider]['public'] += 1
        
        if finding.get('has_interesting_content'):
            self.metrics[provider]['sensitive'] += 1
        
        # Time series data
        self.time_series[provider].append({
            'timestamp': datetime.now().isoformat(),
            'risk_level': risk_level,
            'is_public': finding.get('is_public', False)
        })
    
    def get_summary(self) -> Dict:
        """Get analytics summary"""
        total_findings = sum(p['total'] for p in self.metrics.values())
        
        return {
            'session_duration': str(datetime.now() - self.session_start),
            'total_findings': total_findings,
            'by_provider': dict(self.metrics),
            'by_risk_level': self._aggregate_by_risk(),
            'public_exposure_rate': self._calculate_exposure_rate(),
            'sensitive_data_rate': self._calculate_sensitive_rate(),
            'top_risks': self._get_top_risks()
        }
    
    def get_trends(self, provider: Optional[str] = None) -> Dict:
        """
        Get trend analysis
        
        Args:
            provider: Optional provider filter
            
        Returns:
            Trend analysis
        """
        if provider:
            data = self.time_series.get(provider, [])
        else:
            data = [item for items in self.time_series.values() for item in items]
        
        if not data:
            return {'trend': 'insufficient_data'}
        
        # Analyze last hour
        one_hour_ago = datetime.now() - timedelta(hours=1)
        recent = [
            item for item in data
            if datetime.fromisoformat(item['timestamp']) > one_hour_ago
        ]
        
        if len(recent) < 2:
            return {'trend': 'insufficient_data'}
        
        # Calculate trend
        critical_count = sum(1 for item in recent if item['risk_level'] == 'CRITICAL')
        high_count = sum(1 for item in recent if item['risk_level'] == 'HIGH')
        
        trend = {
            'findings_per_hour': len(recent),
            'critical_per_hour': critical_count,
            'high_per_hour': high_count,
            'public_exposure_trend': sum(1 for item in recent if item.get('is_public', False)),
            'trend_direction': 'increasing' if len(recent) > len(data) / 2 else 'stable'
        }
        
        return trend
    
    def get_provider_comparison(self) -> Dict:
        """Compare providers"""
        comparison = {}
        
        for provider, stats in self.metrics.items():
            total = stats['total']
            if total == 0:
                continue
            
            comparison[provider] = {
                'total_buckets': total,
                'public_rate': round((stats['public'] / total) * 100, 2),
                'sensitive_rate': round((stats['sensitive'] / total) * 100, 2),
                'critical_rate': round((stats.get('critical', 0) / total) * 100, 2),
                'high_rate': round((stats.get('high', 0) / total) * 100, 2),
                'security_score': self._calculate_security_score(stats, total)
            }
        
        return comparison
    
    def get_risk_distribution(self) -> Dict:
        """Get risk level distribution"""
        distribution = Counter()
        
        for provider_stats in self.metrics.values():
            for risk_level in ['critical', 'high', 'medium', 'low']:
                distribution[risk_level] += provider_stats.get(risk_level, 0)
        
        total = sum(distribution.values())
        
        if total == 0:
            return {}
        
        return {
            level: {
                'count': count,
                'percentage': round((count / total) * 100, 2)
            }
            for level, count in distribution.items()
        }
    
    def get_hotspots(self) -> List[Dict]:
        """Identify security hotspots"""
        hotspots = []
        
        for provider, stats in self.metrics.items():
            critical = stats.get('critical', 0)
            high = stats.get('high', 0)
            
            if critical > 0 or high > 3:
                hotspots.append({
                    'provider': provider,
                    'critical_issues': critical,
                    'high_issues': high,
                    'severity': 'CRITICAL' if critical > 0 else 'HIGH',
                    'recommendation': f'Immediate review required for {provider}'
                })
        
        return sorted(hotspots, key=lambda x: (x['critical_issues'], x['high_issues']), reverse=True)
    
    def generate_dashboard(self) -> str:
        """Generate ASCII dashboard"""
        summary = self.get_summary()
        
        dashboard = f"""
╔══════════════════════════════════════════════════════════════╗
║            CloudVault Analytics Dashboard                    ║
╠══════════════════════════════════════════════════════════════╣
║ Session Duration: {summary['session_duration']:<42} ║
║ Total Findings:   {summary['total_findings']:<42} ║
╠══════════════════════════════════════════════════════════════╣
║                    Risk Distribution                         ║
╠══════════════════════════════════════════════════════════════╣
"""
        
        risk_dist = self.get_risk_distribution()
        for level, data in risk_dist.items():
            bar = '█' * int(data['percentage'] / 2)
            dashboard += f"║ {level.upper():<10} {data['count']:>4} │ {bar:<25} {data['percentage']:>5.1f}% ║\n"
        
        dashboard += f"""╠══════════════════════════════════════════════════════════════╣
║                   Provider Statistics                        ║
╠══════════════════════════════════════════════════════════════╣
"""
        
        for provider, stats in self.metrics.items():
            dashboard += f"║ {provider.upper():<10} Total: {stats['total']:>4} │ Public: {stats['public']:>4} │ Sensitive: {stats['sensitive']:>4} ║\n"
        
        dashboard += "╚══════════════════════════════════════════════════════════════╝\n"
        
        return dashboard
    
    def export_analytics(self, filename: str):
        """Export analytics data"""
        data = {
            'generated_at': datetime.now().isoformat(),
            'summary': self.get_summary(),
            'trends': self.get_trends(),
            'comparison': self.get_provider_comparison(),
            'distribution': self.get_risk_distribution(),
            'hotspots': self.get_hotspots()
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        logger.info(f"Analytics exported to {filename}")
    
    def _aggregate_by_risk(self) -> Dict:
        """Aggregate findings by risk level"""
        aggregated = Counter()
        
        for provider_stats in self.metrics.values():
            for risk_level in ['critical', 'high', 'medium', 'low']:
                aggregated[risk_level] += provider_stats.get(risk_level, 0)
        
        return dict(aggregated)
    
    def _calculate_exposure_rate(self) -> float:
        """Calculate public exposure rate"""
        total = sum(p['total'] for p in self.metrics.values())
        public = sum(p['public'] for p in self.metrics.values())
        
        if total == 0:
            return 0.0
        
        return round((public / total) * 100, 2)
    
    def _calculate_sensitive_rate(self) -> float:
        """Calculate sensitive data rate"""
        total = sum(p['total'] for p in self.metrics.values())
        sensitive = sum(p['sensitive'] for p in self.metrics.values())
        
        if total == 0:
            return 0.0
        
        return round((sensitive / total) * 100, 2)
    
    def _get_top_risks(self) -> List[Dict]:
        """Get top risk categories"""
        risks = []
        
        for provider, stats in self.metrics.items():
            if stats.get('critical', 0) > 0:
                risks.append({
                    'provider': provider,
                    'type': 'critical_findings',
                    'count': stats['critical'],
                    'severity': 'CRITICAL'
                })
            
            if stats.get('public', 0) > stats['total'] * 0.5:
                risks.append({
                    'provider': provider,
                    'type': 'high_public_exposure',
                    'percentage': round((stats['public'] / stats['total']) * 100, 2),
                    'severity': 'HIGH'
                })
        
        return sorted(risks, key=lambda x: x.get('count', x.get('percentage', 0)), reverse=True)[:5]
    
    def _calculate_security_score(self, stats: Dict, total: int) -> int:
        """Calculate security score (0-100)"""
        if total == 0:
            return 100
        
        # Start with perfect score
        score = 100
        
        # Deduct for risks
        score -= (stats.get('critical', 0) / total) * 50
        score -= (stats.get('high', 0) / total) * 30
        score -= (stats.get('public', 0) / total) * 20
        
        return max(0, int(score))
