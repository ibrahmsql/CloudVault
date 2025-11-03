"""
Real-time Monitoring Engine
Continuous monitoring, alerting, and real-time notifications
"""
import logging
import time
from typing import List, Dict, Optional, Callable
from datetime import datetime
from threading import Thread, Event
from queue import Queue
import json

logger = logging.getLogger(__name__)


class MonitoringEngine:
    """
    Real-time monitoring with alerts and notifications
    """
    
    def __init__(self):
        """Initialize monitoring engine"""
        self.alert_queue = Queue()
        self.alert_handlers = []
        self.monitoring_active = False
        self.monitor_thread = None
        self.metrics = {
            'alerts_sent': 0,
            'critical_alerts': 0,
            'monitoring_uptime': 0
        }
        self.start_time = None
        logger.info("Monitoring engine initialized")
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        if self.monitoring_active:
            logger.warning("Monitoring already active")
            return
        
        self.monitoring_active = True
        self.start_time = datetime.now()
        self.monitor_thread = Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info("Real-time monitoring started")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        uptime = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        self.metrics['monitoring_uptime'] = uptime
        
        logger.info(f"Monitoring stopped. Uptime: {uptime}s")
    
    def add_alert_handler(self, handler: Callable):
        """
        Add custom alert handler
        
        Args:
            handler: Callable that accepts alert dictionary
        """
        self.alert_handlers.append(handler)
        logger.info(f"Alert handler added. Total handlers: {len(self.alert_handlers)}")
    
    def send_alert(self, alert_type: str, severity: str, message: str, metadata: Dict = None):
        """
        Send an alert
        
        Args:
            alert_type: Type of alert
            severity: CRITICAL, HIGH, MEDIUM, LOW
            message: Alert message
            metadata: Additional metadata
        """
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'severity': severity,
            'message': message,
            'metadata': metadata or {}
        }
        
        self.alert_queue.put(alert)
        self.metrics['alerts_sent'] += 1
        
        if severity == 'CRITICAL':
            self.metrics['critical_alerts'] += 1
        
        logger.warning(f"[{severity}] {message}")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        logger.info("Monitoring loop started")
        
        while self.monitoring_active:
            try:
                # Process alerts from queue
                if not self.alert_queue.empty():
                    alert = self.alert_queue.get(timeout=1)
                    self._process_alert(alert)
                
                time.sleep(0.1)
            
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(1)
        
        logger.info("Monitoring loop stopped")
    
    def _process_alert(self, alert: Dict):
        """Process an alert"""
        # Call all registered handlers
        for handler in self.alert_handlers:
            try:
                handler(alert)
            except Exception as e:
                logger.error(f"Error in alert handler: {e}")
        
        # Default console output
        self._default_alert_handler(alert)
    
    def _default_alert_handler(self, alert: Dict):
        """Default alert handler - console output"""
        from termcolor import cprint
        
        severity = alert['severity']
        message = alert['message']
        
        colors = {
            'CRITICAL': 'red',
            'HIGH': 'yellow',
            'MEDIUM': 'cyan',
            'LOW': 'white'
        }
        
        color = colors.get(severity, 'white')
        emoji = {'CRITICAL': '🚨', 'HIGH': '⚠️', 'MEDIUM': 'ℹ️', 'LOW': '📝'}
        
        cprint(
            f"{emoji.get(severity, '•')} [{severity}] {message}",
            color,
            attrs=['bold'] if severity in ['CRITICAL', 'HIGH'] else []
        )
    
    def get_metrics(self) -> Dict:
        """Get monitoring metrics"""
        uptime = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        
        return {
            **self.metrics,
            'current_uptime': uptime,
            'alerts_per_minute': round(self.metrics['alerts_sent'] / max(uptime / 60, 1), 2),
            'active_handlers': len(self.alert_handlers),
            'queue_size': self.alert_queue.qsize()
        }
    
    def create_webhook_handler(self, webhook_url: str) -> Callable:
        """
        Create a webhook alert handler
        
        Args:
            webhook_url: Webhook URL
            
        Returns:
            Handler function
        """
        def webhook_handler(alert: Dict):
            import requests
            try:
                response = requests.post(
                    webhook_url,
                    json=alert,
                    headers={'Content-Type': 'application/json'},
                    timeout=10
                )
                if response.status_code != 200:
                    logger.warning(f"Webhook returned {response.status_code}")
            except Exception as e:
                logger.error(f"Webhook error: {e}")
        
        return webhook_handler
    
    def create_email_handler(self, smtp_config: Dict) -> Callable:
        """
        Create an email alert handler
        
        Args:
            smtp_config: SMTP configuration
            
        Returns:
            Handler function
        """
        def email_handler(alert: Dict):
            # Simplified email handler (would need actual SMTP implementation)
            logger.info(f"Email alert: {alert['message']} to {smtp_config.get('to')}")
        
        return email_handler
    
    def create_slack_handler(self, webhook_url: str) -> Callable:
        """
        Create a Slack alert handler
        
        Args:
            webhook_url: Slack webhook URL
            
        Returns:
            Handler function
        """
        def slack_handler(alert: Dict):
            import requests
            
            severity_emoji = {'CRITICAL': ':rotating_light:', 'HIGH': ':warning:', 'MEDIUM': ':information_source:', 'LOW': ':memo:'}
            
            payload = {
                'text': f"{severity_emoji.get(alert['severity'], ':bell:')} *{alert['severity']}*: {alert['message']}",
                'username': 'CloudVault Monitor',
                'icon_emoji': ':shield:'
            }
            
            try:
                requests.post(webhook_url, json=payload, timeout=10)
            except Exception as e:
                logger.error(f"Slack error: {e}")
        
        return slack_handler
    
    def export_alerts(self, filename: str):
        """Export all alerts"""
        alerts = []
        
        while not self.alert_queue.empty():
            try:
                alerts.append(self.alert_queue.get_nowait())
            except:
                break
        
        with open(filename, 'w') as f:
            json.dump({
                'generated_at': datetime.now().isoformat(),
                'total_alerts': len(alerts),
                'alerts': alerts
            }, f, indent=2)
        
        # Put alerts back
        for alert in alerts:
            self.alert_queue.put(alert)
        
        logger.info(f"Alerts exported to {filename}")


class HealthMonitor:
    """System health monitoring"""
    
    def __init__(self):
        """Initialize health monitor"""
        self.health_checks = {}
        self.status = 'HEALTHY'
    
    def register_check(self, name: str, check_func: Callable):
        """Register health check"""
        self.health_checks[name] = check_func
    
    def run_checks(self) -> Dict:
        """Run all health checks"""
        results = {}
        
        for name, check_func in self.health_checks.items():
            try:
                results[name] = {
                    'status': 'PASS' if check_func() else 'FAIL',
                    'checked_at': datetime.now().isoformat()
                }
            except Exception as e:
                results[name] = {
                    'status': 'ERROR',
                    'error': str(e),
                    'checked_at': datetime.now().isoformat()
                }
        
        # Determine overall status
        if any(r['status'] in ['FAIL', 'ERROR'] for r in results.values()):
            self.status = 'UNHEALTHY'
        else:
            self.status = 'HEALTHY'
        
        return {
            'overall_status': self.status,
            'checks': results
        }
