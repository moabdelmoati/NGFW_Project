"""
Suricata Integration Module
- Reads Suricata eve.json logs
- Integrates with IPS engine for blocking
- URL detection and prevention
"""

import json
import os
import time
import logging
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

LOG = logging.getLogger("suricata")

# Suricata configuration
SURICATA_LOG_DIR = Path(__file__).parent / "data" / "suricata_logs"
SURICATA_EVE_LOG = SURICATA_LOG_DIR / "eve.json"
SURICATA_CONFIG = Path(__file__).parent / "suricata.yaml"

# Create log directory if it doesn't exist
SURICATA_LOG_DIR.mkdir(parents=True, exist_ok=True)


class SuricataReader:
    """Reads and processes Suricata eve.json logs"""
    
    def __init__(self, eve_log_path: Path = SURICATA_EVE_LOG):
        self.eve_log_path = eve_log_path
        self.last_position = 0
        self.running = False
        self.thread = None
        self.callbacks: List[callable] = []
        
    def add_callback(self, callback: callable):
        """Add callback function to be called when alert is detected"""
        self.callbacks.append(callback)
    
    def _read_new_alerts(self) -> List[Dict[str, Any]]:
        """Read new alerts from eve.json since last position"""
        alerts = []
        
        if not self.eve_log_path.exists():
            return alerts
        
        try:
            with open(self.eve_log_path, 'r', encoding='utf-8') as f:
                # Move to last position
                f.seek(self.last_position)
                
                # Read new lines
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        event = json.loads(line)
                        
                        # Only process alerts
                        if event.get('event_type') == 'alert':
                            alerts.append(event)
                    except json.JSONDecodeError:
                        continue
                
                # Update position
                self.last_position = f.tell()
                
        except Exception as e:
            LOG.error(f"Error reading Suricata logs: {e}")
        
        return alerts
    
    def _process_alert(self, alert: Dict[str, Any]):
        """Process a single alert and trigger callbacks"""
        try:
            # Extract alert information
            alert_data = {
                'timestamp': alert.get('timestamp'),
                'event_type': alert.get('event_type'),
                'alert': alert.get('alert', {}),
                'src_ip': alert.get('src_ip'),
                'dest_ip': alert.get('dest_ip'),
                'src_port': alert.get('src_port'),
                'dest_port': alert.get('dest_port'),
                'protocol': alert.get('protocol'),
                'http': alert.get('http', {}),
                'tls': alert.get('tls', {}),
                'dns': alert.get('dns', {}),
                'flow': alert.get('flow', {}),
            }
            
            # Extract URL if available
            url = None
            if alert_data.get('http'):
                host = alert_data['http'].get('hostname', '')
                uri = alert_data['http'].get('url', '')
                if host:
                    url = f"http://{host}{uri}" if not uri.startswith('http') else uri
            elif alert_data.get('tls'):
                # Extract from TLS SNI
                sni = alert_data['tls'].get('sni', '')
                if sni:
                    url = f"https://{sni}"
            
            if url:
                alert_data['url'] = url
            
            # Extract signature information
            alert_info = alert_data.get('alert', {})
            signature = {
                'id': alert_info.get('signature_id', 0),
                'name': alert_info.get('signature', 'Unknown'),
                'category': alert_info.get('category', ''),
                'severity': self._map_severity(alert_info.get('severity', 0)),
                'action': 'block' if alert_info.get('action', '') == 'block' else 'alert'
            }
            alert_data['signature'] = signature
            
            # Trigger callbacks
            for callback in self.callbacks:
                try:
                    callback(alert_data)
                except Exception as e:
                    LOG.error(f"Error in callback: {e}")
                    
        except Exception as e:
            LOG.error(f"Error processing alert: {e}")
    
    def _map_severity(self, severity: int) -> str:
        """Map Suricata severity to our severity levels"""
        if severity >= 3:
            return 'critical'
        elif severity >= 2:
            return 'high'
        elif severity >= 1:
            return 'medium'
        else:
            return 'low'
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        LOG.info("Starting Suricata log monitor...")
        
        while self.running:
            try:
                alerts = self._read_new_alerts()
                
                for alert in alerts:
                    self._process_alert(alert)
                
                # Sleep before next check
                time.sleep(1)  # Check every second
                
            except Exception as e:
                LOG.error(f"Error in monitor loop: {e}")
                time.sleep(5)
    
    def start(self):
        """Start monitoring Suricata logs"""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        LOG.info("Suricata monitor started")
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        LOG.info("Suricata monitor stopped")


class SuricataIPS:
    """Suricata IPS Integration - Blocks URLs based on Suricata alerts"""
    
    def __init__(self):
        self.reader = SuricataReader()
        self.blocked_urls: Dict[str, datetime] = {}
        self.blocked_ips: Dict[str, datetime] = {}
        self.block_duration_minutes = 60
        
        # Setup callback
        self.reader.add_callback(self._handle_alert)
    
    def _handle_alert(self, alert_data: Dict[str, Any]):
        """Handle Suricata alert and block if necessary"""
        try:
            url = alert_data.get('url')
            src_ip = alert_data.get('src_ip')
            signature = alert_data.get('signature', {})
            severity = signature.get('severity', 'low')
            action = signature.get('action', 'alert')
            
            # Block URL if detected
            if url and severity in ['high', 'critical']:
                block_until = datetime.now() + timedelta(minutes=self.block_duration_minutes)
                self.blocked_urls[url] = block_until
                LOG.warning(f"🚫 Suricata blocked URL: {url} (severity: {severity})")
            
            # Block IP if critical
            if src_ip and severity == 'critical':
                block_until = datetime.now() + timedelta(minutes=self.block_duration_minutes)
                self.blocked_ips[src_ip] = block_until
                LOG.warning(f"🚫 Suricata blocked IP: {src_ip} (critical alert)")
            
            # Log alert
            LOG.info(f"Suricata alert: {signature.get('name')} - {url or src_ip}")
            
        except Exception as e:
            LOG.error(f"Error handling Suricata alert: {e}")
    
    def is_url_blocked(self, url: str) -> bool:
        """Check if URL is blocked by Suricata"""
        if url not in self.blocked_urls:
            return False
        
        block_until = self.blocked_urls[url]
        if datetime.now() > block_until:
            del self.blocked_urls[url]
            return False
        
        return True
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is blocked by Suricata"""
        if ip not in self.blocked_ips:
            return False
        
        block_until = self.blocked_ips[ip]
        if datetime.now() > block_until:
            del self.blocked_ips[ip]
            return False
        
        return True
    
    def start(self):
        """Start Suricata monitoring"""
        self.reader.start()
    
    def stop(self):
        """Stop Suricata monitoring"""
        self.reader.stop()


# Global Suricata IPS instance
_suricata_ips = None

def get_suricata_ips() -> SuricataIPS:
    """Get global Suricata IPS instance"""
    global _suricata_ips
    if _suricata_ips is None:
        _suricata_ips = SuricataIPS()
    return _suricata_ips

