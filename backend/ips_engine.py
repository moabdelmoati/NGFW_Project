"""
Intrusion Prevention System (IPS) Engine
- Decision making for threat response
- Action execution (block, alert, quarantine)
- Firewall rule management
- Suricata integration
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from enum import Enum

LOG = logging.getLogger("ips")


class ActionType(Enum):
    """IPS action types"""
    ALERT = "alert"  # Log only
    BLOCK = "block"  # Block connection
    DROP = "drop"    # Drop packet
    QUARANTINE = "quarantine"  # Isolate traffic
    RESET = "reset"  # Reset connection


class IPSEngine:
    """Intrusion Prevention System Engine"""
    
    def __init__(self, mode: str = "ids"):
        """
        Initialize IPS engine
        
        Args:
            mode: "ids" (detection only) or "ips" (detection + prevention)
        """
        self.mode = mode.lower()
        self.blocked_ips: Dict[str, datetime] = {}  # IP -> block_until
        self.blocked_ports: Dict[int, datetime] = {}  # Port -> block_until
        self.rate_limits: Dict[str, List[datetime]] = {}  # IP -> timestamps
        self.action_history: List[Dict[str, Any]] = []
        
        # Configuration
        self.max_actions_history = 1000
        self.block_duration_minutes = 60
        self.rate_limit_threshold = 100  # requests per minute
        self.rate_limit_window = 60  # seconds
        
        # Suricata integration
        self.suricata_enabled = True
        try:
            from suricata_integration import get_suricata_ips
            self.suricata_ips = get_suricata_ips()
            if self.mode == "ips":
                self.suricata_ips.start()
        except ImportError:
            LOG.warning("Suricata integration not available")
            self.suricata_enabled = False
            self.suricata_ips = None
    
    def evaluate_threat(self, 
                       flow_data: Dict[str, Any],
                       ml_score: Optional[float] = None,
                       ml_label: Optional[str] = None,
                       signature_matches: Optional[List] = None,
                       dpi_indicators: Optional[List] = None,
                       is_trusted_domain: bool = False) -> Dict[str, Any]:
        """
        Evaluate threat and determine action
        
        Args:
            flow_data: Network flow data
            ml_score: ML model prediction score
            ml_label: ML model prediction label
            signature_matches: List of matched signatures
            dpi_indicators: DPI threat indicators
        
        Returns:
            Decision dictionary with action and details
        """
        decision = {
            'action': ActionType.ALERT.value,
            'reason': [],
            'severity': 'low',
            'blocked': False,
            'timestamp': datetime.now().isoformat()
        }
        
        src_ip = flow_data.get('src_ip')
        dst_ip = flow_data.get('dst_ip') or flow_data.get('dest_ip')
        url = flow_data.get('url')
        
        # Check Suricata blocking first
        if self.suricata_enabled and self.suricata_ips:
            if url and self.suricata_ips.is_url_blocked(url):
                decision['action'] = ActionType.BLOCK.value
                decision['blocked'] = True
                decision['severity'] = 'critical'
                decision['reason'].append(f"URL blocked by Suricata: {url}")
                return decision
            
            if src_ip and self.suricata_ips.is_ip_blocked(src_ip):
                decision['action'] = ActionType.BLOCK.value
                decision['blocked'] = True
                decision['severity'] = 'critical'
                decision['reason'].append(f"IP blocked by Suricata: {src_ip}")
                return decision
        
        # Check if IP is already blocked
        if src_ip and self._is_ip_blocked(src_ip):
            decision['action'] = ActionType.BLOCK.value
            decision['blocked'] = True
            decision['reason'].append(f"IP {src_ip} is in blocklist")
            return decision
        
        # Evaluate ML prediction
        # For trusted domains, ignore ML score unless there are clear threats
        if is_trusted_domain:
            # Trusted domains: only use ML score if there are other threat indicators
            if ml_label == "malicious" and ml_score and ml_score >= 0.95:
                # Very high confidence + other indicators needed for trusted domains
                if signature_matches or dpi_indicators:
                    decision['severity'] = 'high'
                    decision['reason'].append(f"ML model detected threat (score: {ml_score:.3f}) with additional indicators")
                    decision['action'] = ActionType.BLOCK.value
                    decision['blocked'] = True
                else:
                    # Ignore ML score for trusted domains without other indicators
                    LOG.info(f"Trusted domain: ignoring ML score {ml_score:.3f} (no other threat indicators)")
        else:
            # Normal logic for non-trusted domains
            if ml_label == "malicious" and ml_score and ml_score >= 0.8:
                decision['severity'] = 'high'
                decision['reason'].append(f"ML model detected threat (score: {ml_score:.3f})")
                if ml_score >= 0.9:
                    decision['action'] = ActionType.BLOCK.value
                    decision['blocked'] = True
        
        # Evaluate signature matches
        if signature_matches:
            critical_sigs = [m for m in signature_matches if m[0].severity == 'critical']
            high_sigs = [m for m in signature_matches if m[0].severity == 'high']
            
            if critical_sigs:
                decision['action'] = ActionType.BLOCK.value
                decision['severity'] = 'critical'
                decision['blocked'] = True
                decision['reason'].append(f"Critical signature match: {critical_sigs[0][0].name}")
            elif high_sigs:
                if decision['action'] == ActionType.ALERT.value:
                    decision['action'] = ActionType.BLOCK.value
                    decision['severity'] = 'high'
                    decision['blocked'] = True
                decision['reason'].append(f"High severity signature: {high_sigs[0][0].name}")
        
        # Evaluate DPI indicators
        if dpi_indicators:
            # If DPI detected threats, escalate severity
            if decision['severity'] == 'low':
                decision['severity'] = 'medium'
            decision['reason'].extend([f"DPI threat: {ind}" for ind in dpi_indicators])
            # Block if high severity DPI threats
            if any('Path traversal' in ind or 'Malicious pattern' in ind or 'Suspicious file extension' in ind for ind in dpi_indicators):
                if decision['action'] == ActionType.ALERT.value:
                    decision['action'] = ActionType.BLOCK.value
                    decision['blocked'] = True
                    decision['severity'] = 'high'
        
        # Rate limiting check
        if src_ip and self._check_rate_limit(src_ip):
            decision['action'] = ActionType.BLOCK.value
            decision['severity'] = 'medium'
            decision['blocked'] = True
            decision['reason'].append(f"Rate limit exceeded for {src_ip}")
        
        # Execute action if in IPS mode
        if self.mode == "ips" and decision['action'] != ActionType.ALERT.value:
            self._execute_action(decision, flow_data)
        
        # Log action
        self._log_action(decision, flow_data)
        
        return decision
    
    def _is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked"""
        if ip not in self.blocked_ips:
            return False
        
        block_until = self.blocked_ips[ip]
        if datetime.now() > block_until:
            # Block expired, remove it
            del self.blocked_ips[ip]
            return False
        
        return True
    
    def _check_rate_limit(self, ip: str) -> bool:
        """Check if IP has exceeded rate limit"""
        now = datetime.now()
        
        # Clean old timestamps
        if ip in self.rate_limits:
            self.rate_limits[ip] = [
                ts for ts in self.rate_limits[ip]
                if (now - ts).total_seconds() < self.rate_limit_window
            ]
        else:
            self.rate_limits[ip] = []
        
        # Add current request
        self.rate_limits[ip].append(now)
        
        # Check threshold
        return len(self.rate_limits[ip]) > self.rate_limit_threshold
    
    def _execute_action(self, decision: Dict[str, Any], flow_data: Dict[str, Any]):
        """Execute IPS action"""
        action = decision['action']
        src_ip = flow_data.get('src_ip')
        
        if action == ActionType.BLOCK.value and src_ip:
            # Block IP for configured duration
            block_until = datetime.now() + timedelta(minutes=self.block_duration_minutes)
            self.blocked_ips[src_ip] = block_until
            LOG.warning("🚫 Blocked IP %s until %s", src_ip, block_until)
        
        elif action == ActionType.DROP.value:
            # Drop packet (would need firewall integration)
            LOG.warning("📦 Dropping packet from %s", src_ip)
        
        elif action == ActionType.RESET.value:
            # Reset connection (would need firewall integration)
            LOG.warning("🔄 Resetting connection from %s", src_ip)
    
    def _log_action(self, decision: Dict[str, Any], flow_data: Dict[str, Any]):
        """Log IPS action"""
        log_entry = {
            'timestamp': decision['timestamp'],
            'action': decision['action'],
            'severity': decision['severity'],
            'src_ip': flow_data.get('src_ip'),
            'dst_ip': flow_data.get('dst_ip') or flow_data.get('dest_ip'),
            'reason': decision['reason'],
            'flow_id': flow_data.get('id')
        }
        
        self.action_history.append(log_entry)
        
        # Keep history size limited
        if len(self.action_history) > self.max_actions_history:
            self.action_history = self.action_history[-self.max_actions_history:]
    
    def block_ip(self, ip: str, duration_minutes: int = None):
        """Manually block an IP address"""
        duration = duration_minutes or self.block_duration_minutes
        block_until = datetime.now() + timedelta(minutes=duration)
        self.blocked_ips[ip] = block_until
        LOG.info("🔒 Manually blocked IP %s until %s", ip, block_until)
    
    def unblock_ip(self, ip: str):
        """Unblock an IP address"""
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
            LOG.info("🔓 Unblocked IP %s", ip)
    
    def get_blocked_ips(self) -> List[Dict[str, Any]]:
        """Get list of currently blocked IPs"""
        now = datetime.now()
        blocked = []
        
        for ip, block_until in self.blocked_ips.items():
            if now < block_until:
                blocked.append({
                    'ip': ip,
                    'blocked_until': block_until.isoformat(),
                    'remaining_minutes': int((block_until - now).total_seconds() / 60)
                })
        
        return blocked
    
    def get_action_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent action history"""
        return self.action_history[-limit:]
    
    def set_mode(self, mode: str):
        """Set IPS mode (ids or ips)"""
        self.mode = mode.lower()
        LOG.info("IPS mode set to: %s", self.mode.upper())


# Global IPS engine instance
_ips_engine = None

def get_ips_engine(mode: str = "ids") -> IPSEngine:
    """Get global IPS engine instance"""
    global _ips_engine
    if _ips_engine is None:
        _ips_engine = IPSEngine(mode=mode)
    return _ips_engine

