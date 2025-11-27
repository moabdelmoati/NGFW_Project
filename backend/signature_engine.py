"""
Signature-Based Detection Engine
- Pattern matching for known threats
- Support for Snort/Suricata rules
- Custom signature management
"""

import re
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass

LOG = logging.getLogger("signature")


@dataclass
class Signature:
    """Signature rule definition"""
    id: int
    name: str
    description: str
    pattern: str  # Regex pattern or byte pattern
    protocol: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    severity: str = "medium"  # low, medium, high, critical
    action: str = "alert"  # alert, block, drop
    enabled: bool = True


class SignatureEngine:
    """Signature-based detection engine"""
    
    def __init__(self):
        self.signatures: List[Signature] = []
        self.compiled_patterns: Dict[int, re.Pattern] = {}
        self._load_default_signatures()
    
    def _load_default_signatures(self):
        """Load default threat signatures"""
        default_sigs = [
            Signature(
                id=1,
                name="SQL Injection Attempt",
                description="Detects SQL injection patterns",
                pattern=r"(?i)(union\s+select|insert\s+into|drop\s+table|exec\s*\(|'or\s+'1'\s*=\s*'1)",
                protocol="HTTP",
                severity="high",
                action="alert"
            ),
            Signature(
                id=2,
                name="XSS Attack",
                description="Detects cross-site scripting attempts",
                pattern=r"(?i)(<script|javascript:|onerror=|onload=)",
                protocol="HTTP",
                severity="high",
                action="alert"
            ),
            Signature(
                id=3,
                name="Command Injection",
                description="Detects command injection attempts",
                pattern=r"(?i)(;|\||&&)\s*(cat|ls|pwd|whoami|id|uname)",
                severity="critical",
                action="block"
            ),
            Signature(
                id=4,
                name="Directory Traversal",
                description="Detects path traversal attempts",
                pattern=r"(\.\.\/|\.\.\\|%2e%2e%2f)",
                protocol="HTTP",
                severity="high",
                action="alert"
            ),
            Signature(
                id=5,
                name="Suspicious User Agent",
                description="Detects suspicious or malicious user agents",
                pattern=r"(?i)(sqlmap|nikto|nmap|masscan|zap|burp)",
                protocol="HTTP",
                severity="medium",
                action="alert"
            ),
            Signature(
                id=6,
                name="Port Scan Detection",
                description="Detects potential port scanning",
                pattern=None,  # Behavioral, not pattern-based
                severity="medium",
                action="alert"
            ),
            Signature(
                id=7,
                name="Incomplete URL",
                description="Detects incomplete or malformed URLs",
                pattern=r"(^[^/]+$|^[^:]+://[^/]*$|^[^:]+://$)",
                protocol="HTTP",
            ),
            # URL-based signatures (like Suricata rules)
            Signature(
                id=100,
                name="Phishing URL - Typosquatting (go.ogle)",
                description="Detects typosquatting for Google",
                pattern=r"(?i)(go\.ogle|g00gle|goog1e)",
                protocol="HTTP",
                severity="high",
                action="block"
            ),
            Signature(
                id=101,
                name="Phishing URL - Typosquatting (youtube)",
                description="Detects typosquatting for YouTube",
                pattern=r"(?i)(yotube|youtub|y0utube)",
                protocol="HTTP",
                severity="high",
                action="block"
            ),
            Signature(
                id=102,
                name="Phishing URL - Typosquatting (facebook)",
                description="Detects typosquatting for Facebook",
                pattern=r"(?i)(facebok|faceb00k|fac3book)",
                protocol="HTTP",
                severity="high",
                action="block"
            ),
            Signature(
                id=103,
                name="Phishing URL - Typosquatting (amazon)",
                description="Detects typosquatting for Amazon",
                pattern=r"(?i)(amazom|amaz0n|amaz0m)",
                protocol="HTTP",
                severity="high",
                action="block"
            ),
            Signature(
                id=104,
                name="Phishing URL - Typosquatting (paypal)",
                description="Detects typosquatting for PayPal",
                pattern=r"(?i)(paypall|paypa1|payp@l)",
                protocol="HTTP",
                severity="high",
                action="block"
            ),
            Signature(
                id=105,
                name="Suspicious Domain - .cc TLD",
                description="Detects suspicious .cc domains",
                pattern=r"\.cc(/|$|\?|#)",
                protocol="HTTP",
                severity="medium",
                action="alert"
            ),
            Signature(
                id=106,
                name="Suspicious Domain - .tk TLD",
                description="Detects suspicious .tk domains",
                pattern=r"\.tk(/|$|\?|#)",
                protocol="HTTP",
                severity="medium",
                action="alert"
            ),
            Signature(
                id=107,
                name="Malicious URL Pattern - bic-wswhatsapp",
                description="Detects suspicious WhatsApp-related domains",
                pattern=r"(?i)(bic-wswhatsapp|whatsapp.*\.cc)",
                protocol="HTTP",
                severity="high",
                action="block"
            ),
            Signature(
                id=108,
                name="Phishing Site Pattern",
                description="Detects phishing site patterns",
                pattern=r"(?i)(phishing|example-phishing)",
                protocol="HTTP",
                severity="high",
                action="block"
            ),
            Signature(
                id=8,
                name="Suspicious URL Path",
                description="Detects suspicious patterns in URL paths",
                pattern=r"(\.\.\/|\.\.\\|%2e%2e|\.exe|\.bat|\.cmd|\.scr)",
                protocol="HTTP",
                severity="high",
                action="alert"
            ),
            Signature(
                id=9,
                name="Obfuscated URL",
                description="Detects heavily encoded or obfuscated URLs",
                pattern=r"(%[0-9a-fA-F]{2}){10,}",
                protocol="HTTP",
                severity="medium",
                action="alert"
            ),
            Signature(
                id=10,
                name="IP Address in URL",
                description="Detects IP addresses used instead of domain names",
                pattern=r"https?://(\d{1,3}\.){3}\d{1,3}",
                protocol="HTTP",
                severity="low",
                action="alert"
            ),
            Signature(
                id=109,
                name="Phishing Pattern - Numeric Path",
                description="Detects URLs with numeric-only paths (common in phishing)",
                pattern=r"https?://[^/]+/\d{6,}",
                protocol="HTTP",
                severity="high",
                action="block"
            ),
            Signature(
                id=110,
                name="Suspicious Domain - Very Long",
                description="Detects very long domain names (potential phishing)",
                pattern=r"https?://[a-z0-9-]{25,}\.(com|net|org|info|biz)",
                protocol="HTTP",
                severity="medium",
                action="alert"
            ),
            Signature(
                id=111,
                name="Phishing Pattern - Unknown Domain with Numeric Path",
                description="Detects unknown domains with numeric paths",
                pattern=r"https?://[a-z0-9-]{20,}\.(com|net|org)/\d{5,}",
                protocol="HTTP",
                severity="high",
                action="block"
            ),
        ]
        
        for sig in default_sigs:
            self.add_signature(sig)
    
    def add_signature(self, signature: Signature):
        """Add a signature to the engine"""
        self.signatures.append(signature)
        if signature.pattern:
            try:
                self.compiled_patterns[signature.id] = re.compile(signature.pattern)
            except re.error as e:
                LOG.warning("Invalid regex pattern for signature %d: %s", signature.id, e)
    
    def match_signatures(self, flow_data: Dict[str, Any], packet_payload: Optional[bytes] = None) -> List[Tuple[Signature, Dict[str, Any]]]:
        """
        Match flow data against signatures
        
        Args:
            flow_data: Network flow data
            packet_payload: Optional raw packet payload
        
        Returns:
            List of (signature, match_info) tuples
        """
        matches = []
        
        for sig in self.signatures:
            if not sig.enabled:
                continue
            
            # Protocol filter
            if sig.protocol and flow_data.get('protocol', '').upper() != sig.protocol.upper():
                continue
            
            # Port filters
            dst_port = flow_data.get('dst_port') or flow_data.get('dest_port')
            src_port = flow_data.get('src_port')
            
            if sig.dst_port and dst_port != sig.dst_port:
                continue
            if sig.src_port and src_port != sig.src_port:
                continue
            
            # Pattern matching
            if sig.pattern:
                match_info = self._check_pattern(sig, flow_data, packet_payload)
                if match_info:
                    matches.append((sig, match_info))
        
        return matches
    
    def _check_pattern(self, signature: Signature, flow_data: Dict[str, Any], payload: Optional[bytes]) -> Optional[Dict[str, Any]]:
        """Check if signature pattern matches"""
        pattern = self.compiled_patterns.get(signature.id)
        if not pattern:
            return None
        
        # Search in URL first (most important for URL-based detection)
        url = flow_data.get('url', '')
        if url:
            url_lower = url.lower()
            match = pattern.search(url_lower)
            if match:
                return {
                    'matched_field': 'url',
                    'match_text': match.group(0),
                    'timestamp': datetime.now().isoformat()
                }
        
        # Search in flow data (string representation)
        flow_str = str(flow_data).lower()
        if pattern.search(flow_str):
            return {
                'matched_field': 'flow_data',
                'match_text': pattern.search(flow_str).group(0),
                'timestamp': datetime.now().isoformat()
            }
        
        # Search in packet payload if available
        if payload:
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
                match = pattern.search(payload_str)
                if match:
                    return {
                        'matched_field': 'payload',
                        'match_text': match.group(0),
                        'timestamp': datetime.now().isoformat()
                    }
            except:
                pass
        
        return None
    
    def get_signature_by_id(self, sig_id: int) -> Optional[Signature]:
        """Get signature by ID"""
        for sig in self.signatures:
            if sig.id == sig_id:
                return sig
        return None
    
    def enable_signature(self, sig_id: int):
        """Enable a signature"""
        sig = self.get_signature_by_id(sig_id)
        if sig:
            sig.enabled = True
    
    def disable_signature(self, sig_id: int):
        """Disable a signature"""
        sig = self.get_signature_by_id(sig_id)
        if sig:
            sig.enabled = False
    
    def list_signatures(self) -> List[Dict[str, Any]]:
        """List all signatures"""
        return [
            {
                'id': sig.id,
                'name': sig.name,
                'description': sig.description,
                'protocol': sig.protocol,
                'severity': sig.severity,
                'action': sig.action,
                'enabled': sig.enabled
            }
            for sig in self.signatures
        ]


# Global signature engine instance
_signature_engine = None

def get_signature_engine() -> SignatureEngine:
    """Get global signature engine instance"""
    global _signature_engine
    if _signature_engine is None:
        _signature_engine = SignatureEngine()
    return _signature_engine

