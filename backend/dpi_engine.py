"""
Deep Packet Inspection (DPI) Engine
- Analyzes packets at Layer 3-7
- Extracts application-layer information
- Protocol identification and parsing
"""

import logging
import re
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, Optional, List
from datetime import datetime

try:
    from scapy.all import IP, TCP, UDP, Raw, DNS, HTTP, sniff
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available. DPI features will be limited.")

LOG = logging.getLogger("dpi")


class DPIEngine:
    """Deep Packet Inspection Engine"""
    
    def __init__(self):
        self.protocol_parsers = {
            'http': self._parse_http,
            'https': self._parse_tls,
            'dns': self._parse_dns,
            'ftp': self._parse_ftp,
            'smtp': self._parse_smtp,
        }
    
    def analyze_packet(self, packet_data: bytes, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a packet and extract DPI information
        
        Args:
            packet_data: Raw packet bytes
            metadata: Basic packet metadata (src_ip, dst_ip, ports, protocol)
        
        Returns:
            Dictionary with DPI analysis results
        """
        result = {
            'dpi_analyzed': False,
            'application_protocol': None,
            'application_name': None,
            'extracted_features': {},
            'threat_indicators': [],
            'timestamp': datetime.now().isoformat()
        }
        
        if not SCAPY_AVAILABLE:
            result['error'] = 'Scapy not available'
            return result
        
        try:
            # Parse packet with Scapy
            packet = IP(packet_data) if len(packet_data) > 20 else None
            if not packet:
                return result
            
            # Layer 3-4 analysis
            layer_info = self._analyze_layers(packet, metadata)
            result.update(layer_info)
            
            # Application layer analysis
            app_info = self._analyze_application_layer(packet, metadata)
            result.update(app_info)
            
            result['dpi_analyzed'] = True
            
        except Exception as e:
            LOG.exception("DPI analysis error: %s", e)
            result['error'] = str(e)
        
        return result
    
    def _analyze_layers(self, packet, metadata: Dict) -> Dict[str, Any]:
        """Analyze network and transport layers"""
        info = {}
        
        # IP layer
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            info['ip_version'] = ip_layer.version
            info['ip_ttl'] = ip_layer.ttl
            info['ip_flags'] = str(ip_layer.flags)
            info['ip_len'] = ip_layer.len
        
        # TCP layer
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            info['tcp_flags'] = str(tcp_layer.flags)
            info['tcp_window'] = tcp_layer.window
            info['tcp_seq'] = tcp_layer.seq
            info['tcp_ack'] = tcp_layer.ack
            info['transport_protocol'] = 'TCP'
        
        # UDP layer
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            info['udp_len'] = udp_layer.len
            info['transport_protocol'] = 'UDP'
        
        return info
    
    def _analyze_application_layer(self, packet, metadata: Dict) -> Dict[str, Any]:
        """Analyze application layer protocols"""
        info = {
            'application_protocol': None,
            'application_name': None,
            'extracted_features': {}
        }
        
        # HTTP analysis
        if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
            http_info = self._parse_http(packet)
            info.update(http_info)
            info['application_protocol'] = 'HTTP'
        
        # DNS analysis
        elif packet.haslayer(DNS):
            dns_info = self._parse_dns(packet)
            info.update(dns_info)
            info['application_protocol'] = 'DNS'
        
        # TLS/SSL (HTTPS) - basic detection
        elif packet.haslayer(Raw):
            raw_data = packet[Raw].load
            if self._detect_tls(raw_data):
                tls_info = self._parse_tls(raw_data)
                info.update(tls_info)
                info['application_protocol'] = 'HTTPS'
        
        return info
    
    def _parse_http(self, packet) -> Dict[str, Any]:
        """Parse HTTP protocol"""
        features = {}
        
        if packet.haslayer(HTTPRequest):
            http = packet[HTTPRequest]
            features['http_method'] = getattr(http, 'Method', b'').decode('utf-8', errors='ignore')
            features['http_host'] = getattr(http, 'Host', b'').decode('utf-8', errors='ignore')
            features['http_path'] = getattr(http, 'Path', b'').decode('utf-8', errors='ignore')
            features['http_user_agent'] = getattr(http, 'User_Agent', b'').decode('utf-8', errors='ignore')
            features['http_referer'] = getattr(http, 'Referer', b'').decode('utf-8', errors='ignore')
            
            # Build full URL and validate
            if features.get('http_host') and features.get('http_path'):
                full_url = f"http://{features['http_host']}{features['http_path']}"
                url_validation = self.validate_url(full_url)
                features['url_validation'] = url_validation
        
        elif packet.haslayer(HTTPResponse):
            http = packet[HTTPResponse]
            features['http_status_code'] = getattr(http, 'Status_Code', b'').decode('utf-8', errors='ignore')
            features['http_server'] = getattr(http, 'Server', b'').decode('utf-8', errors='ignore')
        
        return {'extracted_features': features}
    
    def _parse_dns(self, packet) -> Dict[str, Any]:
        """Parse DNS protocol"""
        features = {}
        
        if packet.haslayer(DNS):
            dns = packet[DNS]
            features['dns_qname'] = dns.qd.qname.decode('utf-8', errors='ignore') if dns.qd else None
            features['dns_qtype'] = dns.qd.qtype if dns.qd else None
            features['dns_rcode'] = dns.rcode
            features['dns_opcode'] = dns.opcode
            
            # Extract answers
            if dns.an:
                features['dns_answers'] = [str(rr.rdata) for rr in dns.an]
        
        return {'extracted_features': features}
    
    def _parse_tls(self, raw_data: bytes) -> Dict[str, Any]:
        """Parse TLS/SSL handshake (basic)"""
        features = {}
        
        # Basic TLS detection
        if raw_data[:3] == b'\x16\x03':  # TLS handshake
            features['tls_detected'] = True
            features['tls_version'] = f"{raw_data[1]}.{raw_data[2]}"
            
            # Try to extract SNI (Server Name Indication)
            sni = self._extract_sni(raw_data)
            if sni:
                features['tls_sni'] = sni
        
        return {'extracted_features': features}
    
    def _extract_sni(self, data: bytes) -> Optional[str]:
        """Extract Server Name Indication from TLS handshake"""
        try:
            # Simplified SNI extraction
            sni_marker = b'\x00\x00'
            idx = data.find(sni_marker)
            if idx > 0 and idx < len(data) - 10:
                # Basic SNI parsing (simplified)
                length = int.from_bytes(data[idx+3:idx+5], 'big')
                if length > 0 and idx + 5 + length <= len(data):
                    sni = data[idx+5:idx+5+length].decode('utf-8', errors='ignore')
                    return sni
        except:
            pass
        return None
    
    def _detect_tls(self, data: bytes) -> bool:
        """Detect if data contains TLS/SSL"""
        if len(data) < 5:
            return False
        # TLS handshake starts with 0x16, SSLv3/TLS version follows
        return data[0] == 0x16 and data[1:3] in [b'\x03\x00', b'\x03\x01', b'\x03\x02', b'\x03\x03']
    
    def _parse_ftp(self, packet) -> Dict[str, Any]:
        """Parse FTP protocol"""
        # TODO: Implement FTP parsing
        return {'extracted_features': {}}
    
    def _parse_smtp(self, packet) -> Dict[str, Any]:
        """Parse SMTP protocol"""
        # TODO: Implement SMTP parsing
        return {'extracted_features': {}}
    
    def identify_application(self, dpi_result: Dict[str, Any]) -> str:
        """Identify application name from DPI results"""
        features = dpi_result.get('extracted_features', {})
        
        # HTTP/HTTPS applications
        if 'http_host' in features:
            host = features['http_host'].lower()
            if 'facebook' in host:
                return 'Facebook'
            elif 'youtube' in host or 'googlevideo' in host:
                return 'YouTube'
            elif 'twitter' in host or 'x.com' in host:
                return 'Twitter'
            elif 'instagram' in host:
                return 'Instagram'
            elif 'whatsapp' in host:
                return 'WhatsApp'
            elif 'google' in host:
                return 'Google'
            elif 'microsoft' in host or 'office' in host:
                return 'Microsoft'
            else:
                return 'Web Browser'
        
        # DNS
        if 'dns_qname' in features:
            return 'DNS'
        
        # TLS/HTTPS
        if 'tls_sni' in features:
            sni = features['tls_sni'].lower()
            if 'facebook' in sni:
                return 'Facebook'
            elif 'youtube' in sni:
                return 'YouTube'
            # Add more application detection based on SNI
        
        return 'Unknown'
    
    def validate_url(self, url: str) -> Dict[str, Any]:
        """
        Validate and analyze URL for security threats
        
        Args:
            url: URL string to validate
        
        Returns:
            Dictionary with validation results and threat indicators
        """
        result = {
            'is_valid': False,
            'is_complete': False,
            'threat_indicators': [],
            'warnings': [],
            'parsed_url': None,
            'issues': []
        }
        
        if not url or not isinstance(url, str):
            result['issues'].append('URL is empty or not a string')
            return result
        
        url = url.strip()
        
        # Check if URL is complete
        try:
            parsed = urlparse(url)
            result['parsed_url'] = {
                'scheme': parsed.scheme,
                'netloc': parsed.netloc,
                'path': parsed.path,
                'query': parsed.query,
                'fragment': parsed.fragment
            }
            
            # Check completeness
            has_scheme = bool(parsed.scheme)
            has_netloc = bool(parsed.netloc)
            
            if not has_scheme:
                result['issues'].append('Missing URL scheme (http/https)')
                result['warnings'].append('Incomplete URL: missing protocol')
            
            if not has_netloc:
                result['issues'].append('Missing domain/host')
                result['warnings'].append('Incomplete URL: missing hostname')
            
            result['is_complete'] = has_scheme and has_netloc
            result['is_valid'] = has_scheme and has_netloc
            
            # Security checks
            if parsed.path:
                # Check for path traversal
                if '..' in parsed.path or '../' in parsed.path or '..\\' in parsed.path:
                    result['threat_indicators'].append('Path traversal detected')
                    result['warnings'].append('Suspicious: directory traversal attempt')
                
                # Check for suspicious file extensions
                suspicious_extensions = ['.exe', '.bat', '.cmd', '.scr', '.vbs', '.js', '.jar']
                path_lower = parsed.path.lower()
                for ext in suspicious_extensions:
                    if ext in path_lower:
                        result['threat_indicators'].append(f'Suspicious file extension: {ext}')
                        result['warnings'].append(f'Warning: executable file in URL path')
            
            # Check query parameters for suspicious patterns
            if parsed.query:
                query_lower = parsed.query.lower()
                suspicious_patterns = [
                    r'<script', r'javascript:', r'onerror=', r'onload=',
                    r'union\s+select', r'drop\s+table', r'exec\s*\(',
                    r'\.\./', r'\.\.\\', r'%2e%2e'
                ]
                for pattern in suspicious_patterns:
                    if re.search(pattern, query_lower, re.IGNORECASE):
                        result['threat_indicators'].append(f'Malicious pattern in query: {pattern}')
                        result['warnings'].append('Suspicious: potential injection attack')
            
            # Check for IP address instead of domain (can be suspicious)
            if parsed.netloc:
                ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$'
                if re.match(ip_pattern, parsed.netloc.split(':')[0]):
                    result['warnings'].append('URL uses IP address instead of domain name')
            
            # Check for very long URLs (potential buffer overflow)
            if len(url) > 2048:
                result['warnings'].append('URL is very long (potential buffer overflow attempt)')
            
            # Check for encoding obfuscation
            if '%' in url and url.count('%') > 5:
                result['warnings'].append('Heavy URL encoding detected (possible obfuscation)')
            
            # Check for very long domain names (potential phishing)
            if parsed.netloc and len(parsed.netloc) > 25:
                result['threat_indicators'].append(f'Very long domain name ({len(parsed.netloc)} chars) - potential phishing')
                result['warnings'].append('Suspicious: domain name is unusually long')
            
            # Check for numeric-only paths (common in phishing)
            if parsed.path and len(parsed.path) > 1:
                path_without_slash = parsed.path.lstrip('/')
                if path_without_slash.isdigit() and len(path_without_slash) >= 6:
                    result['threat_indicators'].append('Numeric-only path detected - common phishing pattern')
                    result['warnings'].append('Suspicious: path contains only numbers (phishing indicator)')
            
        except Exception as e:
            result['issues'].append(f'URL parsing error: {str(e)}')
            result['is_valid'] = False
            result['is_complete'] = False
        
        return result


def analyze_flow_dpi(flow_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze network flow with DPI
    
    Args:
        flow_data: Network flow data
    
    Returns:
        Enhanced flow data with DPI information
    """
    engine = DPIEngine()
    
    # For now, simulate DPI analysis from flow metadata
    # In production, this would analyze actual packet bytes
    result = {
        'dpi_analyzed': True,
        'application_protocol': flow_data.get('protocol', 'UNKNOWN'),
        'application_name': None,
        'extracted_features': {},
        'threat_indicators': [],
        'timestamp': datetime.now().isoformat()
    }
    
    # Basic application identification from port
    dst_port = flow_data.get('dst_port') or flow_data.get('dest_port')
    if dst_port == 80:
        result['application_protocol'] = 'HTTP'
        result['application_name'] = 'Web Browser'
    elif dst_port == 443:
        result['application_protocol'] = 'HTTPS'
        result['application_name'] = 'Web Browser'
    elif dst_port == 53:
        result['application_protocol'] = 'DNS'
        result['application_name'] = 'DNS'
    elif dst_port == 21:
        result['application_protocol'] = 'FTP'
        result['application_name'] = 'FTP'
    elif dst_port == 25 or dst_port == 587:
        result['application_protocol'] = 'SMTP'
        result['application_name'] = 'Email'
    
    # If URL is provided in flow_data, validate it
    if 'url' in flow_data:
        url_validation = engine.validate_url(flow_data['url'])
        result['url_validation'] = url_validation
        if url_validation.get('threat_indicators'):
            result['threat_indicators'].extend(url_validation['threat_indicators'])
    
    # Check for URL in pkt_hash or other fields (if it looks like a URL)
    for field in ['pkt_hash', 'src_ip', 'dst_ip']:
        value = flow_data.get(field, '')
        if isinstance(value, str) and ('http://' in value.lower() or 'https://' in value.lower()):
            url_validation = engine.validate_url(value)
            if url_validation.get('threat_indicators'):
                result['threat_indicators'].extend(url_validation['threat_indicators'])
    
    return result

