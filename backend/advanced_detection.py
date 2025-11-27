"""
Advanced Phishing Detection Module
Modern techniques for URL threat detection:
- Entropy analysis
- Homoglyph detection
- Brand impersonation
- URL shortening detection
- Domain reputation
- Behavioral analysis
"""

import re
import math
import logging
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse
from collections import Counter

LOG = logging.getLogger("advanced_detection")

# Brand names for impersonation detection
KNOWN_BRANDS = {
    'google': ['go0gle', 'go0g1e', 'g00gle', 'go.ogle', 'gogle', 'goog1e', 'g0ogle'],
    'youtube': ['y0utube', 'youtub', 'yotube', 'y0utub', 'youtub3'],
    'facebook': ['facebok', 'faceb00k', 'fac3book', 'faceb0ok', 'f4cebook'],
    'amazon': ['amazom', 'amaz0n', 'amaz0m', 'amaz0n', 'amazom'],
    'paypal': ['paypall', 'paypa1', 'payp@l', 'payp4l', 'payp@1'],
    'microsoft': ['micros0ft', 'micr0soft', 'microsft', 'micr0s0ft'],
    'apple': ['app1e', 'app1e', 'appl3', 'aple'],
    'twitter': ['twitt3r', 'twittr', 'tw1tter', 'twitt3r'],
    'instagram': ['instagr4m', 'instagrm', 'instagr@m'],
    'linkedin': ['link3din', 'linkdin', 'link3d1n'],
    'whatsapp': ['whats4pp', 'whatsap', 'whats@pp'],
    'ebay': ['3bay', 'eb@y', '3b@y'],
    'netflix': ['netfl1x', 'netflx', 'netfl1x'],
    'spotify': ['spot1fy', 'spotfy', 'spot1fy'],
    'bank': ['b4nk', 'b@nk', 'bankk'],
    'chase': ['ch4se', 'chas3', 'ch@se'],
    'wells': ['w3lls', 'wellss', 'w3lls'],
}

# URL shortening services
SHORTENING_SERVICES = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'short.link', 'rebrand.ly', 'cutt.ly', 'shorturl.at',
    'tiny.cc', 'v.gd', 'shorte.st', 'adf.ly', 'bc.vc', 'u.to'
]

# Suspicious TLDs
SUSPICIOUS_TLDS = [
    '.cc', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz',
    '.click', '.download', '.stream', '.online', '.site', '.website'
]

# Homoglyph character mappings
HOMOGLYPHS = {
    'o': ['0', 'O', 'о', 'ο'],  # o, 0, O, Cyrillic о, Greek ο
    'a': ['@', 'а', 'α'],  # a, @, Cyrillic а, Greek α
    'e': ['3', 'е', 'ε'],  # e, 3, Cyrillic е, Greek ε
    'i': ['1', 'l', 'і', 'ι'],  # i, 1, l, Cyrillic і, Greek ι
    's': ['5', '$', 'ѕ'],  # s, 5, $, Cyrillic ѕ
    'g': ['9', 'q'],  # g, 9, q
    'z': ['2'],  # z, 2
    'b': ['6'],  # b, 6
}


class AdvancedDetectionEngine:
    """Advanced phishing detection using modern techniques"""
    
    def __init__(self):
        self.brand_patterns = self._build_brand_patterns()
    
    def _build_brand_patterns(self) -> Dict[str, re.Pattern]:
        """Build regex patterns for brand detection"""
        patterns = {}
        for brand, variants in KNOWN_BRANDS.items():
            # Create pattern that matches brand name or variants
            pattern_parts = [re.escape(brand)]
            pattern_parts.extend([re.escape(v) for v in variants])
            pattern = r'(?i)(' + '|'.join(pattern_parts) + r')'
            patterns[brand] = re.compile(pattern)
        return patterns
    
    def calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of a string
        Higher entropy = more random/unpredictable (potentially suspicious)
        """
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = Counter(text.lower())
        length = len(text)
        
        # Calculate entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def detect_homoglyphs(self, domain: str) -> Dict[str, Any]:
        """
        Detect homoglyph attacks (e.g., go.ogle instead of google)
        """
        result = {
            'has_homoglyphs': False,
            'homoglyph_count': 0,
            'suspicious_chars': [],
            'potential_brand': None
        }
        
        domain_lower = domain.lower()
        
        # Check for homoglyph characters
        for normal_char, homoglyphs in HOMOGLYPHS.items():
            for hg in homoglyphs:
                if hg in domain_lower:
                    result['has_homoglyphs'] = True
                    result['homoglyph_count'] += domain_lower.count(hg)
                    if hg not in result['suspicious_chars']:
                        result['suspicious_chars'].append(hg)
        
        # Check for brand impersonation using homoglyphs
        for brand, pattern in self.brand_patterns.items():
            if pattern.search(domain_lower):
                result['potential_brand'] = brand
                break
        
        return result
    
    def detect_brand_impersonation(self, url: str) -> Dict[str, Any]:
        """
        Detect brand impersonation attempts
        """
        result = {
            'is_impersonation': False,
            'impersonated_brand': None,
            'confidence': 0.0,
            'indicators': []
        }
        
        url_lower = url.lower()
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'http://{url}')
        domain = parsed.netloc.split(':')[0].lower()
        domain_without_tld = domain.rsplit('.', 1)[0] if '.' in domain else domain
        domain_lower = domain.lower()
        
        # Check for brand names in domain
        for brand, variants in KNOWN_BRANDS.items():
            # Check exact brand name
            if brand in domain_lower:
                # But domain is not the actual brand domain
                if not any(actual_domain in domain for actual_domain in [
                    f'{brand}.com', f'{brand}.net', f'{brand}.org',
                    f'www.{brand}.com', f'www.{brand}.net'
                ]):
                    result['is_impersonation'] = True
                    result['impersonated_brand'] = brand
                    result['confidence'] = 0.9
                    result['indicators'].append(f'Brand name "{brand}" found in suspicious domain')
                    break
            
            # Check variants
            for variant in variants:
                if variant in domain_lower:
                    result['is_impersonation'] = True
                    result['impersonated_brand'] = brand
                    result['confidence'] = 0.95  # Higher confidence for variants
                    result['indicators'].append(f'Brand variant "{variant}" detected (impersonating {brand})')
                    break
        
        # Check for homoglyph-based impersonation
        homoglyph_result = self.detect_homoglyphs(domain)
        if homoglyph_result['potential_brand']:
            result['is_impersonation'] = True
            result['impersonated_brand'] = homoglyph_result['potential_brand']
            result['confidence'] = 0.85
            result['indicators'].append('Homoglyph-based brand impersonation detected')
        
        return result
    
    def detect_url_shortening(self, url: str) -> Dict[str, Any]:
        """
        Detect URL shortening services
        """
        result = {
            'is_shortened': False,
            'shortening_service': None,
            'risk_level': 'low'
        }
        
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'http://{url}')
        domain = parsed.netloc.split(':')[0].lower()
        
        for service in SHORTENING_SERVICES:
            if service in domain:
                result['is_shortened'] = True
                result['shortening_service'] = service
                result['risk_level'] = 'medium'  # Shortened URLs can hide destination
                break
        
        return result
    
    def analyze_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """
        Analyze domain characteristics for reputation scoring
        """
        result = {
            'reputation_score': 50,  # Neutral score (0-100, lower = more suspicious)
            'indicators': [],
            'risk_factors': []
        }
        
        domain_lower = domain.lower()
        
        # Check domain length
        if len(domain) > 25:
            result['reputation_score'] -= 15
            result['risk_factors'].append('Very long domain name')
        
        # Check for suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                result['reputation_score'] -= 20
                result['risk_factors'].append(f'Suspicious TLD: {tld}')
                break
        
        # Check for numbers in domain (can be suspicious)
        if any(c.isdigit() for c in domain):
            digit_count = sum(c.isdigit() for c in domain)
            if digit_count > 3:
                result['reputation_score'] -= 10
                result['risk_factors'].append('Multiple digits in domain')
        
        # Check for hyphens (can be suspicious if many)
        hyphen_count = domain.count('-')
        if hyphen_count > 2:
            result['reputation_score'] -= 10
            result['risk_factors'].append('Multiple hyphens in domain')
        
        # Check for subdomains (too many can be suspicious)
        subdomain_count = domain.count('.') - 1
        if subdomain_count > 3:
            result['reputation_score'] -= 10
            result['risk_factors'].append('Too many subdomains')
        
        # Check entropy (high entropy = random = suspicious)
        entropy = self.calculate_entropy(domain)
        if entropy > 4.0:  # High entropy threshold
            result['reputation_score'] -= 15
            result['risk_factors'].append('High entropy (random-looking domain)')
        
        # Ensure score doesn't go below 0
        result['reputation_score'] = max(0, result['reputation_score'])
        
        if result['reputation_score'] < 30:
            result['indicators'].append('Low domain reputation score')
        
        return result
    
    def detect_suspicious_patterns(self, url: str) -> Dict[str, Any]:
        """
        Detect various suspicious patterns in URLs
        """
        result = {
            'patterns_detected': [],
            'risk_score': 0,
            'indicators': []
        }
        
        url_lower = url.lower()
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'http://{url}')
        domain = parsed.netloc.split(':')[0]
        path = parsed.path
        query = parsed.query
        
        # Check for numeric-only path (common in phishing)
        if path and len(path) > 1:
            path_without_slash = path.lstrip('/')
            if path_without_slash.isdigit() and len(path_without_slash) >= 6:
                result['patterns_detected'].append('numeric_path')
                result['risk_score'] += 30
                result['indicators'].append('Numeric-only path detected')
        
        # Check for very long path
        if len(path) > 100:
            result['patterns_detected'].append('long_path')
            result['risk_score'] += 10
            result['indicators'].append('Very long URL path')
        
        # Check for suspicious query parameters
        suspicious_query_patterns = [
            r'redirect=', r'url=', r'link=', r'goto=', r'next=',
            r'return=', r'continue=', r'dest=', r'target='
        ]
        for pattern in suspicious_query_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                result['patterns_detected'].append('suspicious_query')
                result['risk_score'] += 15
                result['indicators'].append('Suspicious query parameter detected')
                break
        
        # Check for IP address in URL
        ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
        if re.search(ip_pattern, domain):
            result['patterns_detected'].append('ip_address')
            result['risk_score'] += 20
            result['indicators'].append('IP address used instead of domain')
        
        # Check for port number (can be suspicious)
        if ':' in parsed.netloc and not re.match(r'^(\d{1,3}\.){3}\d{1,3}', parsed.netloc.split(':')[0]):
            port = parsed.netloc.split(':')[1]
            if port.isdigit() and int(port) not in [80, 443, 8080, 8443]:
                result['patterns_detected'].append('non_standard_port')
                result['risk_score'] += 10
                result['indicators'].append('Non-standard port number')
        
        return result
    
    def comprehensive_analysis(self, url: str) -> Dict[str, Any]:
        """
        Perform comprehensive analysis using all advanced techniques
        """
        result = {
            'url': url,
            'overall_risk_score': 0,  # 0-100, higher = more risky
            'threat_level': 'low',  # low, medium, high, critical
            'detections': {},
            'recommendation': 'allow'
        }
        
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'http://{url}')
        domain = parsed.netloc.split(':')[0] if parsed.netloc else ''
        
        # 1. Entropy analysis
        url_entropy = self.calculate_entropy(url)
        domain_entropy = self.calculate_entropy(domain)
        result['detections']['entropy'] = {
            'url_entropy': url_entropy,
            'domain_entropy': domain_entropy,
            'is_suspicious': url_entropy > 4.5 or domain_entropy > 4.0
        }
        if result['detections']['entropy']['is_suspicious']:
            result['overall_risk_score'] += 20
        
        # 2. Homoglyph detection
        homoglyph_result = self.detect_homoglyphs(domain)
        result['detections']['homoglyphs'] = homoglyph_result
        if homoglyph_result['has_homoglyphs']:
            result['overall_risk_score'] += 25
        
        # 3. Brand impersonation
        brand_result = self.detect_brand_impersonation(url)
        result['detections']['brand_impersonation'] = brand_result
        if brand_result['is_impersonation']:
            result['overall_risk_score'] += 40
        
        # 4. URL shortening
        shortening_result = self.detect_url_shortening(url)
        result['detections']['url_shortening'] = shortening_result
        if shortening_result['is_shortened']:
            result['overall_risk_score'] += 15
        
        # 5. Domain reputation
        reputation_result = self.analyze_domain_reputation(domain)
        result['detections']['domain_reputation'] = reputation_result
        # Convert reputation score to risk (lower reputation = higher risk)
        risk_from_reputation = 50 - reputation_result['reputation_score']
        result['overall_risk_score'] += risk_from_reputation
        
        # 6. Suspicious patterns
        pattern_result = self.detect_suspicious_patterns(url)
        result['detections']['suspicious_patterns'] = pattern_result
        result['overall_risk_score'] += pattern_result['risk_score']
        
        # Determine threat level
        if result['overall_risk_score'] >= 70:
            result['threat_level'] = 'critical'
            result['recommendation'] = 'block'
        elif result['overall_risk_score'] >= 50:
            result['threat_level'] = 'high'
            result['recommendation'] = 'block'
        elif result['overall_risk_score'] >= 30:
            result['threat_level'] = 'medium'
            result['recommendation'] = 'alert'
        else:
            result['threat_level'] = 'low'
            result['recommendation'] = 'allow'
        
        # Ensure score doesn't exceed 100
        result['overall_risk_score'] = min(100, result['overall_risk_score'])
        
        return result


# Global instance
_advanced_detection_engine = None

def get_advanced_detection_engine() -> AdvancedDetectionEngine:
    """Get global advanced detection engine instance"""
    global _advanced_detection_engine
    if _advanced_detection_engine is None:
        _advanced_detection_engine = AdvancedDetectionEngine()
    return _advanced_detection_engine

