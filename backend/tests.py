"""
NGFW System Test Suite
جميع اختبارات النظام في ملف واحد
"""

import os
import sys
import requests
import json
import time
import io
import psycopg2
import pandas as pd
from datetime import datetime
from typing import Dict, Any, List

# Fix encoding for Windows console
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# ============================================================================
# Configuration
# ============================================================================

BASE_URL = "http://127.0.0.1:5000"
API_BASE = f"{BASE_URL}/api"

# Database configuration
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "127.0.0.1"),
    "port": int(os.getenv("DB_PORT", 5432)),
    "dbname": os.getenv("DB_NAME", "ngfw_db"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASS", "1234")
}

# Test URLs
SUSPICIOUS_URLS = [
    {
        "name": "Path Traversal Attack",
        "url": "http://example.com/../../../etc/passwd",
        "description": "محاولة directory traversal"
    },
    {
        "name": "SQL Injection",
        "url": "http://example.com/login?user=admin' OR '1'='1",
        "description": "محاولة SQL injection"
    },
    {
        "name": "XSS Attack",
        "url": "http://example.com/page?name=<script>alert('XSS')</script>",
        "description": "محاولة cross-site scripting"
    },
    {
        "name": "Executable File Download",
        "url": "http://example.com/download/malware.exe",
        "description": "تحميل ملف executable مشبوه"
    },
    {
        "name": "Command Injection",
        "url": "http://example.com/search?cmd=;cat /etc/passwd",
        "description": "محاولة command injection"
    }
]

TEST_URLS = [
    {"name": "URL بدون scheme", "url": "example.com/path", "expected_blocked": False},
    {"name": "URL بدون host", "url": "http:///path/to/file", "expected_blocked": False},
    {"name": "Path traversal", "url": "http://example.com/../../../etc/passwd", "expected_blocked": True},
    {"name": "SQL Injection", "url": "http://example.com/search?q=admin' OR '1'='1", "expected_blocked": True},
    {"name": "XSS", "url": "http://example.com/page?name=<script>alert('xss')</script>", "expected_blocked": True},
    {"name": "URL صحيح", "url": "http://example.com/page", "expected_blocked": False},
]

# ============================================================================
# Utility Functions
# ============================================================================

def print_header(text):
    print("\n" + "="*60)
    print(f"  {text}")
    print("="*60)

def print_success(text):
    print(f"✅ {text}")

def print_error(text):
    print(f"❌ {text}")

def print_info(text):
    print(f"ℹ️  {text}")

def check_backend():
    """التحقق من أن Backend يعمل"""
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=3)
        return response.status_code == 200
    except:
        return False

# ============================================================================
# Database Tests
# ============================================================================

def test_database_connection():
    """اختبار الاتصال بقاعدة البيانات"""
    print_header("Database Connection Test")
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        print_success("Database connection successful!")
        print(f"   Host: {DB_CONFIG['host']}")
        print(f"   Database: {DB_CONFIG['dbname']}")
        conn.close()
        return True
    except Exception as e:
        print_error(f"Database connection failed: {e}")
        return False

def test_database_schema():
    """اختبار schema قاعدة البيانات"""
    print_header("Database Schema Test")
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Check if table exists
        cursor.execute("""
            SELECT column_name, data_type
            FROM information_schema.columns
            WHERE table_name = 'network_flows'
            ORDER BY ordinal_position
        """)
        cols = cursor.fetchall()
        
        if cols:
            print_success(f"Table 'network_flows' found with {len(cols)} columns")
            print("\n   Columns:")
            for name, dtype in cols[:10]:  # Show first 10
                print(f"   - {name} ({dtype})")
            if len(cols) > 10:
                print(f"   ... and {len(cols) - 10} more columns")
        else:
            print_error("Table 'network_flows' not found")
            return False
        
        # Check row count
        cursor.execute("SELECT COUNT(*) FROM network_flows")
        count = cursor.fetchone()[0]
        print_info(f"Total rows: {count}")
        
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print_error(f"Schema test failed: {e}")
        return False

# ============================================================================
# API Tests
# ============================================================================

def test_health():
    """Test health endpoint"""
    print_header("1. Health Check")
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print_success("Backend is healthy!")
            print(f"   Status: {data.get('status')}")
            print(f"   Model Loaded: {data.get('model_loaded')}")
            print(f"   Preprocessor: {data.get('preproc')}")
            return True
        else:
            print_error(f"Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Health check failed: {e}")
        return False

def test_ingest():
    """Test ingest endpoint"""
    print_header("2. Ingest Test")
    try:
        test_flow = {
            "src_ip": "192.168.1.100",
            "dst_ip": "8.8.8.8",
            "src_port": 54321,
            "dst_port": 80,
            "protocol": "TCP",
            "pkt_hash": f"test-{int(time.time())}",
            "flow_duration": 5.25,
            "tot_fwd_pkts": 150,
            "tot_bwd_pkts": 75,
            "totlen_fwd_pkts": 15000,
            "totlen_bwd_pkts": 7500
        }
        
        response = requests.post(f"{BASE_URL}/ingest", json=test_flow, timeout=5)
        if response.status_code == 201:
            data = response.json()
            print_success("Flow ingested successfully!")
            print(f"   Flow ID: {data.get('flow_id')}")
            return data.get('flow_id')
        else:
            print_error(f"Ingest failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return None
    except Exception as e:
        print_error(f"Ingest failed: {e}")
        return None

def test_events():
    """Test events endpoint"""
    print_header("3. Events API Test")
    try:
        response = requests.get(f"{API_BASE}/events?n=5", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print_success(f"Retrieved {len(data)} events")
            if len(data) > 0:
                first = data[0]
                print(f"\n   Sample Event:")
                print(f"   - ID: {first.get('id')}")
                print(f"   - Source IP: {first.get('src_ip')}")
                print(f"   - Dest IP: {first.get('dst_ip')}")
                print(f"   - Protocol: {first.get('protocol')}")
            return True
        else:
            print_error(f"Events API failed: {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Events API failed: {e}")
        return False

def test_signatures():
    """Test signatures endpoint"""
    print_header("4. Signatures API Test")
    try:
        response = requests.get(f"{API_BASE}/signatures", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print_success(f"Retrieved {len(data)} signatures")
            if len(data) > 0:
                print(f"\n   Sample Signatures:")
                for sig in data[:3]:
                    print(f"   - {sig.get('name')} ({sig.get('severity')})")
            return True
        else:
            print_error(f"Signatures API failed: {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Signatures API failed: {e}")
        return False

def test_blocked_ips():
    """Test blocked IPs endpoint"""
    print_header("5. Blocked IPs API Test")
    try:
        response = requests.get(f"{API_BASE}/blocked", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print_success(f"Retrieved {len(data)} blocked IPs")
            if len(data) > 0:
                for blocked in data:
                    print(f"   - {blocked.get('ip')} (until {blocked.get('blocked_until')})")
            else:
                print_info("No IPs currently blocked")
            return True
        else:
            print_error(f"Blocked IPs API failed: {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Blocked IPs API failed: {e}")
        return False

def test_enhanced_ingest():
    """Test enhanced ingest endpoint"""
    print_header("6. Enhanced Ingest Test")
    try:
        test_flow = {
            "src_ip": "10.0.0.100",
            "dst_ip": "104.29.146.192",
            "src_port": 12345,
            "dst_port": 443,
            "protocol": "HTTPS",
            "pkt_hash": f"enhanced-test-{int(time.time())}",
            "flow_duration": 12.5,
            "tot_fwd_pkts": 200
        }
        
        response = requests.post(f"{API_BASE}/ingest-enhanced", json=test_flow, timeout=10)
        if response.status_code == 201:
            data = response.json()
            print_success("Enhanced ingest successful!")
            print(f"   Flow ID: {data.get('flow_id')}")
            print(f"   Status: {data.get('status')}")
            return True
        else:
            print_error(f"Enhanced ingest failed: {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Enhanced ingest failed: {e}")
        return False

def test_threats():
    """Test threats endpoint"""
    print_header("7. Threats API Test")
    try:
        response = requests.get(f"{API_BASE}/threats?n=3", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print_success(f"Retrieved {len(data)} threats")
            if len(data) > 0:
                for threat in data[:2]:
                    print(f"\n   Threat ID: {threat.get('id')}")
                    print(f"   - Source: {threat.get('src_ip')}")
                    print(f"   - Threat Level: {threat.get('threat_level')}")
            else:
                print_info("No threats detected")
            return True
        else:
            print_error(f"Threats API failed: {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Threats API failed: {e}")
        return False

# ============================================================================
# URL Validation Tests
# ============================================================================

def test_url_validation():
    """Test URL validation directly"""
    print_header("URL Validation Test")
    try:
        from dpi_engine import DPIEngine
        engine = DPIEngine()
        
        for test_case in TEST_URLS:
            url = test_case["url"]
            print(f"\n[TEST] {test_case['name']}")
            print(f"   URL: {url}")
            
            result = engine.validate_url(url)
            print(f"   Valid: {result['is_valid']}")
            print(f"   Complete: {result['is_complete']}")
            
            if result.get('threat_indicators'):
                print(f"   [THREAT] Threats: {result['threat_indicators']}")
        return True
    except Exception as e:
        print_error(f"URL validation test failed: {e}")
        return False

def test_suspicious_urls():
    """Test suspicious URLs"""
    print_header("Suspicious URLs Test")
    results = []
    
    for test_case in SUSPICIOUS_URLS:
        url = test_case["url"]
        print(f"\n[TEST] {test_case['name']}")
        print(f"   URL: {url}")
        
        try:
            response = requests.post(f"{API_BASE}/test-url", json={"url": url}, timeout=5)
            if response.status_code == 200:
                data = response.json()
                blocked = data.get('blocked', False)
                action = data.get('ips_decision', {}).get('action', 'alert')
                
                if blocked or action == 'block':
                    print_success("URL blocked!")
                    results.append({"name": test_case["name"], "blocked": True})
                else:
                    print_info("URL detected but not blocked")
                    results.append({"name": test_case["name"], "blocked": False})
        except Exception as e:
            print_error(f"Test failed: {e}")
            results.append({"name": test_case["name"], "blocked": False})
    
    return results

# ============================================================================
# ML Model Tests
# ============================================================================

def test_ml_files():
    """Test ML model files"""
    print_header("ML Model Files Test")
    try:
        model_path = os.path.join('ml', 'lgb_model.txt')
        preproc_path = os.path.join('ml', 'preproc.joblib')
        
        if os.path.exists(model_path):
            print_success(f"Model found: {model_path}")
        else:
            print_error(f"Model not found: {model_path}")
            return False
        
        if os.path.exists(preproc_path):
            print_success(f"Preprocessor found: {preproc_path}")
        else:
            print_error(f"Preprocessor not found: {preproc_path}")
            return False
        
        return True
    except Exception as e:
        print_error(f"ML files test failed: {e}")
        return False

# ============================================================================
# Main Test Runner
# ============================================================================

def run_all_tests():
    """Run all tests"""
    print("\n" + "="*60)
    print("  NGFW System Test Suite")
    print(f"  Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)
    
    results = []
    
    # Database tests (always run)
    results.append(("Database Connection", test_database_connection()))
    results.append(("Database Schema", test_database_schema()))
    results.append(("ML Files", test_ml_files()))
    
    # API tests (require backend)
    if check_backend():
        print_success("Backend is running, running API tests...")
        results.append(("Health Check", test_health()))
        results.append(("Ingest", test_ingest()))
        results.append(("Events API", test_events()))
        results.append(("Signatures API", test_signatures()))
        results.append(("Blocked IPs API", test_blocked_ips()))
        results.append(("Enhanced Ingest", test_enhanced_ingest()))
        results.append(("Threats API", test_threats()))
        results.append(("URL Validation", test_url_validation()))
        test_suspicious_urls()
    else:
        print_error("Backend is not running. Skipping API tests.")
        print_info("Start backend with: python app.py")
    
    # Summary
    print_header("Test Summary")
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {status} - {name}")
    
    print(f"\n  Total: {passed}/{total} tests passed")
    
    if passed == total:
        print_success("All tests passed! 🎉")
    else:
        print_error(f"{total - passed} test(s) failed")
    
    print(f"\n  Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60 + "\n")

if __name__ == "__main__":
    run_all_tests()








