"""
app.py - NGFW backend (Flask)
- يحاول التكيف مع سكيمات قاعدة البيانات المختلفة
- إذا لم يكن network_events.flow_id موجودًا، سيضيفه آليًا (nullable, no FK)
- يدعم تحميل preproc.joblib كـ dict أو transformer object
"""

import os
import sys
import json
import logging
import subprocess
import threading
import time
from datetime import datetime
from typing import List, Optional, Dict, Any
from pathlib import Path

import joblib
import psycopg2
from psycopg2 import sql
from flask import Flask, request, jsonify

# ---------- CONFIG ----------
LOG = logging.getLogger("ngfw")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s:%(name)s: %(message)s")

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "127.0.0.1"),
    "port": int(os.getenv("DB_PORT", 5432)),
    "dbname": os.getenv("DB_NAME", "ngfw_db"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASS", "1234"),
}

NETWORK_FLOWS_TABLE = os.getenv("NETWORK_FLOWS_TABLE", "network_flows")
NETWORK_EVENTS_TABLE = os.getenv("NETWORK_EVENTS_TABLE", "network_events")
ML_PRED_TABLE = os.getenv("ML_PRED_TABLE", "ml_predictions")

# Get project root directory (backend -> parent -> ml)
BACKEND_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = BACKEND_DIR.parent
ML_DIR = PROJECT_ROOT / "ml"

MODEL_PATH = str(ML_DIR / "lgb_model.txt")
PREPROC_PATH = str(ML_DIR / "preproc.joblib")
URL_MODEL_PATH = str(ML_DIR / "url_classifier_model.txt")
URL_PREPROC_PATH = str(ML_DIR / "url_preprocessor.joblib")

app = Flask(__name__)
from flask_cors import CORS
CORS(app)

model = None
preproc_obj = None
preproc_num_cols: Optional[List[str]] = None
url_model = None
url_preproc = None

# ---------- Utilities ----------
def get_db_conn():
    return psycopg2.connect(**DB_CONFIG)

def table_columns(conn, table_name: str) -> List[str]:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT column_name FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = %s
        ORDER BY ordinal_position
        """,
        (table_name,),
    )
    cols = [r[0] for r in cur.fetchall()]
    cur.close()
    return cols

# ---------- Ensure minimal tables ----------
def ensure_tables():
    try:
        with get_db_conn() as conn, conn.cursor() as cur:
            cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {NETWORK_FLOWS_TABLE} (
                id SERIAL PRIMARY KEY,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                timestamp TIMESTAMP WITH TIME ZONE DEFAULT now(),
                ml_label TEXT,
                ml_score DOUBLE PRECISION,
                pkt_hash TEXT,
                flow_duration DOUBLE PRECISION,
                tot_fwd_pkts INTEGER,
                tot_bwd_pkts INTEGER,
                totlen_fwd_pkts DOUBLE PRECISION,
                totlen_bwd_pkts DOUBLE PRECISION
            );
            """)
            # Add columns if they don't exist (for existing tables)
            cur.execute(f"""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                               WHERE table_name = '{NETWORK_FLOWS_TABLE}' AND column_name = 'flow_duration') THEN
                    ALTER TABLE {NETWORK_FLOWS_TABLE} ADD COLUMN flow_duration DOUBLE PRECISION;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                               WHERE table_name = '{NETWORK_FLOWS_TABLE}' AND column_name = 'tot_fwd_pkts') THEN
                    ALTER TABLE {NETWORK_FLOWS_TABLE} ADD COLUMN tot_fwd_pkts INTEGER;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                               WHERE table_name = '{NETWORK_FLOWS_TABLE}' AND column_name = 'tot_bwd_pkts') THEN
                    ALTER TABLE {NETWORK_FLOWS_TABLE} ADD COLUMN tot_bwd_pkts INTEGER;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                               WHERE table_name = '{NETWORK_FLOWS_TABLE}' AND column_name = 'totlen_fwd_pkts') THEN
                    ALTER TABLE {NETWORK_FLOWS_TABLE} ADD COLUMN totlen_fwd_pkts DOUBLE PRECISION;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                               WHERE table_name = '{NETWORK_FLOWS_TABLE}' AND column_name = 'totlen_bwd_pkts') THEN
                    ALTER TABLE {NETWORK_FLOWS_TABLE} ADD COLUMN totlen_bwd_pkts DOUBLE PRECISION;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                               WHERE table_name = '{NETWORK_FLOWS_TABLE}' AND column_name = 'url') THEN
                    ALTER TABLE {NETWORK_FLOWS_TABLE} ADD COLUMN url TEXT;
                END IF;
            END $$;
            """)
            cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {NETWORK_EVENTS_TABLE} (
                id SERIAL PRIMARY KEY,
                -- flow_id may be added later if not present
                event_type TEXT,
                ts TIMESTAMP WITH TIME ZONE DEFAULT now()
            );
            """)
            cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {ML_PRED_TABLE} (
                id SERIAL PRIMARY KEY,
                event_id INTEGER,
                pkt_hash TEXT,
                label TEXT,
                score DOUBLE PRECISION,
                model_version TEXT,
                ts TIMESTAMP WITH TIME ZONE DEFAULT now()
            );
            """)
            conn.commit()
            LOG.info("✅ Tables checked/created (minimal).")
    except Exception as e:
        LOG.exception("Failed to ensure tables: %s", e)
        raise

def ensure_url_checks_table():
    """Ensure url_checks table exists for storing URL check results"""
    try:
        with get_db_conn() as conn, conn.cursor() as cur:
            cur.execute("""
            CREATE TABLE IF NOT EXISTS url_checks (
                id SERIAL PRIMARY KEY,
                url TEXT NOT NULL,
                is_safe BOOLEAN NOT NULL,
                is_blocked BOOLEAN NOT NULL DEFAULT false,
                ml_score DOUBLE PRECISION,
                ml_label TEXT,
                ml_threshold DOUBLE PRECISION,
                ml_confidence DOUBLE PRECISION,
                url_validation JSONB,
                threat_indicators JSONB,
                signatures JSONB,
                ips_decision JSONB,
                checked_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
            );
            """)
            # Create indexes
            cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_url_checks_url ON url_checks(url);
            CREATE INDEX IF NOT EXISTS idx_url_checks_is_blocked ON url_checks(is_blocked);
            CREATE INDEX IF NOT EXISTS idx_url_checks_checked_at ON url_checks(checked_at);
            CREATE INDEX IF NOT EXISTS idx_url_checks_is_safe ON url_checks(is_safe);
            """)
            conn.commit()
            LOG.info("✅ url_checks table checked/created.")
    except Exception as e:
        LOG.exception("Failed to ensure url_checks table: %s", e)
        raise

# ---------- Load model & preproc ----------
def load_model_and_preproc():
    global model, preproc_obj, preproc_num_cols
    try:
        if os.path.exists(MODEL_PATH):
            try:
                import lightgbm as lgb
                model = lgb.Booster(model_file=MODEL_PATH)
                LOG.info("✅ Model loaded: %s", MODEL_PATH)
            except Exception:
                try:
                    model = joblib.load(MODEL_PATH)
                    LOG.info("✅ Model loaded via joblib: %s", MODEL_PATH)
                except Exception as e:
                    LOG.warning("Could not load model: %s", e)
                    model = None
        else:
            LOG.warning("Model file not found: %s", MODEL_PATH)

        if os.path.exists(PREPROC_PATH):
            p = joblib.load(PREPROC_PATH)
            LOG.info("Loaded preproc.joblib type: %s", type(p))
            if hasattr(p, "transform"):
                preproc_obj = p
                LOG.info("✅ Preproc loaded (object).")
            elif isinstance(p, dict):
                if "preprocessor" in p and hasattr(p["preprocessor"], "transform"):
                    preproc_obj = p["preprocessor"]
                    LOG.info("✅ Preproc loaded from dict['preprocessor'].")
                elif "num_cols" in p and isinstance(p["num_cols"], (list, tuple)):
                    preproc_num_cols = list(p["num_cols"])
                    LOG.info("✅ Preproc loaded (num_cols list).")
                else:
                    # try common keys
                    for k in ("num_cols", "cols", "columns"):
                        if k in p and isinstance(p[k], (list, tuple)):
                            preproc_num_cols = list(p[k])
                            LOG.info("✅ Preproc loaded from dict key '%s'.", k)
                            break
                    else:
                        LOG.warning("❌ No valid preprocessor inside preproc.joblib dict.")
            else:
                LOG.warning("❌ preproc found but not usable.")
        else:
            LOG.warning("preproc.joblib not found: %s", PREPROC_PATH)
    except Exception as e:
        LOG.exception("Failed loading model/preproc: %s", e)

# ---------- Load URL model & preproc ----------
def load_url_model_and_preproc():
    global url_model, url_preproc
    try:
        if os.path.exists(URL_MODEL_PATH):
            try:
                import lightgbm as lgb
                url_model = lgb.Booster(model_file=URL_MODEL_PATH)
                LOG.info("✅ URL Model loaded: %s", URL_MODEL_PATH)
            except Exception as e:
                LOG.warning("Could not load URL model: %s", e)
                url_model = None
        else:
            LOG.warning("URL Model file not found: %s", URL_MODEL_PATH)

        if os.path.exists(URL_PREPROC_PATH):
            url_preproc = joblib.load(URL_PREPROC_PATH)
            optimal_threshold = url_preproc.get('optimal_threshold', 0.5)
            LOG.info("✅ URL Preprocessor loaded: %s", URL_PREPROC_PATH)
            LOG.info("   Optimal threshold: %s", optimal_threshold)
        else:
            LOG.warning("URL Preprocessor not found: %s", URL_PREPROC_PATH)
    except Exception as e:
        LOG.exception("Failed loading URL model/preproc: %s", e)

# ---------- Active Learning: Retrain model from database ----------
def incremental_learn_from_db():
    """إعادة تدريب الموديل تلقائياً من البيانات الجديدة في قاعدة البيانات"""
    global url_model, url_preproc
    
    try:
        LOG.info("🔄 Starting incremental learning from database...")
        
        # Import training functions
        import sys
        sys.path.insert(0, str(ML_DIR))
        try:
            # noinspection PyUnresolvedReferences
            from train_url_classifier import (
                extract_url_features, load_phish_tank_data, load_phishing_site_urls_data,
                generate_safe_urls, prepare_dataset, train_model
            )
        except ImportError as e:
            LOG.error(f"Failed to import train_url_classifier: {e}")
            return jsonify({"error": "Training module not available", "success": False}), 500
        import pandas as pd
        from pathlib import Path
        
        # Load existing data sources
        PROJECT_ROOT = Path(__file__).parent.parent
        phish_df = load_phish_tank_data(PROJECT_ROOT / "PhishTank.csv")
        phishing_site_df = load_phishing_site_urls_data(PROJECT_ROOT / "phishing_site_urls.csv")
        
        # Load new data from database
        with get_db_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT url, is_safe, is_blocked, ml_score, checked_at
                FROM url_checks
                WHERE checked_at > now() - interval '7 days'
                ORDER BY checked_at DESC
            """)
            db_rows = cur.fetchall()
            cur.close()
        
        if not db_rows:
            LOG.info("   No new data from database to learn from")
            return
        
        LOG.info(f"   Found {len(db_rows)} URL checks from last 7 days")
        
        # Convert database results to DataFrame
        db_data = []
        for row in db_rows:
            url, is_safe, is_blocked, ml_score, checked_at = row
            # Use is_blocked as label (1 = malicious/blocked, 0 = safe)
            label = 0 if is_safe else 1
            db_data.append({'url': url, 'label': label})
        
        db_df = pd.DataFrame(db_data)
        
        # Remove duplicates
        db_df = db_df.drop_duplicates(subset=['url'])
        LOG.info(f"   After deduplication: {len(db_df)} unique URLs")
        
        # Split into safe and malicious
        db_safe = db_df[db_df['label'] == 0]
        db_malicious = db_df[db_df['label'] == 1]
        
        LOG.info(f"   Database data - Safe: {len(db_safe)}, Malicious: {len(db_malicious)}")
        
        # Combine with original data sources
        # Add database malicious URLs to phishing data
        if len(db_malicious) > 0:
            phish_df_combined = pd.concat([phish_df, db_malicious[['url', 'label']]], ignore_index=True)
            phish_df_combined = phish_df_combined.drop_duplicates(subset=['url'])
        else:
            phish_df_combined = phish_df
        
        # Add database safe URLs to safe data
        if len(db_safe) > 0:
            phishing_site_safe = phishing_site_df[phishing_site_df['label'] == 0] if len(phishing_site_df) > 0 else pd.DataFrame(columns=['url', 'label'])
            safe_combined = pd.concat([phishing_site_safe, db_safe[['url', 'label']]], ignore_index=True)
            safe_combined = safe_combined.drop_duplicates(subset=['url'])
        else:
            safe_combined = phishing_site_df[phishing_site_df['label'] == 0] if len(phishing_site_df) > 0 else pd.DataFrame(columns=['url', 'label'])
        
        # Generate additional safe URLs if needed
        total_malicious = len(phish_df_combined)
        total_safe = len(safe_combined)
        target_safe = int(total_malicious * 0.4)
        
        if total_safe < target_safe:
            n_additional = target_safe - total_safe
            generated_safe = generate_safe_urls(n_samples=min(n_additional, 10000))
            safe_combined = pd.concat([safe_combined, generated_safe], ignore_index=True)
        
        # Prepare dataset
        dataset = prepare_dataset(
            phish_df_combined, 
            safe_combined, 
            phishing_site_df=phishing_site_df if len(phishing_site_df) > 0 else None,
            balance_ratio=0.4
        )
        
        LOG.info(f"   Total training data: {len(dataset)} samples")
        
        # Retrain model
        new_model, feature_cols, optimal_threshold = train_model(dataset)
        
        # Save new model
        new_model.save_model(str(URL_MODEL_PATH))
        
        # Update preprocessor
        preprocessor = {
            'feature_columns': feature_cols,
            'model_type': 'lightgbm',
            'optimal_threshold': float(optimal_threshold),
            'default_threshold': 0.5
        }
        joblib.dump(preprocessor, URL_PREPROC_PATH)
        
        # Reload model in memory
        import lightgbm as lgb
        url_model = lgb.Booster(model_file=URL_MODEL_PATH)
        url_preproc = preprocessor
        
        LOG.info("✅ Model retrained and updated successfully!")
        LOG.info(f"   New optimal threshold: {optimal_threshold:.3f}")
        LOG.info(f"   Model saved to: {URL_MODEL_PATH}")
        
    except Exception as e:
        LOG.exception(f"❌ Incremental learning failed: {e}")
        # Don't raise - we don't want to break the main flow

# ---------- Trusted Domains Whitelist ----------
TRUSTED_DOMAINS = {
    # Major Tech Companies
    'google.com', 'youtube.com', 'gmail.com', 'googleusercontent.com',
    'microsoft.com', 'office.com', 'live.com', 'outlook.com',
    'apple.com', 'icloud.com', 'appleid.apple.com',
    'amazon.com', 'aws.amazon.com',
    'facebook.com', 'fb.com', 'instagram.com', 'whatsapp.com',
    'twitter.com', 'x.com', 't.co',
    'linkedin.com', 'github.com', 'stackoverflow.com',
    'netflix.com', 'spotify.com', 'twitch.tv',
    'reddit.com', 'pinterest.com', 'tumblr.com',
    'wikipedia.org', 'wikimedia.org',
    'dropbox.com', 'onedrive.com',
    'wordpress.com', 'blogger.com', 'medium.com',
    'bbc.com', 'cnn.com', 'reuters.com', 'theguardian.com',
    'yahoo.com', 'bing.com',
    # E-commerce
    'ebay.com', 'etsy.com', 'shopify.com',
    # Education
    'edu', 'coursera.org', 'udemy.com', 'khanacademy.org',
    # Cloud Services
    'cloudflare.com', 'akamai.com',
    # Remove www prefix for matching
}
TRUSTED_DOMAINS = {domain.replace('www.', '') for domain in TRUSTED_DOMAINS}

def is_trusted_domain(url: str) -> bool:
    """Check if URL belongs to a trusted domain"""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'http://{url}')
        domain = parsed.netloc.lower()
        # Remove port if present
        domain = domain.split(':')[0]
        
        # Always trust localhost and local IPs
        if domain in ['localhost', '127.0.0.1', '0.0.0.0', '::1']:
            return True
        if domain.startswith('127.') or domain.startswith('192.168.') or domain.startswith('10.') or domain.startswith('172.'):
            return True
        
        # Remove www prefix
        domain = domain.replace('www.', '')
        # Check exact match or subdomain
        if domain in TRUSTED_DOMAINS:
            return True
        # Check if it's a subdomain of trusted domain
        for trusted in TRUSTED_DOMAINS:
            if domain.endswith('.' + trusted):
                return True
        return False
    except:
        return False

# ---------- Extract URL features for ML ----------
def extract_url_features(url: str) -> dict:
    """استخراج features من URL لاستخدامها في ML - محسّن بتقنيات حديثة"""
    import re
    import math
    from urllib.parse import urlparse
    from collections import Counter
    
    features = {}
    
    if not url or not isinstance(url, str):
        url = ""
    
    url = url.strip().lower()
    
    # Basic features
    features['url_length'] = len(url)
    features['domain_length'] = 0
    features['path_length'] = 0
    features['query_length'] = 0
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_underscores'] = url.count('_')
    features['num_slashes'] = url.count('/')
    features['num_question_marks'] = url.count('?')
    features['num_equals'] = url.count('=')
    features['num_ampersands'] = url.count('&')
    features['num_percent'] = url.count('%')
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['num_letters'] = sum(c.isalpha() for c in url)
    
    # Parse URL
    try:
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'http://{url}')
        domain = parsed.netloc or parsed.path.split('/')[0] if parsed.path else ''
        path = parsed.path
        query = parsed.query
        
        features['domain_length'] = len(domain)
        features['path_length'] = len(path)
        features['query_length'] = len(query)
        
        # Domain features
        features['has_ip'] = bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$', domain.split(':')[0]))
        features['num_subdomains'] = domain.count('.') - 1 if '.' in domain else 0
        features['domain_has_digits'] = any(c.isdigit() for c in domain)
        
        # TLD features
        tld = domain.split('.')[-1] if '.' in domain else ''
        features['tld_length'] = len(tld)
        common_tlds = ['com', 'org', 'net', 'edu', 'gov', 'co', 'io', 'uk', 'de', 'fr']
        features['is_common_tld'] = tld in common_tlds
        
        # Trusted domain feature
        features['is_trusted_domain'] = is_trusted_domain(url)
        
        # Path features
        features['path_depth'] = path.count('/') - 1 if path else 0
        features['has_file_extension'] = bool(re.search(r'\.[a-z]{2,4}(/|$|\?|#)', path.lower()))
        
        # Suspicious patterns (expanded)
        suspicious_keywords = [
            'login', 'signin', 'sign-in', 'account', 'verify', 'confirm', 'update',
            'secure', 'banking', 'paypal', 'amazon', 'ebay', 'microsoft', 'apple',
            'admin', 'password', 'reset', 'unlock', 'suspended', 'locked',
            'webscr', 'cgi-bin', 'phishing', 'suspicious', 'alert', 'warning',
            'urgent', 'action-required', 'click-here', 'limited-time', 'expired'
        ]
        url_lower = url.lower()
        features['suspicious_keywords_count'] = sum(1 for kw in suspicious_keywords if kw in url_lower)
        
        # Brand impersonation detection
        brand_keywords = ['paypal', 'amazon', 'ebay', 'microsoft', 'apple', 'google',
                         'facebook', 'twitter', 'instagram', 'linkedin', 'whatsapp',
                         'bank', 'chase', 'wells-fargo', 'bank-of-america', 'santander']
        features['brand_keywords_count'] = sum(1 for kw in brand_keywords if kw in url_lower)
        
        # URL Entropy (Shannon entropy) - detects random-looking URLs
        def calculate_entropy(text):
            if not text:
                return 0.0
            char_counts = Counter(text.lower())
            length = len(text)
            entropy = 0.0
            for count in char_counts.values():
                probability = count / length
                if probability > 0:
                    entropy -= probability * math.log2(probability)
            return entropy
        
        features['url_entropy'] = calculate_entropy(url)
        features['domain_entropy'] = calculate_entropy(domain)
        
        # Homoglyph detection (e.g., go.ogle instead of google)
        homoglyph_chars = ['0', '@', '3', '1', '5', '$', '9', '2', '6']
        features['homoglyph_count'] = sum(1 for char in homoglyph_chars if char in domain.lower())
        features['has_homoglyphs'] = features['homoglyph_count'] > 0
        
        # URL shortening detection
        shortening_services = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
                              'buff.ly', 'short.link', 'rebrand.ly', 'cutt.ly']
        features['is_shortened_url'] = any(service in domain.lower() for service in shortening_services)
        
        # Suspicious TLD detection
        suspicious_tlds = ['.cc', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz']
        features['has_suspicious_tld'] = any(domain.endswith(tld) for tld in suspicious_tlds)
        
        # Encoding features
        features['has_encoding'] = '%' in url
        features['encoding_ratio'] = url.count('%') / len(url) if len(url) > 0 else 0
        
        # Special characters
        features['has_at_symbol'] = '@' in url
        features['has_port'] = ':' in domain and not domain.split(':')[0].replace('.', '').isdigit()
        
        # Path analysis
        if path:
            # Check if path is numeric only (phishing indicator)
            path_without_slash = path.lstrip('/')
            features['path_is_numeric'] = path_without_slash.isdigit() and len(path_without_slash) >= 6
            features['path_entropy'] = calculate_entropy(path)
        else:
            features['path_is_numeric'] = False
            features['path_entropy'] = 0.0
        
    except Exception as e:
        LOG.warning(f"Error parsing URL {url[:50]}: {e}")
    
    # URL structure features
    features['has_https'] = url.startswith('https://')
    features['has_http'] = url.startswith('http://')
    features['has_scheme'] = features['has_https'] or features['has_http']
    
    # Ratio features
    if features['url_length'] > 0:
        features['digit_ratio'] = features['num_digits'] / features['url_length']
        features['letter_ratio'] = features['num_letters'] / features['url_length']
        features['special_char_ratio'] = (features['url_length'] - features['num_digits'] - features['num_letters']) / features['url_length']
        features['dot_ratio'] = features['num_dots'] / features['url_length']
        features['slash_ratio'] = features['num_slashes'] / features['url_length']
    else:
        features['digit_ratio'] = 0
        features['letter_ratio'] = 0
        features['special_char_ratio'] = 0
        features['dot_ratio'] = 0
        features['slash_ratio'] = 0
    
    return features

# ---------- Insert flow (adapt to column names) ----------
def insert_flow(conn, **flow) -> int:
    cols_db = table_columns(conn, NETWORK_FLOWS_TABLE)
    # simple mapping and prefer names that exist
    mapping = {
        "src_ip": ["src_ip", "source_ip"],
        "dst_ip": ["dst_ip", "dest_ip", "destination_ip"],
        "src_port": ["src_port", "source_port"],
        "dst_port": ["dst_port", "dest_port"],
        "protocol": ["protocol", "proto"],
        "timestamp": ["timestamp", "ts"],
        "ml_label": ["ml_label", "label"],
        "ml_score": ["ml_score", "score"],
        "pkt_hash": ["pkt_hash", "packet_hash"],
    }
    insert_cols = []
    values = []
    # use mapping
    for std, aliases in mapping.items():
        for a in aliases:
            if a in cols_db and std in flow:
                insert_cols.append(a)
                values.append(flow[std])
                break
    # add any other keys directly present in both
    for k, v in flow.items():
        if k in cols_db and k not in insert_cols:
            insert_cols.append(k)
            values.append(v)
    if not insert_cols:
        insert_cols = ["src_ip"]
        values = [flow.get("src_ip")]
    cur = conn.cursor()
    insert_sql = sql.SQL("INSERT INTO {table} ({fields}) VALUES ({vals}) RETURNING id").format(
        table=sql.Identifier(NETWORK_FLOWS_TABLE),
        fields=sql.SQL(", ").join(map(sql.Identifier, insert_cols)),
        vals=sql.SQL(", ").join(sql.Placeholder() * len(insert_cols))
    )
    cur.execute(insert_sql, values)
    new_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    LOG.info("✅ Flow inserted id=%s", new_id)
    return new_id

# ---------- Ensure event for a flow (with auto-add of flow_id column if needed) ----------
def ensure_event_for_flow(conn, flow_id: int) -> int:
    """
    Returns an event id associated with the flow.
    If network_events has no flow_id column, add it (nullable).
    """
    cur = conn.cursor()
    cols = table_columns(conn, NETWORK_EVENTS_TABLE)
    # look for an existing candidate column that references flows
    candidate = None
    for c in ("flow_id", "network_flow_id", "flowid", "flow"):
        if c in cols:
            candidate = c
            break

    # if no candidate, add column named flow_id (nullable)
    if not candidate:
        try:
            LOG.info("network_events has no flow_id column. Adding 'flow_id' column...")
            cur.execute(sql.SQL("ALTER TABLE {tbl} ADD COLUMN IF NOT EXISTS flow_id INTEGER").format(
                tbl=sql.Identifier(NETWORK_EVENTS_TABLE)
            ))
            conn.commit()
            candidate = "flow_id"
            # refresh cols
            cols = table_columns(conn, NETWORK_EVENTS_TABLE)
        except Exception:
            LOG.exception("Failed to add flow_id column; proceeding without it.")
            # continue but candidate stays None

    # If candidate exists, try to find an existing event with that flow_id
    if candidate:
        try:
            cur.execute(sql.SQL("SELECT id FROM {tbl} WHERE {col} = %s LIMIT 1").format(
                tbl=sql.Identifier(NETWORK_EVENTS_TABLE),
                col=sql.Identifier(candidate)
            ), (flow_id,))
            row = cur.fetchone()
            if row:
                eid = row[0]
                cur.close()
                return eid
        except Exception:
            LOG.exception("Error selecting event by %s", candidate)

    # Insert a new event row and set flow_id if available
    try:
        if candidate:
            cur.execute(sql.SQL("INSERT INTO {tbl} ({flow_col}, event_type) VALUES (%s, %s) RETURNING id").format(
                tbl=sql.Identifier(NETWORK_EVENTS_TABLE),
                flow_col=sql.Identifier(candidate)
            ), (flow_id, "ingest"))
        else:
            cur.execute(sql.SQL("INSERT INTO {tbl} (event_type) VALUES (%s) RETURNING id").format(
                tbl=sql.Identifier(NETWORK_EVENTS_TABLE)
            ), ("ingest",))
        eid = cur.fetchone()[0]
        conn.commit()
        cur.close()
        LOG.info("Inserted event id=%s for flow=%s (col=%s)", eid, flow_id, candidate)
        return eid
    except Exception as e:
        LOG.exception("Failed to insert event: %s", e)
        cur.close()
        raise

def insert_prediction(conn, event_id: int, pkt_hash: str, label: str, score: float, model_version: str = "v1"):
    cur = conn.cursor()
    try:
        # if ml_predictions has event_id column? assume yes
        cur.execute(sql.SQL("INSERT INTO {tbl} (event_id, pkt_hash, label, score, model_version) VALUES (%s, %s, %s, %s, %s) RETURNING id").format(
            tbl=sql.Identifier(ML_PRED_TABLE)
        ), (event_id, pkt_hash, label, score, model_version))
        pid = cur.fetchone()[0]
        conn.commit()
        LOG.info("Inserted prediction id=%s for event=%s", pid, event_id)
        return pid
    except Exception:
        LOG.exception("Failed to insert prediction; attempting insert without event_id")
        try:
            cur.execute(sql.SQL("INSERT INTO {tbl} (pkt_hash, label, score, model_version) VALUES (%s, %s, %s, %s) RETURNING id").format(
                tbl=sql.Identifier(ML_PRED_TABLE)
            ), (pkt_hash, label, score, model_version))
            pid = cur.fetchone()[0]
            conn.commit()
            LOG.info("Inserted prediction id=%s (no event_id)", pid)
            return pid
        finally:
            cur.close()

# ---------- Endpoints ----------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "model_loaded": model is not None, "preproc": "object" if preproc_obj else ("num_cols" if preproc_num_cols else None)})

@app.route("/ingest", methods=["POST"])
def ingest():
    payload = request.get_json(force=True)
    LOG.info("Ingest: %s", payload)
    src_ip = payload.get("src_ip") or payload.get("source_ip")
    dst_ip = payload.get("dst_ip") or payload.get("dest_ip") or payload.get("destination_ip")
    src_port = payload.get("src_port") or payload.get("source_port")
    dst_port = payload.get("dst_port") or payload.get("dest_port")
    proto = payload.get("protocol") or payload.get("proto")
    pkt_hash = payload.get("pkt_hash") or payload.get("packet_hash")
    # Include all additional fields (flow_duration, tot_fwd_pkts, etc.)
    flow = dict(
        src_ip=src_ip, 
        dst_ip=dst_ip, 
        src_port=src_port, 
        dst_port=dst_port, 
        protocol=proto, 
        pkt_hash=pkt_hash,
        flow_duration=payload.get("flow_duration"),
        tot_fwd_pkts=payload.get("tot_fwd_pkts"),
        tot_bwd_pkts=payload.get("tot_bwd_pkts"),
        totlen_fwd_pkts=payload.get("totlen_fwd_pkts"),
        totlen_bwd_pkts=payload.get("totlen_bwd_pkts"),
    )
    # Remove None values
    flow = {k: v for k, v in flow.items() if v is not None}
    try:
        with get_db_conn() as conn:
            flow_id = insert_flow(conn, **flow)
            ensure_event_for_flow(conn, flow_id)
        return jsonify({"status": "created", "flow_id": flow_id}), 201
    except Exception as e:
        LOG.exception("ingest failed: %s", e)
        return jsonify({"error": str(e)}), 500

@app.route("/predict", methods=["POST"])
def predict():
    payload = request.get_json(force=True)
    LOG.info("predict request keys: %s", list(payload.keys()))
    event = payload.get("event") if isinstance(payload.get("event"), dict) else payload
    flow_id = event.get("flow_id") or event.get("flowId") or payload.get("flow_id")
    row_for_features = {}
    try:
        if flow_id:
            with get_db_conn() as conn:
                cur = conn.cursor()
                cur.execute(sql.SQL("SELECT * FROM {tbl} WHERE id=%s LIMIT 1").format(tbl=sql.Identifier(NETWORK_FLOWS_TABLE)), (flow_id,))
                r = cur.fetchone()
                if r:
                    cols = [c.name for c in cur.description]
                    row_for_features = dict(zip(cols, r))
    except Exception:
        LOG.exception("Could not load flow row for features")

    features_src = event.get("features") or event.get("flow") or event or {}
    features = {**row_for_features, **features_src}

    import pandas as pd
    df = pd.DataFrame([features])
    try:
        if preproc_obj is not None:
            X = preproc_obj.transform(df)
        elif preproc_num_cols:
            cols = preproc_num_cols
            df_sel = pd.DataFrame([{c: features.get(c, 0) for c in cols}])
            X = df_sel.values
        else:
            X = df.select_dtypes(include=["number"]).fillna(0).values

        if model is None:
            raise ValueError("Model not loaded.")
        try:
            import lightgbm as lgb
            if isinstance(model, lgb.Booster):
                preds = model.predict(X)
                score = float(preds[0])
                label = "malicious" if score >= 0.5 else "benign"
            else:
                score = float(model.predict_proba(X)[0, 1]) if hasattr(model, "predict_proba") else float(model.predict(X)[0])
                label = "malicious" if score >= 0.5 else "benign"
        except Exception:
            score = float(model.predict(X)[0])
            label = "malicious" if score >= 0.5 else "benign"

        pkt_hash = features.get("pkt_hash") or features.get("packet_hash") or f"predict-{int(datetime.now().timestamp())}"
        with get_db_conn() as conn:
            if not flow_id:
                flow_id = insert_flow(conn,
                                       src_ip=features.get("src_ip"),
                                       dst_ip=features.get("dst_ip"),
                                       src_port=features.get("src_port"),
                                       dst_port=features.get("dst_port"),
                                       protocol=features.get("protocol"),
                                       pkt_hash=pkt_hash)
            event_id = ensure_event_for_flow(conn, flow_id)
            insert_prediction(conn, event_id=event_id, pkt_hash=pkt_hash, label=label, score=score, model_version="v1")
        return jsonify({"label": label, "score": score, "flow_id": flow_id}), 200
    except Exception as e:
        LOG.exception("❌ Prediction failed: %s", e)
        return jsonify({"error": str(e)}), 500

@app.route("/api/events", methods=["GET"])
def api_events():
    n = int(request.args.get("n", 50))
    try:
        with get_db_conn() as conn, conn.cursor() as cur:
            # Get all columns dynamically to include flow_duration, tot_fwd_pkts, etc.
            cols = table_columns(conn, NETWORK_FLOWS_TABLE)
            if not cols:
                return jsonify({"error": "Table not found or has no columns"}), 404
            
            # Build SELECT query with all columns
            select_cols = sql.SQL(", ").join([sql.Identifier(c) for c in cols])
            cur.execute(sql.SQL("""
                SELECT {cols}
                FROM {tbl} f
                ORDER BY f.id DESC LIMIT %s
            """).format(
                cols=select_cols,
                tbl=sql.Identifier(NETWORK_FLOWS_TABLE)
            ), (n,))
            rows = cur.fetchall()
            # Convert rows to dictionaries with proper column names
            data = [dict(zip(cols, r)) for r in rows]
        return jsonify(data), 200
    except Exception as e:
        LOG.exception("Failed to read events: %s", e)
        return jsonify({"error": str(e)}), 500

# ---------- NGFW Enhanced Endpoints ----------
@app.route("/api/threats", methods=["GET"])
def api_threats():
    """Get detected threats with DPI, signatures, and ML analysis"""
    try:
        from dpi_engine import analyze_flow_dpi
        from signature_engine import get_signature_engine
        from ips_engine import get_ips_engine
        
        n = int(request.args.get("n", 50))
        with get_db_conn() as conn, conn.cursor() as cur:
            cur.execute(sql.SQL("""
                SELECT * FROM {tbl} 
                WHERE ml_label = 'malicious' OR ml_score > 0.5
                ORDER BY id DESC LIMIT %s
            """).format(tbl=sql.Identifier(NETWORK_FLOWS_TABLE)), (n,))
            rows = cur.fetchall()
            cols = [c.name for c in cur.description]
            flows = [dict(zip(cols, r)) for r in rows]
        
        # Enhance with DPI and signature analysis
        sig_engine = get_signature_engine()
        threats = []
        
        for flow in flows:
            # DPI analysis
            dpi_result = analyze_flow_dpi(flow)
            
            # Signature matching
            sig_matches = sig_engine.match_signatures(flow)
            
            threat = {
                **flow,
                'dpi': dpi_result,
                'signature_matches': [
                    {
                        'id': sig.id,
                        'name': sig.name,
                        'severity': sig.severity,
                        'action': sig.action
                    }
                    for sig, match_info in sig_matches
                ],
                'threat_level': 'high' if sig_matches or (flow.get('ml_score', 0) > 0.8) else 'medium'
            }
            threats.append(threat)
        
        return jsonify(threats), 200
    except Exception as e:
        LOG.exception("Failed to get threats: %s", e)
        return jsonify({"error": str(e)}), 500

@app.route("/api/signatures", methods=["GET"])
def api_signatures():
    """Get all signatures"""
    try:
        from signature_engine import get_signature_engine
        sig_engine = get_signature_engine()
        signatures = sig_engine.list_signatures()
        return jsonify(signatures), 200
    except Exception as e:
        LOG.exception("Failed to get signatures: %s", e)
        return jsonify({"error": str(e)}), 500

@app.route("/api/blocked", methods=["GET"])
def api_blocked():
    """Get blocked IPs"""
    try:
        from ips_engine import get_ips_engine
        ips_engine = get_ips_engine()
        blocked = ips_engine.get_blocked_ips()
        return jsonify(blocked), 200
    except Exception as e:
        LOG.exception("Failed to get blocked IPs: %s", e)
        return jsonify({"error": str(e)}), 500

@app.route("/api/blocked-threats-count", methods=["GET"])
def get_blocked_threats_count():
    """Get count of blocked threats from URL checks"""
    try:
        with get_db_conn() as conn:
            cur = conn.cursor()
            # Count blocked URLs from url_checks table
            cur.execute("""
                SELECT COUNT(*) 
                FROM url_checks 
                WHERE is_blocked = true
            """)
            count = cur.fetchone()[0]
            cur.close()
            return jsonify({"count": count}), 200
    except Exception as e:
        LOG.exception("Failed to get blocked threats count: %s", e)
        return jsonify({"error": str(e), "count": 0}), 500

@app.route("/api/blocked-threats", methods=["GET"])
def api_blocked_threats():
    """Get blocked threats/URLs from database"""
    try:
        from dpi_engine import analyze_flow_dpi
        from signature_engine import get_signature_engine
        from ips_engine import get_ips_engine
        
        n = int(request.args.get("n", 50))
        with get_db_conn() as conn, conn.cursor() as cur:
            # Get flows that have URLs and are marked as malicious or have high scores
            cols = table_columns(conn, NETWORK_FLOWS_TABLE)
            select_cols = sql.SQL(", ").join([sql.Identifier(c) for c in cols])
            
            cur.execute(sql.SQL("""
                SELECT {cols}
                FROM {tbl}
                WHERE (ml_label = 'malicious' OR ml_score > 0.7)
                ORDER BY id DESC LIMIT %s
            """).format(
                cols=select_cols,
                tbl=sql.Identifier(NETWORK_FLOWS_TABLE)
            ), (n,))
            rows = cur.fetchall()
            flows = [dict(zip(cols, r)) for r in rows]
        
        # Enhance with DPI and check for blocked URLs
        sig_engine = get_signature_engine()
        ips_engine = get_ips_engine()
        blocked_threats = []
        
        for flow in flows:
            # Check if flow has URL or suspicious indicators
            url = flow.get('url') or flow.get('pkt_hash', '')
            has_url = 'http' in str(url).lower() or '://' in str(url)
            
            # DPI analysis
            dpi_result = analyze_flow_dpi(flow)
            
            # Signature matching
            sig_matches = sig_engine.match_signatures(flow)
            
            # Check if it was blocked
            flow_data = {
                "src_ip": flow.get("src_ip"),
                "dst_ip": flow.get("dst_ip"),
                "protocol": flow.get("protocol"),
                "url": url if has_url else None
            }
            
            ips_decision = ips_engine.evaluate_threat(
                flow_data,
                ml_score=flow.get("ml_score"),
                ml_label=flow.get("ml_label"),
                signature_matches=sig_matches,
                dpi_indicators=dpi_result.get("threat_indicators", [])
            )
            
            # Only include if it was blocked or has threats
            if ips_decision.get("blocked") or sig_matches or dpi_result.get("threat_indicators"):
                threat = {
                    **flow,
                    'url': url if has_url else None,
                    'dpi': dpi_result,
                    'signatures': [
                        {
                            'id': sig.id,
                            'name': sig.name,
                            'severity': sig.severity
                        }
                        for sig, _ in sig_matches
                    ],
                    'ips_decision': ips_decision,
                    'blocked': ips_decision.get("blocked", False),
                    'threat_level': 'high' if sig_matches or (flow.get('ml_score', 0) > 0.8) else 'medium'
                }
                blocked_threats.append(threat)
        
        return jsonify(blocked_threats), 200
    except Exception as e:
        LOG.exception("Failed to get blocked threats: %s", e)
        return jsonify({"error": str(e)}), 500

@app.route("/api/blocked/<ip>", methods=["POST"])
def block_ip(ip):
    """Block an IP address"""
    try:
        from ips_engine import get_ips_engine
        duration = int(request.json.get("duration_minutes", 60)) if request.json else 60
        ips_engine = get_ips_engine()
        ips_engine.block_ip(ip, duration)
        return jsonify({"status": "blocked", "ip": ip, "duration_minutes": duration}), 200
    except Exception as e:
        LOG.exception("Failed to block IP: %s", e)
        return jsonify({"error": str(e)}), 500

@app.route("/api/blocked/<ip>", methods=["DELETE"])
def unblock_ip(ip):
    """Unblock an IP address"""
    try:
        from ips_engine import get_ips_engine
        ips_engine = get_ips_engine()
        ips_engine.unblock_ip(ip)
        return jsonify({"status": "unblocked", "ip": ip}), 200
    except Exception as e:
        LOG.exception("Failed to unblock IP: %s", e)
        return jsonify({"error": str(e)}), 500

@app.route("/api/test-url", methods=["POST"])
def test_url():
    """Test URL validation directly with ML model"""
    try:
        from dpi_engine import DPIEngine
        from signature_engine import get_signature_engine
        from ips_engine import get_ips_engine
        import pandas as pd
        
        payload = request.get_json(force=True)
        url = payload.get("url")
        
        if not url:
            return jsonify({"error": "URL is required"}), 400
        
        # Validate URL with DPI
        engine = DPIEngine()
        url_validation = engine.validate_url(url)
        
        # Advanced detection using modern techniques
        advanced_analysis = {}
        try:
            from advanced_detection import get_advanced_detection_engine
            advanced_engine = get_advanced_detection_engine()
            advanced_analysis = advanced_engine.comprehensive_analysis(url)
            
            # Merge advanced detection results into URL validation
            if advanced_analysis.get('threat_level') in ['high', 'critical']:
                for det in advanced_analysis.get('detections', {}).values():
                    if isinstance(det, dict) and det.get('indicators'):
                        url_validation['threat_indicators'].extend([
                            f"Advanced: {ind}" for ind in det.get('indicators', [])
                        ])
            
            # Add brand impersonation indicators
            brand_imp = advanced_analysis.get('detections', {}).get('brand_impersonation', {})
            if brand_imp.get('is_impersonation'):
                url_validation['threat_indicators'].append(
                    f"Brand impersonation: {brand_imp.get('impersonated_brand')}"
                )
            
            # Use advanced detection risk score for blocking decision
            if advanced_analysis.get('overall_risk_score', 0) >= 50:
                url_validation['threat_indicators'].append(
                    f"High risk score from advanced detection: {advanced_analysis.get('overall_risk_score', 0)}/100"
                )
        except Exception as e:
            LOG.warning(f"Advanced detection failed: {e}")
            advanced_analysis = {}
        
        # ML Prediction using URL model
        ml_score = None
        ml_label = None
        ml_prediction = None
        
        if url_model is not None and url_preproc is not None:
            try:
                # Extract features
                url_features = extract_url_features(url)
                
                # Get feature columns from preprocessor
                feature_cols = url_preproc.get('feature_columns', [])
                
                # Get optimal threshold (default to 0.5 if not found)
                optimal_threshold = url_preproc.get('optimal_threshold', 0.5)
                
                # Create DataFrame with features
                feature_dict = {col: url_features.get(col, 0) for col in feature_cols}
                df = pd.DataFrame([feature_dict])
                
                # Predict
                ml_score = float(url_model.predict(df.values)[0])
                ml_label = "malicious" if ml_score >= optimal_threshold else "safe"
                
                # Calculate confidence based on distance from threshold
                ml_prediction = {
                    "score": ml_score,
                    "label": ml_label,
                    "threshold": optimal_threshold,
                    "confidence": abs(ml_score - optimal_threshold) / max(optimal_threshold, 1 - optimal_threshold)  # Normalized confidence
                }
                
                LOG.info(f"URL ML Prediction: {url[:50]} -> {ml_label} (score: {ml_score:.3f}, threshold: {optimal_threshold:.3f})")
            except Exception as e:
                LOG.warning(f"URL ML prediction failed: {e}")
                ml_prediction = {"error": str(e)}
        
        # Check signatures (includes URL-based detection like Suricata rules)
        sig_engine = get_signature_engine()
        flow_data = {
            "protocol": "HTTP",
            "dst_port": 80,
            "url": url
        }
        sig_matches = sig_engine.match_signatures(flow_data)
        
        # Check for critical/high severity signature matches (auto-block)
        critical_matches = [m for m in sig_matches if m[0].severity in ['critical', 'high'] and m[0].action == 'block']
        if critical_matches:
            LOG.warning(f"🚫 URL blocked by signature match: {url[:100]} - {critical_matches[0][0].name}")
        
        # Check if URL is from trusted domain first (whitelist check)
        is_trusted = is_trusted_domain(url)
        
        # IPS evaluation (use IPS mode for blocking)
        # Pass trusted domain info to IPS engine so it can adjust its decision
        ips_engine = get_ips_engine(mode="ips")  # Use IPS mode for actual blocking
        ips_decision = ips_engine.evaluate_threat(
            flow_data,
            ml_score=ml_score,
            ml_label=ml_label,
            signature_matches=sig_matches,
            dpi_indicators=url_validation.get("threat_indicators", []),
            is_trusted_domain=is_trusted
        )
        
        # Determine if blocked (combine ML, DPI, and signatures)
        # Use optimal threshold if available, otherwise use 0.5
        ml_threshold = 0.5
        if url_preproc is not None:
            ml_threshold = url_preproc.get('optimal_threshold', 0.5)
        
        # If trusted domain, require higher confidence to block
        # Trusted domains need score > 0.9 to be blocked (very high confidence)
        if is_trusted:
            ml_threshold_effective = max(ml_threshold, 0.9)  # Higher threshold for trusted domains
            LOG.info(f"Trusted domain detected: {url[:50]}, using higher threshold: {ml_threshold_effective:.3f}")
        else:
            ml_threshold_effective = ml_threshold
        
        # Block decision: trusted domains are only blocked if very high confidence + clear threat indicators
        # Priority: Critical signatures > Suricata > High signatures > ML/DPI
        
        # Check for critical signature matches first (highest priority)
        if critical_matches:
            is_blocked = True
            LOG.warning(f"🚫 BLOCKED by signature: {url[:100]}")
        elif is_trusted:
            # For trusted domains, we trust them unless there are CLEAR threat indicators
            # Ignore ML score for trusted domains - they are trusted by default
            has_clear_threats = (
                len(url_validation.get("threat_indicators", [])) > 0 or 
                len(sig_matches) > 0 or
                ips_decision.get("blocked", False)
            )
            
            # Only block trusted domains if there are clear threat indicators
            # We ignore ML score for trusted domains because the model may have false positives
            if has_clear_threats:
                is_blocked = True
                LOG.info(f"Trusted domain with threats detected: {url[:50]} - BLOCKING")
            else:
                is_blocked = False
                LOG.info(f"Trusted domain detected: {url[:50]} - marking as SAFE (ignoring ML score: {ml_score:.3f})")
        else:
            # For non-trusted domains, use normal logic
            is_blocked = (
                ips_decision.get("blocked", False) or 
                len(url_validation.get("threat_indicators", [])) > 0 or
                (ml_score is not None and ml_score >= ml_threshold_effective) or
                len(critical_matches) > 0
            )
        
        is_safe = not is_blocked
        
        # Save URL check result to database for active learning
        try:
            with get_db_conn() as conn:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO url_checks (
                        url, is_safe, is_blocked, ml_score, ml_label, ml_threshold, ml_confidence,
                        url_validation, threat_indicators, signatures, ips_decision, checked_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now())
                    RETURNING id
                """, (
                    url,
                    is_safe,
                    is_blocked,
                    ml_score,
                    ml_label,
                    ml_threshold if url_preproc is not None else 0.5,
                    ml_prediction.get("confidence") if ml_prediction and "confidence" in ml_prediction else None,
                    json.dumps(url_validation) if url_validation else None,
                    json.dumps(url_validation.get("threat_indicators", [])) if url_validation else None,
                    json.dumps([{"id": s.id, "name": s.name, "severity": s.severity} for s, _ in sig_matches]),
                    json.dumps(ips_decision) if ips_decision else None
                ))
                check_id = cur.fetchone()[0]
                conn.commit()
                cur.close()
                LOG.info(f"✅ URL check saved to database (id={check_id}): {url[:50]} -> {'BLOCKED' if is_blocked else 'SAFE'}")
                
                # Trigger incremental learning if we have enough new data
                # Check if we should retrain (every 50 new checks or if this is a blocked URL)
                if is_blocked:
                    # For blocked URLs, trigger learning more frequently
                    threading.Thread(target=incremental_learn_from_db, daemon=True).start()
                else:
                    # Check total count and trigger if needed
                    cur = conn.cursor()
                    cur.execute("SELECT COUNT(*) FROM url_checks")
                    total_checks = cur.fetchone()[0]
                    cur.close()
                    
                    # Retrain every 50 new checks
                    if total_checks % 50 == 0:
                        threading.Thread(target=incremental_learn_from_db, daemon=True).start()
        except Exception as db_error:
            LOG.warning(f"Failed to save URL check to database: {db_error}")
            # Continue even if database save fails
        
        return jsonify({
            "url": url,
            "url_validation": url_validation,
            "ml_prediction": ml_prediction,
            "signatures": [{"id": s.id, "name": s.name, "severity": s.severity} for s, _ in sig_matches],
            "ips_decision": ips_decision,
            "advanced_detection": {
                "overall_risk_score": advanced_analysis.get('overall_risk_score', 0),
                "threat_level": advanced_analysis.get('threat_level', 'low'),
                "recommendation": advanced_analysis.get('recommendation', 'allow'),
                "detections": {
                    "entropy": advanced_analysis.get('detections', {}).get('entropy', {}),
                    "homoglyphs": advanced_analysis.get('detections', {}).get('homoglyphs', {}),
                    "brand_impersonation": advanced_analysis.get('detections', {}).get('brand_impersonation', {}),
                    "url_shortening": advanced_analysis.get('detections', {}).get('url_shortening', {}),
                    "domain_reputation": advanced_analysis.get('detections', {}).get('domain_reputation', {}),
                    "suspicious_patterns": advanced_analysis.get('detections', {}).get('suspicious_patterns', {})
                }
            },
            "blocked": is_blocked,
            "is_safe": is_safe,
            "is_trusted_domain": is_trusted,
            "ml_threshold_used": ml_threshold_effective
        }), 200
        
    except Exception as e:
        LOG.exception("URL test failed: %s", e)
        return jsonify({"error": str(e)}), 500

@app.route("/api/intercept-url", methods=["POST"])
def intercept_url():
    """اعتراض URL عند محاولة فتحه - يتم استدعاؤه من Browser Extension"""
    try:
        payload = request.get_json(force=True)
        url = payload.get("url")
        src_ip = payload.get("src_ip", request.remote_addr)
        
        if not url:
            return jsonify({"error": "URL is required", "blocked": False}), 400
        
        # Always allow localhost and local IPs
        from urllib.parse import urlparse
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'http://{url}')
        domain = parsed.netloc.lower().split(':')[0]
        if domain in ['localhost', '127.0.0.1', '0.0.0.0', '::1'] or \
           domain.startswith('127.') or domain.startswith('192.168.') or \
           domain.startswith('10.') or domain.startswith('172.'):
            LOG.info(f"✅ Local URL allowed: {url[:100]}")
            return jsonify({
                "url": url,
                "blocked": False,
                "is_safe": True,
                "message": "✅ Local URL - Always allowed"
            }), 200
        
        LOG.info(f"🔍 Intercepting URL: {url[:100]}")
        
        # استخدام نفس منطق test_url للتحقق
        from dpi_engine import DPIEngine
        from signature_engine import get_signature_engine
        from ips_engine import get_ips_engine
        import pandas as pd
        
        # Validate URL with DPI
        engine = DPIEngine()
        url_validation = engine.validate_url(url)
        
        # Advanced detection
        advanced_analysis = {}
        try:
            from advanced_detection import get_advanced_detection_engine
            advanced_engine = get_advanced_detection_engine()
            advanced_analysis = advanced_engine.comprehensive_analysis(url)
            
            if advanced_analysis.get('threat_level') in ['high', 'critical']:
                for det in advanced_analysis.get('detections', {}).values():
                    if isinstance(det, dict) and det.get('indicators'):
                        url_validation['threat_indicators'].extend([
                            f"Advanced: {ind}" for ind in det.get('indicators', [])
                        ])
            
            # Use advanced detection risk score for blocking
            if advanced_analysis.get('overall_risk_score', 0) >= 50:
                url_validation['threat_indicators'].append(
                    f"High risk score: {advanced_analysis.get('overall_risk_score', 0)}/100"
                )
        except Exception as e:
            LOG.warning(f"Advanced detection failed: {e}")
            advanced_analysis = {}
        
        # ML Prediction
        ml_score = None
        ml_label = None
        ml_prediction = None
        
        if url_model is not None and url_preproc is not None:
            try:
                url_features = extract_url_features(url)
                feature_cols = url_preproc.get('feature_columns', [])
                optimal_threshold = url_preproc.get('optimal_threshold', 0.5)
                feature_dict = {col: url_features.get(col, 0) for col in feature_cols}
                df = pd.DataFrame([feature_dict])
                ml_score = float(url_model.predict(df.values)[0])
                ml_label = "malicious" if ml_score >= optimal_threshold else "safe"
                ml_prediction = {
                    "score": ml_score,
                    "label": ml_label,
                    "threshold": optimal_threshold
                }
            except Exception as e:
                LOG.warning(f"URL ML prediction failed: {e}")
        
        # Check signatures (includes URL-based detection like Suricata rules)
        sig_engine = get_signature_engine()
        flow_data = {
            "protocol": "HTTP",
            "dst_port": 80,
            "url": url,
            "src_ip": src_ip
        }
        sig_matches = sig_engine.match_signatures(flow_data)
        
        # Check for critical/high severity signature matches (auto-block)
        critical_matches = [m for m in sig_matches if m[0].severity in ['critical', 'high'] and m[0].action == 'block']
        if critical_matches:
            LOG.warning(f"🚫 URL blocked by signature match: {url[:100]} - {critical_matches[0][0].name}")
        
        # Check if trusted domain
        is_trusted = is_trusted_domain(url)
        
        # Check Suricata blocking
        suricata_blocked = False
        try:
            from suricata_integration import get_suricata_ips
            suricata_ips = get_suricata_ips()
            suricata_blocked = suricata_ips.is_url_blocked(url) or (src_ip and suricata_ips.is_ip_blocked(src_ip))
            if suricata_blocked:
                LOG.warning(f"🚫 URL blocked by Suricata: {url[:100]}")
        except Exception as e:
            LOG.debug(f"Suricata check failed: {e}")
        
        # IPS evaluation
        ips_engine = get_ips_engine(mode="ips")
        ips_decision = ips_engine.evaluate_threat(
            flow_data,
            ml_score=ml_score,
            ml_label=ml_label,
            signature_matches=sig_matches,
            dpi_indicators=url_validation.get("threat_indicators", []),
            is_trusted_domain=is_trusted
        )
        
        # Block decision
        ml_threshold = url_preproc.get('optimal_threshold', 0.5) if url_preproc else 0.5
        
        # Blocking priority: Critical signatures > Suricata > High signatures > ML/DPI
        if critical_matches:
            is_blocked = True
            LOG.warning(f"🚫 BLOCKED by signature: {url[:100]}")
        elif suricata_blocked:
            is_blocked = True
            LOG.warning(f"🚫 BLOCKED by Suricata: {url[:100]}")
        elif is_trusted:
            has_clear_threats = (
                len(url_validation.get("threat_indicators", [])) > 0 or 
                len(sig_matches) > 0 or
                ips_decision.get("blocked", False)
            )
            is_blocked = has_clear_threats
        else:
            is_blocked = (
                ips_decision.get("blocked", False) or 
                len(url_validation.get("threat_indicators", [])) > 0 or
                (ml_score is not None and ml_score >= ml_threshold) or
                len(critical_matches) > 0
            )
        
        is_safe = not is_blocked
        
        # Save to database
        check_id = None
        try:
            with get_db_conn() as conn:
                cur = conn.cursor()
                # Prepare data
                url_validation_json = json.dumps(url_validation) if url_validation else None
                threat_indicators_json = json.dumps(url_validation.get("threat_indicators", [])) if url_validation else None
                signatures_json = json.dumps([{"id": s.id, "name": s.name, "severity": s.severity} for s, _ in sig_matches]) if sig_matches else None
                ips_decision_json = json.dumps(ips_decision) if ips_decision else None
                
                cur.execute("""
                    INSERT INTO url_checks (
                        url, is_safe, is_blocked, ml_score, ml_label, ml_threshold,
                        url_validation, threat_indicators, signatures, ips_decision, checked_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now())
                    RETURNING id
                """, (
                    url, is_safe, is_blocked, ml_score, ml_label, ml_threshold,
                    url_validation_json,
                    threat_indicators_json,
                    signatures_json,
                    ips_decision_json
                ))
                check_id = cur.fetchone()[0]
                conn.commit()
                cur.close()
                
                if is_blocked:
                    LOG.warning(f"🚫 BLOCKED URL intercepted and saved: {url[:100]} (id={check_id}, ml_score={ml_score}, ml_label={ml_label})")
                else:
                    LOG.info(f"✅ Allowed URL saved: {url[:100]} (id={check_id})")
        except Exception as db_error:
            LOG.error(f"❌ Failed to save intercepted URL to database: {db_error}", exc_info=True)
            # Continue anyway - don't block the request if DB save fails
        
        return jsonify({
            "url": url,
            "blocked": is_blocked,
            "is_safe": is_safe,
            "ml_prediction": ml_prediction,
            "threat_indicators": url_validation.get("threat_indicators", []),
            "signatures": [{"id": s.id, "name": s.name, "severity": s.severity} for s, _ in sig_matches],
            "message": "🚫 تم حظر هذا الرابط - رابط مشبوه!" if is_blocked else "✅ الرابط آمن"
        }), 200
        
    except Exception as e:
        LOG.exception("URL interception failed: %s", e)
        return jsonify({"error": str(e), "blocked": False}), 500

@app.route("/api/blocked-urls", methods=["GET"])
def get_blocked_urls():
    """الحصول على قائمة الروابط المحظورة"""
    try:
        n = int(request.args.get("n", 50))
        with get_db_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT 
                    id, url, is_blocked, ml_score, ml_label, 
                    threat_indicators, signatures, ips_decision, checked_at
                FROM url_checks 
                WHERE is_blocked = true
                ORDER BY checked_at DESC 
                LIMIT %s
            """, (n,))
            rows = cur.fetchall()
            cols = [desc[0] for desc in cur.description]
            blocked_urls = []
            for row in rows:
                url_data = dict(zip(cols, row))
                # Parse JSON fields
                if url_data.get('threat_indicators'):
                    try:
                        if isinstance(url_data['threat_indicators'], str):
                            url_data['threat_indicators'] = json.loads(url_data['threat_indicators'])
                    except:
                        pass
                if url_data.get('signatures'):
                    try:
                        if isinstance(url_data['signatures'], str):
                            url_data['signatures'] = json.loads(url_data['signatures'])
                    except:
                        pass
                if url_data.get('ips_decision'):
                    try:
                        if isinstance(url_data['ips_decision'], str):
                            url_data['ips_decision'] = json.loads(url_data['ips_decision'])
                    except:
                        pass
                blocked_urls.append(url_data)
        
        LOG.info(f"📋 Returning {len(blocked_urls)} blocked URLs (requested: {n})")
        
        # Log some details for debugging
        if blocked_urls:
            LOG.info(f"   Latest blocked URL: {blocked_urls[0].get('url', 'N/A')[:50]} (id={blocked_urls[0].get('id', 'N/A')})")
        
        return jsonify(blocked_urls), 200
    except Exception as e:
        LOG.exception("❌ Failed to get blocked URLs: %s", e)
        return jsonify({"error": str(e)}), 500

@app.route("/api/blocked-urls-count", methods=["GET"])
def get_blocked_urls_count():
    """الحصول على عدد الروابط المحظورة"""
    try:
        with get_db_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM url_checks WHERE is_blocked = true")
            count = cur.fetchone()[0]
            LOG.info(f"📊 Total blocked URLs in database: {count}")
            return jsonify({"count": count}), 200
    except Exception as e:
        LOG.exception("❌ Failed to get blocked URLs count: %s", e)
        return jsonify({"error": str(e), "count": 0}), 500

@app.route("/api/blocked-urls/clear", methods=["DELETE"])
def clear_blocked_urls():
    """حذف جميع الروابط المحظورة من قاعدة البيانات"""
    try:
        with get_db_conn() as conn, conn.cursor() as cur:
            # حذف جميع السجلات المحظورة
            cur.execute("DELETE FROM url_checks WHERE is_blocked = true")
            deleted_count = cur.rowcount
            conn.commit()
            LOG.warning(f"🗑️ Deleted {deleted_count} blocked URLs from database")
            return jsonify({
                "success": True,
                "deleted_count": deleted_count,
                "message": f"تم حذف {deleted_count} رابط محظور"
            }), 200
    except Exception as e:
        LOG.exception("❌ Failed to clear blocked URLs: %s", e)
        return jsonify({"error": str(e), "success": False}), 500

@app.route("/api/ingest-enhanced", methods=["POST"])
def ingest_enhanced():
    """Enhanced ingest with DPI, signature, and IPS analysis"""
    try:
        from dpi_engine import analyze_flow_dpi
        from signature_engine import get_signature_engine
        from ips_engine import get_ips_engine
        
        payload = request.get_json(force=True)
        flow_data = {
            "src_ip": payload.get("src_ip"),
            "dst_ip": payload.get("dst_ip") or payload.get("dest_ip"),
            "src_port": payload.get("src_port"),
            "dst_port": payload.get("dst_port") or payload.get("dest_port"),
            "protocol": payload.get("protocol") or payload.get("proto"),
            "pkt_hash": payload.get("pkt_hash"),
            "url": payload.get("url")  # Add URL if provided
        }
        
        # DPI analysis
        dpi_result = analyze_flow_dpi(flow_data)
        
        # Signature matching
        sig_engine = get_signature_engine()
        sig_matches = sig_engine.match_signatures(flow_data)
        
        # ML prediction (if model available)
        ml_score = None
        ml_label = None
        if model is not None:
            try:
                import pandas as pd
                df = pd.DataFrame([flow_data])
                if preproc_obj is not None:
                    X = preproc_obj.transform(df)
                elif preproc_num_cols:
                    cols = preproc_num_cols
                    df_sel = pd.DataFrame([{c: flow_data.get(c, 0) for c in cols}])
                    X = df_sel.values
                else:
                    X = df.select_dtypes(include=["number"]).fillna(0).values
                
                import lightgbm as lgb
                if isinstance(model, lgb.Booster):
                    preds = model.predict(X)
                    ml_score = float(preds[0])
                    ml_label = "malicious" if ml_score >= 0.5 else "benign"
                else:
                    ml_score = float(model.predict_proba(X)[0, 1]) if hasattr(model, "predict_proba") else float(model.predict(X)[0])
                    ml_label = "malicious" if ml_score >= 0.5 else "benign"
            except Exception as e:
                LOG.warning("ML prediction failed in enhanced ingest: %s", e)
        
        # IPS evaluation (use IPS mode for blocking)
        ips_engine = get_ips_engine(mode="ips")  # Use IPS mode for actual blocking
        ips_decision = ips_engine.evaluate_threat(
            flow_data,
            ml_score=ml_score,
            ml_label=ml_label,
            signature_matches=sig_matches,
            dpi_indicators=dpi_result.get("threat_indicators", [])
        )
        
        # Store in database (include URL and ML results)
        with get_db_conn() as conn:
            flow_data_to_store = {**flow_data}
            if ml_score is not None:
                flow_data_to_store["ml_score"] = ml_score
            if ml_label:
                flow_data_to_store["ml_label"] = ml_label
            flow_id = insert_flow(conn, **flow_data_to_store)
            ensure_event_for_flow(conn, flow_id)
        
        # Determine if threat was blocked
        is_blocked = ips_decision.get("blocked", False)
        threat_detected = (
            is_blocked or 
            sig_matches or 
            dpi_result.get("threat_indicators") or
            (ml_label == "malicious" and ml_score and ml_score >= 0.5)
        )
        
        return jsonify({
            "status": "blocked" if is_blocked else ("threat_detected" if threat_detected else "analyzed"),
            "flow_id": flow_id,
            "blocked": is_blocked,
            "threat_detected": threat_detected,
            "dpi": dpi_result,
            "signatures": [{"id": s.id, "name": s.name, "severity": s.severity, "action": s.action} for s, _ in sig_matches],
            "ips_decision": ips_decision,
            "ml": {"score": ml_score, "label": ml_label},
            "message": "🚫 تم حظر التهديد" if is_blocked else ("⚠️ تم اكتشاف تهديد" if threat_detected else "✅ آمن")
        }), 201
        
    except Exception as e:
        LOG.exception("Enhanced ingest failed: %s", e)
        return jsonify({"error": str(e)}), 500

# ---------- Sniffer Auto-Start ----------
def start_sniffer():
    """تشغيل Sniffer تلقائياً لإرسال بيانات"""
    try:
        # التحقق من متغير البيئة لتخطي تشغيل Sniffer
        if os.getenv("SKIP_SNIFFER", "false").lower() == "true":
            LOG.info("Skipping Sniffer auto-start (SKIP_SNIFFER=true)")
            return
        
        # الحصول على مسار المشروع
        backend_dir = Path(__file__).parent.absolute()
        
        # استيراد وتشغيل sniffer في thread منفصل
        LOG.info("Starting Sniffer to generate network traffic...")
        
        def run_sniffer():
            try:
                import sniffer
                # تشغيل sniffer في loop
                sniffer.resend_unsent()
                if sniffer.MODE == "SIMULATE":
                    sniffer.simulate_loop()
            except Exception as e:
                LOG.error(f"Sniffer error: {e}")
        
        sniffer_thread = threading.Thread(target=run_sniffer, daemon=True)
        sniffer_thread.start()
        LOG.info("✅ Sniffer started! Generating network flows...")
        
    except Exception as e:
        LOG.error(f"Failed to start Sniffer: {e}")
        LOG.info("You can start Sniffer manually: python sniffer.py")

# ---------- Frontend Auto-Start ----------
def start_frontend():
    """تشغيل Frontend تلقائياً"""
    try:
        # التحقق من متغير البيئة لتخطي تشغيل Frontend
        if os.getenv("SKIP_FRONTEND", "false").lower() == "true":
            LOG.info("Skipping Frontend auto-start (SKIP_FRONTEND=true)")
            return
        
        # الحصول على مسار المشروع (backend -> root)
        backend_dir = Path(__file__).parent.absolute()
        project_root = backend_dir.parent
        frontend_dir = project_root / "frontend-react"
        
        if not frontend_dir.exists():
            LOG.warning(f"Frontend directory not found: {frontend_dir}")
            LOG.info("You can start Frontend manually: cd frontend-react && npm start")
            return
        
        # التحقق من وجود node_modules
        node_modules = frontend_dir / "node_modules"
        if not node_modules.exists():
            LOG.info("Installing frontend dependencies...")
            install_result = subprocess.run(
                ["npm", "install"],
                cwd=str(frontend_dir),
                shell=True,
                check=False,
                capture_output=True
            )
            if install_result.returncode != 0:
                LOG.warning("Failed to install frontend dependencies. Please run: cd frontend-react && npm install")
                return
        
        # تشغيل Frontend
        LOG.info("Starting Frontend (React) on port 3000...")
        if sys.platform == "win32":
            # Windows - فتح نافذة جديدة
            subprocess.Popen(
                ["npm", "start"],
                cwd=str(frontend_dir),
                shell=True,
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
        else:
            # Linux/Mac
            subprocess.Popen(
                ["npm", "start"],
                cwd=str(frontend_dir),
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        
        LOG.info("✅ Frontend started! Access it at: http://localhost:3000")
        LOG.info("   (Note: Frontend may take 10-30 seconds to fully load)")
        
    except Exception as e:
        LOG.error(f"Failed to start Frontend: {e}")
        LOG.info("You can start Frontend manually: cd frontend-react && npm start")

# ---------- Startup ----------
if __name__ == "__main__":
    LOG.info("="*60)
    LOG.info("🚀 Starting NGFW Backend...")
    LOG.info("="*60)
    
    # Load model and preprocessor
    LOG.info("Loading model and preprocessor...")
    load_model_and_preproc()
    
    # Load URL model and preprocessor
    LOG.info("Loading URL model and preprocessor...")
    load_url_model_and_preproc()
    
    # Ensure DB tables
    LOG.info("Ensuring DB tables...")
    ensure_tables()
    ensure_url_checks_table()
    
    # Start Suricata integration
    try:
        from suricata_integration import get_suricata_ips
        suricata_ips = get_suricata_ips()
        suricata_ips.start()
        LOG.info("✅ Suricata IPS integration started")
    except Exception as e:
        LOG.warning(f"⚠️ Suricata integration not available: {e}")
        LOG.info("   Suricata will be disabled. Install Suricata to enable IDS/IPS features.")
    
    # Start Sniffer in a separate thread
    auto_start_sniffer = os.getenv("AUTO_START_SNIFFER", "true").lower() == "true"
    if auto_start_sniffer:
        LOG.info("Preparing to start Sniffer...")
        start_sniffer()
        time.sleep(1)
    else:
        LOG.info("Sniffer auto-start disabled (AUTO_START_SNIFFER=false)")
        LOG.info("Start Sniffer manually: python sniffer.py")
    
    # Start Frontend in a separate thread (with delay)
    auto_start_frontend = os.getenv("AUTO_START_FRONTEND", "true").lower() == "true"
    if auto_start_frontend:
        LOG.info("Preparing to start Frontend...")
        frontend_thread = threading.Thread(target=start_frontend, daemon=True)
        frontend_thread.start()
        # Give Frontend time to start
        time.sleep(2)
    else:
        LOG.info("Frontend auto-start disabled (AUTO_START_FRONTEND=false)")
        LOG.info("Start Frontend manually: cd frontend-react && npm start")
    
    LOG.info("="*60)
    LOG.info("✅ Backend starting on: http://localhost:5000")
    LOG.info("✅ Sniffer generating traffic...")
    LOG.info("✅ Frontend starting on: http://localhost:3000")
    LOG.info("="*60)
    LOG.info("")
    
    # Start Flask app
    app.run(host="0.0.0.0", port=5000, debug=True)
