"""
URL Classification Model Training Script
تدريب موديل ML لتصنيف الروابط (آمنة/خبيثة) باستخدام بيانات PhishTank
"""

import os
import sys
import re
import pandas as pd
import numpy as np
from urllib.parse import urlparse
import joblib
from pathlib import Path
import logging

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score, precision_recall_curve
import lightgbm as lgb

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
LOG = logging.getLogger("url_trainer")

# Paths
PROJECT_ROOT = Path(__file__).parent.parent
PHISHTANK_CSV = PROJECT_ROOT / "PhishTank.csv"
PHISHING_SITE_URLS_CSV = PROJECT_ROOT / "phishing_site_urls.csv"
MODEL_DIR = Path(__file__).parent
URL_MODEL_PATH = MODEL_DIR / "url_classifier_model.txt"
URL_PREPROC_PATH = MODEL_DIR / "url_preprocessor.joblib"


def extract_url_features(url: str) -> dict:
    """
    استخراج features من URL لاستخدامها في ML
    """
    features = {}
    
    if not url or not isinstance(url, str):
        url = ""
    
    url = url.strip().lower()
    url_lower = url  # Keep reference for later use
    
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
        trusted_domains = {
            'google.com', 'youtube.com', 'gmail.com', 'microsoft.com', 'apple.com',
            'amazon.com', 'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
            'linkedin.com', 'github.com', 'netflix.com', 'spotify.com', 'reddit.com',
            'wikipedia.org', 'dropbox.com', 'wordpress.com', 'medium.com',
            'bbc.com', 'cnn.com', 'yahoo.com', 'bing.com'
        }
        domain_clean = domain.replace('www.', '').lower()
        features['is_trusted_domain'] = any(domain_clean == td or domain_clean.endswith('.' + td) for td in trusted_domains)
        
        # Path features
        features['path_depth'] = path.count('/') - 1 if path else 0
        features['has_file_extension'] = bool(re.search(r'\.[a-z]{2,4}(/|$|\?|#)', path.lower()))
        
        # Suspicious patterns - expanded list
        suspicious_keywords = [
            'login', 'signin', 'sign-in', 'account', 'verify', 'confirm', 'update',
            'secure', 'banking', 'paypal', 'amazon', 'ebay', 'microsoft', 'apple',
            'admin', 'password', 'reset', 'unlock', 'suspended', 'locked',
            'webscr', 'cgi-bin', 'phishing', 'suspicious', 'alert', 'warning',
            'urgent', 'action-required', 'click-here', 'limited-time', 'expired',
            'suspended', 'locked', 'verify-account', 'update-info', 'confirm-identity'
        ]
        features['suspicious_keywords_count'] = sum(1 for kw in suspicious_keywords if kw in url_lower)
        
        # Brand impersonation patterns
        brand_keywords = ['paypal', 'amazon', 'ebay', 'microsoft', 'apple', 'google',
                         'facebook', 'twitter', 'instagram', 'linkedin', 'whatsapp',
                         'bank', 'chase', 'wells-fargo', 'bank-of-america', 'santander']
        features['brand_keywords_count'] = sum(1 for kw in brand_keywords if kw in url_lower)
        
        # Typosquatting indicators
        features['has_typosquatting'] = bool(re.search(r'[a-z]{2,}\.[a-z]{2,}\.[a-z]{2,}', url_lower))
        
        # Encoding features
        features['has_encoding'] = '%' in url
        features['encoding_ratio'] = url.count('%') / len(url) if len(url) > 0 else 0
        
        # Special characters
        features['has_at_symbol'] = '@' in url
        features['has_port'] = ':' in domain and not domain.split(':')[0].replace('.', '').isdigit()
        
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
    
    # Entropy-based features (higher entropy might indicate randomness/obfuscation)
    if len(url) > 0:
        char_counts = {}
        for char in url:
            char_counts[char] = char_counts.get(char, 0) + 1
        entropy = -sum((count/len(url)) * np.log2(count/len(url)) for count in char_counts.values() if count > 0)
        features['url_entropy'] = entropy
    else:
        features['url_entropy'] = 0
    
    # Shortened URL indicators
    features['is_shortened'] = any(short in url_lower for short in ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly'])
    
    return features


def load_phish_tank_data(csv_path: Path) -> pd.DataFrame:
    """تحميل بيانات PhishTank"""
    LOG.info(f"Loading PhishTank data from {csv_path}")
    
    if not csv_path.exists():
        LOG.warning(f"PhishTank CSV not found: {csv_path}, skipping...")
        return pd.DataFrame(columns=['url', 'label'])
    
    try:
        df = pd.read_csv(csv_path)
        LOG.info(f"Loaded {len(df)} records from PhishTank")
        
        # Filter verified phishing URLs
        if 'verified' in df.columns:
            df = df[df['verified'] == 'yes']
            LOG.info(f"Filtered to {len(df)} verified phishing URLs")
        
        # Extract URLs and label as malicious (1)
        if 'url' in df.columns:
            df_phish = pd.DataFrame({
                'url': df['url'].dropna(),
                'label': 1  # malicious
            })
            # Remove duplicates
            df_phish = df_phish.drop_duplicates(subset=['url'])
            LOG.info(f"Final PhishTank phishing URLs: {len(df_phish)}")
            return df_phish
        else:
            LOG.warning("'url' column not found in PhishTank CSV")
            return pd.DataFrame(columns=['url', 'label'])
    except Exception as e:
        LOG.error(f"Error loading PhishTank data: {e}")
        return pd.DataFrame(columns=['url', 'label'])


def load_phishing_site_urls_data(csv_path: Path) -> pd.DataFrame:
    """تحميل بيانات phishing_site_urls.csv"""
    LOG.info(f"Loading phishing_site_urls data from {csv_path}")
    
    if not csv_path.exists():
        LOG.warning(f"phishing_site_urls CSV not found: {csv_path}, skipping...")
        return pd.DataFrame(columns=['url', 'label'])
    
    try:
        df = pd.read_csv(csv_path)
        LOG.info(f"Loaded {len(df)} records from phishing_site_urls")
        
        # Check column names (might be 'URL' or 'url')
        url_col = 'URL' if 'URL' in df.columns else 'url'
        label_col = 'Label' if 'Label' in df.columns else 'label'
        
        if url_col not in df.columns:
            LOG.warning(f"URL column not found in phishing_site_urls CSV")
            return pd.DataFrame(columns=['url', 'label'])
        
        # Map labels: 'bad' -> 1 (malicious), 'good' -> 0 (safe)
        label_mapping = {'bad': 1, 'good': 0, 'malicious': 1, 'safe': 0, 1: 1, 0: 0}
        
        df_processed = pd.DataFrame({
            'url': df[url_col].dropna(),
            'label': df[label_col].map(label_mapping) if label_col in df.columns else None
        })
        
        # If label column doesn't exist or mapping failed, try to infer
        if df_processed['label'].isna().all() or label_col not in df.columns:
            LOG.warning("Label column not found or mapping failed, skipping this dataset")
            return pd.DataFrame(columns=['url', 'label'])
        
        # Remove rows with invalid labels
        df_processed = df_processed[df_processed['label'].notna()]
        
        # Remove duplicates
        df_processed = df_processed.drop_duplicates(subset=['url'])
        
        # Log distribution
        label_dist = df_processed['label'].value_counts().to_dict()
        LOG.info(f"phishing_site_urls distribution: {label_dist}")
        LOG.info(f"Final phishing_site_urls records: {len(df_processed)}")
        
        return df_processed
    except Exception as e:
        LOG.error(f"Error loading phishing_site_urls data: {e}")
        return pd.DataFrame(columns=['url', 'label'])


def generate_safe_urls(n_samples: int = None) -> pd.DataFrame:
    """إنشاء URLs آمنة للتدريب - نسخة محسّنة مع المزيد من التنويع"""
    LOG.info("Generating safe URLs...")
    
    # قائمة موسعة من النطاقات الآمنة
    safe_domains = [
        # Tech companies
        'google.com', 'youtube.com', 'github.com', 'stackoverflow.com',
        'microsoft.com', 'apple.com', 'adobe.com', 'oracle.com',
        'ibm.com', 'intel.com', 'nvidia.com', 'amd.com',
        # Social media
        'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com',
        'reddit.com', 'pinterest.com', 'tumblr.com',
        # E-commerce
        'amazon.com', 'ebay.com', 'etsy.com', 'shopify.com',
        # Media
        'netflix.com', 'spotify.com', 'youtube.com', 'twitch.tv',
        # Education
        'wikipedia.org', 'edu', 'coursera.org', 'udemy.com',
        # News
        'bbc.com', 'cnn.com', 'reuters.com', 'theguardian.com',
        # Cloud services
        'dropbox.com', 'onedrive.com', 'drive.google.com',
        # Other popular
        'wordpress.com', 'blogger.com', 'medium.com', 'quora.com'
    ]
    
    # مسارات آمنة متنوعة
    safe_paths = [
        '/', '/home', '/index', '/about', '/contact', '/products', '/services',
        '/blog', '/news', '/help', '/support', '/docs', '/api', '/documentation',
        '/search', '/login', '/register', '/signup', '/signin', '/profile',
        '/settings', '/account', '/dashboard', '/explore', '/discover',
        '/features', '/pricing', '/download', '/install', '/guide',
        '/tutorial', '/learn', '/resources', '/faq', '/terms', '/privacy'
    ]
    
    safe_urls = []
    n_samples = n_samples or 10000
    
    # Generate from safe domains with paths
    for domain in safe_domains:
        for path in safe_paths:
            safe_urls.append(f"https://{domain}{path}")
            safe_urls.append(f"https://www.{domain}{path}")
            if len(safe_urls) >= n_samples:
                break
        if len(safe_urls) >= n_samples:
            break
    
    # Add variations with subdomains
    subdomains = ['www', 'blog', 'news', 'shop', 'store', 'mail', 'mail', 'docs', 'api', 'help']
    for domain in safe_domains[:20]:
        for subdomain in subdomains[:3]:
            safe_urls.append(f"https://{subdomain}.{domain}/")
            if len(safe_urls) >= n_samples:
                break
        if len(safe_urls) >= n_samples:
            break
    
    # Add variations with query parameters (safe)
    for domain in safe_domains[:15]:
        for param in ['q', 'search', 'page', 'id', 'ref']:
            safe_urls.append(f"https://{domain}/?{param}=test")
            if len(safe_urls) >= n_samples:
                break
        if len(safe_urls) >= n_samples:
            break
    
    # Add numbered pages
    for domain in safe_domains[:10]:
        for i in range(10):
            safe_urls.append(f"https://{domain}/page{i}")
            safe_urls.append(f"https://{domain}/article{i}")
            if len(safe_urls) >= n_samples:
                break
        if len(safe_urls) >= n_samples:
            break
    
    df_safe = pd.DataFrame({
        'url': safe_urls[:n_samples],
        'label': 0  # safe
    })
    
    LOG.info(f"Generated {len(df_safe)} safe URLs")
    return df_safe


def prepare_dataset(phish_df: pd.DataFrame, safe_df: pd.DataFrame, phishing_site_df: pd.DataFrame = None, balance_ratio: float = 0.5) -> pd.DataFrame:
    """تحضير dataset للتدريب مع موازنة البيانات"""
    LOG.info("Preparing dataset with class balancing...")
    
    # Combine all malicious URLs (PhishTank + phishing_site_urls with label=1)
    malicious_dfs = [phish_df]
    if phishing_site_df is not None and len(phishing_site_df) > 0:
        phishing_malicious = phishing_site_df[phishing_site_df['label'] == 1]
        if len(phishing_malicious) > 0:
            malicious_dfs.append(phishing_malicious)
            LOG.info(f"Added {len(phishing_malicious)} malicious URLs from phishing_site_urls")
    
    # Combine all safe URLs (generated + phishing_site_urls with label=0)
    safe_dfs = [safe_df]
    if phishing_site_df is not None and len(phishing_site_df) > 0:
        phishing_safe = phishing_site_df[phishing_site_df['label'] == 0]
        if len(phishing_safe) > 0:
            safe_dfs.append(phishing_safe)
            LOG.info(f"Added {len(phishing_safe)} safe URLs from phishing_site_urls")
    
    # Combine all malicious and safe
    phish_df_combined = pd.concat(malicious_dfs, ignore_index=True).drop_duplicates(subset=['url'])
    safe_df_combined = pd.concat(safe_dfs, ignore_index=True).drop_duplicates(subset=['url'])
    
    # Balance the dataset
    n_malicious = len(phish_df_combined)
    n_safe = len(safe_df_combined)
    
    LOG.info(f"Original distribution - Malicious: {n_malicious}, Safe: {n_safe}")
    
    # If safe URLs are too few, we'll undersample malicious URLs
    if n_safe < n_malicious * balance_ratio:
        # Undersample malicious to match safe (with ratio)
        target_malicious = int(n_safe / balance_ratio)
        if target_malicious < n_malicious:
            phish_df_combined = phish_df_combined.sample(n=min(target_malicious, n_malicious), random_state=42)
            LOG.info(f"Undersampled malicious URLs to: {len(phish_df_combined)}")
    
    # Combine datasets
    df = pd.concat([phish_df_combined, safe_df_combined], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)  # Shuffle
    
    LOG.info(f"Final dataset - Total: {len(df)} (Malicious: {len(phish_df_combined)}, Safe: {len(safe_df_combined)})")
    LOG.info(f"Class distribution: {df['label'].value_counts().to_dict()}")
    
    # Extract features - optimized with vectorization where possible
    LOG.info("Extracting features from URLs...")
    feature_list = []
    total = len(df)
    for idx, row in df.iterrows():
        if idx % 5000 == 0 or idx == total - 1:
            LOG.info(f"Processing {idx+1}/{total} URLs... ({100*(idx+1)/total:.1f}%)")
        features = extract_url_features(row['url'])
        feature_list.append(features)
    
    features_df = pd.DataFrame(feature_list)
    
    # Combine with labels
    dataset = pd.concat([features_df, df[['label']].reset_index(drop=True)], axis=1)
    
    LOG.info(f"Dataset prepared: {len(dataset)} samples, {len(features_df.columns)} features")
    LOG.info(f"Feature columns: {list(features_df.columns)}")
    
    return dataset


def find_optimal_threshold(y_true, y_proba):
    """إيجاد optimal threshold باستخدام F1 score"""
    from sklearn.metrics import f1_score
    
    thresholds = np.arange(0.1, 0.9, 0.01)
    best_threshold = 0.5
    best_f1 = 0
    
    for threshold in thresholds:
        y_pred = (y_proba >= threshold).astype(int)
        f1 = f1_score(y_true, y_pred, average='weighted')
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = threshold
    
    return best_threshold, best_f1


def train_model(dataset: pd.DataFrame):
    """تدريب الموديل مع class balancing و optimal threshold"""
    LOG.info("Training URL classifier model with class balancing...")
    
    # Prepare features and labels
    feature_cols = [col for col in dataset.columns if col != 'label']
    X = dataset[feature_cols].fillna(0)
    
    # Convert boolean columns to int (LightGBM requires int/float/bool, not object)
    bool_cols = ['has_ip', 'domain_has_digits', 'is_common_tld', 'has_file_extension', 
                  'has_typosquatting', 'has_encoding', 'has_at_symbol', 'has_port',
                  'has_https', 'has_http', 'has_scheme', 'is_shortened']
    for col in bool_cols:
        if col in X.columns:
            X[col] = X[col].astype(int)
    
    # Ensure all columns are numeric
    for col in X.columns:
        if X[col].dtype == 'object':
            X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)
    
    y = dataset['label'].astype(int)
    
    LOG.info(f"Features shape: {X.shape}, Labels shape: {y.shape}")
    class_dist = y.value_counts().to_dict()
    LOG.info(f"Class distribution: {class_dist}")
    
    # Calculate class weights for balancing
    n_safe = class_dist.get(0, 0)
    n_malicious = class_dist.get(1, 0)
    
    if n_safe > 0 and n_malicious > 0:
        # Calculate balanced weights
        total = n_safe + n_malicious
        weight_safe = total / (2 * n_safe)
        weight_malicious = total / (2 * n_malicious)
        scale_pos_weight = n_safe / n_malicious if n_malicious > 0 else 1.0
        LOG.info(f"Class weights - Safe: {weight_safe:.3f}, Malicious: {weight_malicious:.3f}")
        LOG.info(f"Scale pos weight: {scale_pos_weight:.3f}")
    else:
        scale_pos_weight = 1.0
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    LOG.info(f"Train set: {len(X_train)}, Test set: {len(X_test)}")
    
    # Train LightGBM model with class weights
    LOG.info("Training LightGBM model with class balancing...")
    train_data = lgb.Dataset(X_train, label=y_train)
    test_data = lgb.Dataset(X_test, label=y_test, reference=train_data)
    
    # Improved hyperparameters for better performance
    params = {
        'objective': 'binary',
        'metric': 'binary_logloss',
        'boosting_type': 'gbdt',
        'num_leaves': 64,  # Increased for more complex patterns
        'learning_rate': 0.03,  # Lower learning rate for better convergence
        'feature_fraction': 0.85,  # Use 85% of features per tree
        'bagging_fraction': 0.85,  # Use 85% of data per tree
        'bagging_freq': 5,
        'min_child_samples': 20,  # Minimum samples in leaf
        'min_split_gain': 0.0,
        'reg_alpha': 0.1,  # L1 regularization
        'reg_lambda': 0.1,  # L2 regularization
        'scale_pos_weight': scale_pos_weight,  # Balance classes
        'max_depth': 10,  # Limit depth to prevent overfitting
        'verbose': 0
    }
    
    model = lgb.train(
        params,
        train_data,
        num_boost_round=300,  # Increased rounds
        valid_sets=[train_data, test_data],
        valid_names=['train', 'eval'],
        callbacks=[lgb.early_stopping(30, verbose=False), lgb.log_evaluation(50)]  # More patience
    )
    
    # Get predictions for threshold optimization
    y_proba = model.predict(X_test)
    
    # Calculate ROC-AUC
    roc_auc = roc_auc_score(y_test, y_proba)
    LOG.info(f"\nROC-AUC Score: {roc_auc:.4f}")
    
    # Find optimal threshold
    optimal_threshold, best_f1 = find_optimal_threshold(y_test, y_proba)
    LOG.info(f"Optimal threshold: {optimal_threshold:.3f} (F1: {best_f1:.4f})")
    
    # Evaluate with default threshold (0.5)
    y_pred_default = (y_proba >= 0.5).astype(int)
    accuracy_default = accuracy_score(y_test, y_pred_default)
    
    # Evaluate with optimal threshold
    y_pred_optimal = (y_proba >= optimal_threshold).astype(int)
    accuracy_optimal = accuracy_score(y_test, y_pred_optimal)
    
    LOG.info(f"\n{'='*60}")
    LOG.info(f"Model Performance Metrics:")
    LOG.info(f"  ROC-AUC: {roc_auc:.4f}")
    LOG.info(f"  Accuracy (threshold=0.5): {accuracy_default:.4f}")
    LOG.info(f"  Accuracy (threshold={optimal_threshold:.3f}): {accuracy_optimal:.4f}")
    LOG.info(f"{'='*60}\n")
    
    LOG.info("Classification Report (optimal threshold):")
    LOG.info(f"\n{classification_report(y_test, y_pred_optimal)}")
    LOG.info(f"\nConfusion Matrix (optimal threshold):\n{confusion_matrix(y_test, y_pred_optimal)}")
    
    # Feature importance
    try:
        # Try new API first
        importances = model.feature_importance(importance_type='gain')
    except:
        # Fallback to old API
        importances = model.feature_importances_
    
    feature_importance = pd.DataFrame({
        'feature': feature_cols,
        'importance': importances
    }).sort_values('importance', ascending=False)
    
    LOG.info(f"\nTop 15 Most Important Features:")
    LOG.info(f"\n{feature_importance.head(15).to_string(index=False)}")
    
    # Save model
    model.save_model(str(URL_MODEL_PATH))
    LOG.info(f"✅ Model saved to: {URL_MODEL_PATH}")
    
    # Save preprocessor with optimal threshold
    preprocessor = {
        'feature_columns': feature_cols,
        'model_type': 'lightgbm',
        'optimal_threshold': float(optimal_threshold),
        'default_threshold': 0.5
    }
    joblib.dump(preprocessor, URL_PREPROC_PATH)
    LOG.info(f"✅ Preprocessor saved to: {URL_PREPROC_PATH}")
    LOG.info(f"✅ Optimal threshold saved: {optimal_threshold:.3f}")
    
    return model, feature_cols, optimal_threshold


def main():
    """Main training function"""
    LOG.info("="*60)
    LOG.info("URL Classifier Training - Improved Version")
    LOG.info("Using PhishTank + phishing_site_urls datasets")
    LOG.info("="*60)
    
    try:
        # Load PhishTank data
        phish_df = load_phish_tank_data(PHISHTANK_CSV)
        
        # Load phishing_site_urls data
        phishing_site_df = load_phishing_site_urls_data(PHISHING_SITE_URLS_CSV)
        
        # Calculate total malicious URLs from both sources
        total_malicious = len(phish_df)
        if len(phishing_site_df) > 0:
            total_malicious += len(phishing_site_df[phishing_site_df['label'] == 1])
        
        # Calculate total safe URLs
        total_safe = 0
        if len(phishing_site_df) > 0:
            total_safe = len(phishing_site_df[phishing_site_df['label'] == 0])
        
        LOG.info(f"\nData Summary:")
        LOG.info(f"  PhishTank malicious: {len(phish_df)}")
        if len(phishing_site_df) > 0:
            LOG.info(f"  phishing_site_urls malicious: {len(phishing_site_df[phishing_site_df['label'] == 1])}")
            LOG.info(f"  phishing_site_urls safe: {len(phishing_site_df[phishing_site_df['label'] == 0])}")
        LOG.info(f"  Total malicious: {total_malicious}")
        LOG.info(f"  Total safe (from phishing_site_urls): {total_safe}")
        
        # Generate additional safe URLs if needed for better balance
        # We want approximately 40% safe, 60% malicious
        target_safe = int(total_malicious * 0.4)
        if total_safe < target_safe:
            n_additional_safe = target_safe - total_safe
            LOG.info(f"Generating {n_additional_safe} additional safe URLs for better balance...")
            safe_df = generate_safe_urls(n_samples=n_additional_safe)
        else:
            LOG.info("Using safe URLs from phishing_site_urls only")
            safe_df = pd.DataFrame(columns=['url', 'label'])
        
        # Prepare dataset with balancing (40% safe, 60% malicious)
        dataset = prepare_dataset(phish_df, safe_df, phishing_site_df=phishing_site_df, balance_ratio=0.4)
        
        # Train model
        model, feature_cols, optimal_threshold = train_model(dataset)
        
        LOG.info("="*60)
        LOG.info("✅ Training completed successfully!")
        LOG.info(f"Model: {URL_MODEL_PATH}")
        LOG.info(f"Preprocessor: {URL_PREPROC_PATH}")
        LOG.info(f"Optimal threshold: {optimal_threshold:.3f}")
        LOG.info("="*60)
        
    except Exception as e:
        LOG.exception(f"❌ Training failed: {e}")
        raise


if __name__ == "__main__":
    main()

