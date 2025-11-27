"""
Improved ML Training Script with:
- Advanced hyperparameter tuning (Optuna)
- Better preprocessing and feature engineering
- Cross-validation
- Class imbalance handling
- Feature importance analysis
- Better evaluation metrics
"""

import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import OrdinalEncoder, RobustScaler
from sklearn.metrics import (
    classification_report, 
    confusion_matrix, 
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    roc_curve
)
import lightgbm as lgb
import joblib
import optuna
from optuna.integration import LightGBMPruningCallback
import warnings
import sys
from pathlib import Path

# Add current directory to path to import preprocessing_pipeline
sys.path.insert(0, str(Path(__file__).parent))
from preprocessing_pipeline import PreprocessingPipeline

warnings.filterwarnings('ignore')

# ========== Configuration ==========
PARQUET = "sampled_600k.parquet"
RANDOM_SEED = 42
TEST_SIZE = 0.2
LABEL_CANDIDATES = ['label','Label','attack','Attack','class','Class','labelled','labelled_class','target']
N_TRIALS = 50  # Number of Optuna trials for hyperparameter tuning
CV_FOLDS = 5   # Cross-validation folds

print("=" * 60)
print(" Improved ML Model Training")
print("=" * 60)

# ========== 1. Load Data ==========
print("\n[1/8] Loading data...")
df = pd.read_parquet(PARQUET)
print(f"[OK] Loaded {len(df):,} rows")
print(f"   Columns: {len(df.columns)}")

# ========== 2. Detect Label Column ==========
print("\n[2/8] Detecting label column...")
label_col = None
for c in LABEL_CANDIDATES:
    if c in df.columns:
        label_col = c
        break

if label_col is None:
    for c in df.columns:
        nunique = df[c].nunique(dropna=True)
        if 2 <= nunique <= 200 and df[c].dtype != 'float64' and df[c].dtype != 'int64':
            label_col = c
            print(f"   Auto-detected: {c} (unique={nunique})")
            break

if label_col is None:
    raise SystemExit("[ERROR] لم أجد عمود التصنيف. يرجى التأكد من وجود عمود 'label' أو 'attack'")

print(f"[OK] Using label column: {label_col}")

# ========== 3. Prepare Features and Labels ==========
print("\n[3/8] Preparing features and labels...")
y = df[label_col].copy()
X = df.drop(columns=[label_col])

# Normalize labels
y = y.astype(str).str.strip().str.lower()

# Create label mapping
unique_labels = sorted(y.unique())
label_mapping = {lbl: i for i, lbl in enumerate(unique_labels)}
reverse_mapping = {i: lbl for lbl, i in label_mapping.items()}
print(f"   Label mapping: {label_mapping}")
print(f"   Number of classes: {len(unique_labels)}")

# Check for class imbalance
label_counts = y.value_counts()
print(f"\n   Class distribution:")
for lbl, count in label_counts.items():
    pct = (count / len(y)) * 100
    print(f"     {lbl}: {count:,} ({pct:.2f}%)")

y = y.map(label_mapping)
is_multiclass = y.nunique() > 2

# ========== 4. Data Cleaning ==========
print("\n[4/8] Cleaning data...")
initial_cols = len(X.columns)

# Drop high-cardinality or non-informative columns
DROP_COLS = ['payload', 'raw_payload', 'data', 'timestamp', 'time', 'date']
for col in DROP_COLS:
    if col in X.columns:
        X = X.drop(columns=[col])

# Drop columns with too many missing values (>80%)
missing_threshold = 0.8
missing_pct = X.isnull().sum() / len(X)
cols_to_drop_missing = missing_pct[missing_pct > missing_threshold].index.tolist()
if cols_to_drop_missing:
    X = X.drop(columns=cols_to_drop_missing)
    print(f"   Dropped {len(cols_to_drop_missing)} columns with >{missing_threshold*100}% missing values")

# Drop constant columns (zero variance)
constant_cols = [col for col in X.columns if X[col].nunique() <= 1]
if constant_cols:
    X = X.drop(columns=constant_cols)
    print(f"   Dropped {len(constant_cols)} constant columns")

print(f"[OK] Kept {len(X.columns)}/{initial_cols} columns after cleaning")

# ========== 5. Feature Engineering ==========
print("\n[5/8] Feature engineering...")
X_original = X.copy()

# Separate numeric and categorical columns
num_cols = X.select_dtypes(include=[np.number]).columns.tolist()
cat_cols = X.select_dtypes(exclude=[np.number]).columns.tolist()
print(f"   Numeric columns: {len(num_cols)}")
print(f"   Categorical columns: {len(cat_cols)}")

# Handle missing values
print("   Handling missing values...")
for col in num_cols:
    if X[col].isnull().any():
        # Use median for numeric (more robust than mean)
        X[col].fillna(X[col].median(), inplace=True)

for col in cat_cols:
    if X[col].isnull().any():
        X[col].fillna('unknown', inplace=True)

# Encode categorical variables
oe = None
if cat_cols:
    print("   Encoding categorical variables...")
    oe = OrdinalEncoder(handle_unknown='use_encoded_value', unknown_value=-1)
    X[cat_cols] = oe.fit_transform(X[cat_cols].astype(str))
    # Convert to numeric after encoding
    X[cat_cols] = X[cat_cols].astype(float)

# Scale numeric features (RobustScaler is more robust to outliers)
print("   Scaling numeric features...")
scaler = RobustScaler()
X[num_cols] = scaler.fit_transform(X[num_cols])

# Feature selection: Remove highly correlated features
print("   Removing highly correlated features...")
corr_matrix = X.corr().abs()
upper_triangle = corr_matrix.where(
    np.triu(np.ones(corr_matrix.shape), k=1).astype(bool)
)
high_corr_cols = [col for col in upper_triangle.columns if any(upper_triangle[col] > 0.95)]
if high_corr_cols:
    X = X.drop(columns=high_corr_cols)
    print(f"   Dropped {len(high_corr_cols)} highly correlated columns")

print(f"[OK] Final feature count: {len(X.columns)}")

# ========== 6. Train-Test Split ==========
print("\n[6/8] Splitting data...")
stratify = y if y.nunique() <= 100 else None
X_train, X_test, y_train, y_test = train_test_split(
    X, y, 
    test_size=TEST_SIZE, 
    random_state=RANDOM_SEED, 
    stratify=stratify
)
print(f"[OK] Train: {len(X_train):,} samples")
print(f"   Test: {len(X_test):,} samples")

# ========== 7. Hyperparameter Tuning with Optuna ==========
print("\n[7/8] Hyperparameter tuning with Optuna...")
print(f"   Running {N_TRIALS} trials...")

def objective(trial):
    """Optuna objective function for hyperparameter tuning"""
    params = {
        'objective': 'multiclass' if is_multiclass else 'binary',
        'num_class': y.nunique() if is_multiclass else 1,
        'metric': 'multi_logloss' if is_multiclass else 'binary_logloss',
        'boosting_type': 'gbdt',
        'learning_rate': trial.suggest_float('learning_rate', 0.01, 0.3, log=True),
        'num_leaves': trial.suggest_int('num_leaves', 20, 300),
        'max_depth': trial.suggest_int('max_depth', 3, 15),
        'min_data_in_leaf': trial.suggest_int('min_data_in_leaf', 10, 100),
        'feature_fraction': trial.suggest_float('feature_fraction', 0.5, 1.0),
        'bagging_fraction': trial.suggest_float('bagging_fraction', 0.5, 1.0),
        'bagging_freq': trial.suggest_int('bagging_freq', 1, 7),
        'lambda_l1': trial.suggest_float('lambda_l1', 1e-8, 10.0, log=True),
        'lambda_l2': trial.suggest_float('lambda_l2', 1e-8, 10.0, log=True),
        'min_gain_to_split': trial.suggest_float('min_gain_to_split', 0, 15),
        'seed': RANDOM_SEED,
        'verbosity': -1,
        'force_row_wise': True
    }
    
    # Cross-validation
    skf = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_SEED)
    cv_scores = []
    
    for train_idx, val_idx in skf.split(X_train, y_train):
        X_tr, X_val = X_train.iloc[train_idx], X_train.iloc[val_idx]
        y_tr, y_val = y_train.iloc[train_idx], y_train.iloc[val_idx]
        
        # Handle class imbalance using sample_weight (LightGBM doesn't support class_weight dict)
        sample_weights = None
        if is_multiclass:
            class_counts = y_tr.value_counts().sort_index()
            total = len(y_tr)
            class_weights_dict = {i: total / (len(class_counts) * count) 
                                  for i, count in enumerate(class_counts)}
            sample_weights = y_tr.map(class_weights_dict).values
        
        if sample_weights is not None:
            train_data = lgb.Dataset(X_tr, label=y_tr, weight=sample_weights)
        else:
            train_data = lgb.Dataset(X_tr, label=y_tr)
        val_data = lgb.Dataset(X_val, label=y_val, reference=train_data)
        
        model = lgb.train(
            params,
            train_data,
            valid_sets=[val_data],
            num_boost_round=1000,
            callbacks=[
                LightGBMPruningCallback(trial, 'multi_logloss' if is_multiclass else 'binary_logloss'),
                lgb.early_stopping(stopping_rounds=50, verbose=False)
            ]
        )
        
        y_pred = model.predict(X_val)
        if is_multiclass:
            y_pred_class = np.argmax(y_pred, axis=1)
        else:
            y_pred_class = (y_pred > 0.5).astype(int)
        
        score = f1_score(y_val, y_pred_class, average='weighted')
        cv_scores.append(score)
    
    return np.mean(cv_scores)

# Run Optuna optimization
study = optuna.create_study(direction='maximize', study_name='lgb_optimization')
study.optimize(objective, n_trials=N_TRIALS, show_progress_bar=True)

print(f"[OK] Best hyperparameters found!")
print(f"   Best CV score: {study.best_value:.4f}")
print("\n   Best parameters:")
for key, value in study.best_params.items():
    print(f"     {key}: {value}")

# ========== 8. Train Final Model ==========
print("\n[8/8] Training final model with best hyperparameters...")

best_params = study.best_params.copy()
best_params.update({
    'objective': 'multiclass' if is_multiclass else 'binary',
    'num_class': y.nunique() if is_multiclass else 1,
    'metric': 'multi_logloss' if is_multiclass else 'binary_logloss',
    'boosting_type': 'gbdt',
    'seed': RANDOM_SEED,
    'verbosity': -1,
    'force_row_wise': True
})

# Handle class imbalance using sample_weight in final model
train_sample_weights = None
if is_multiclass:
    class_counts = y_train.value_counts().sort_index()
    total = len(y_train)
    class_weights_dict = {i: total / (len(class_counts) * count) 
                          for i, count in enumerate(class_counts)}
    train_sample_weights = y_train.map(class_weights_dict).values

if train_sample_weights is not None:
    train_data = lgb.Dataset(X_train, label=y_train, weight=train_sample_weights)
else:
    train_data = lgb.Dataset(X_train, label=y_train)
valid_data = lgb.Dataset(X_test, label=y_test, reference=train_data)

final_model = lgb.train(
    best_params,
    train_data,
    valid_sets=[train_data, valid_data],
    valid_names=['train', 'valid'],
    num_boost_round=2000,
    callbacks=[
        lgb.early_stopping(stopping_rounds=100, verbose=True),
        lgb.log_evaluation(period=100)
    ]
)

# ========== 9. Evaluation ==========
print("\n" + "=" * 60)
print("[EVAL] Model Evaluation")
print("=" * 60)

y_pred_prob = final_model.predict(X_test)
if is_multiclass:
    y_pred = np.argmax(y_pred_prob, axis=1)
else:
    y_pred = (y_pred_prob > 0.5).astype(int)
    y_pred_prob = y_pred_prob.flatten()

# Calculate metrics
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)

print(f"\n[METRICS] Overall Metrics:")
print(f"   Accuracy:  {accuracy:.4f}")
print(f"   Precision: {precision:.4f}")
print(f"   Recall:    {recall:.4f}")
print(f"   F1-Score:  {f1:.4f}")

if not is_multiclass:
    try:
        auc = roc_auc_score(y_test, y_pred_prob)
        print(f"   AUC-ROC:   {auc:.4f}")
    except:
        pass

print(f"\n[REPORT] Classification Report:")
print(classification_report(y_test, y_pred, 
                          target_names=[reverse_mapping[i] for i in range(len(reverse_mapping))]))

print(f"\n[EVAL] Confusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print(cm)

# Feature importance
print(f"\n[TOP] Top 20 Most Important Features:")
feature_importance = pd.DataFrame({
    'feature': X.columns,
    'importance': final_model.feature_importance(importance_type='gain')
}).sort_values('importance', ascending=False)

for idx, row in feature_importance.head(20).iterrows():
    print(f"   {row['feature']}: {row['importance']:.2f}")

# ========== 10. Save Model and Preprocessing ==========
print("\n" + "=" * 60)
print("[SAVE] Saving model and preprocessing...")
print("=" * 60)

MODEL_PATH = "lgb_model.txt"
PREPROC_PATH = "preproc.joblib"

final_model.save_model(MODEL_PATH)
print(f"[OK] Model saved: {MODEL_PATH}")

# Create preprocessing pipeline for easy use in backend
preproc_pipeline = PreprocessingPipeline(
    num_cols=num_cols,
    cat_cols=cat_cols,
    feature_names=X.columns.tolist()
)
preproc_pipeline.fit(X_train)

# Save both dict (for compatibility) and pipeline (for easy transform)
preproc_dict = {
    'preprocessor': preproc_pipeline,  # Main preprocessor with transform method
    'ordinal_encoder': oe,
    'scaler': scaler,
    'num_cols': num_cols,
    'cat_cols': cat_cols,
    'label_mapping': label_mapping,
    'reverse_mapping': reverse_mapping,
    'feature_names': X.columns.tolist(),
    'is_multiclass': is_multiclass
}

joblib.dump(preproc_dict, PREPROC_PATH)
print(f"[OK] Preprocessor saved: {PREPROC_PATH}")

# Save evaluation metrics
metrics_dict = {
    'accuracy': float(accuracy),
    'precision': float(precision),
    'recall': float(recall),
    'f1_score': float(f1),
    'best_params': study.best_params,
    'best_cv_score': float(study.best_value)
}

if not is_multiclass:
    try:
        metrics_dict['auc_roc'] = float(auc)
    except:
        pass

joblib.dump(metrics_dict, "model_metrics.joblib")
print(f"[OK] Metrics saved: model_metrics.joblib")

print("\n" + "=" * 60)
print("[OK] Training completed successfully!")
print("=" * 60)
print(f"\n📁 Files created:")
print(f"   - {MODEL_PATH}")
print(f"   - {PREPROC_PATH}")
print(f"   - model_metrics.joblib")
print(f"\n[PERF] Model Performance:")
print(f"   Accuracy: {accuracy:.2%}")
print(f"   F1-Score: {f1:.2%}")

