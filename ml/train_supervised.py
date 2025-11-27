# train_supervised.py
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OrdinalEncoder
from sklearn.metrics import classification_report, confusion_matrix
import lightgbm as lgb
import joblib

PARQUET = "sampled_600k.parquet"
RANDOM_SEED = 42
TEST_SIZE = 0.2
LABEL_CANDIDATES = ['label','Label','attack','Attack','class','Class','labelled','labelled_class','target']

# 1. load
df = pd.read_parquet(PARQUET)
print("Loaded rows:", len(df))
print("Columns:", df.columns.tolist())

# 2. detect label column automatically from common names
label_col = None
for c in LABEL_CANDIDATES:
    if c in df.columns:
        label_col = c
        break

if label_col is None:
    # fallback: if there's a column with few unique small set, pick it (likely categorical label)
    for c in df.columns:
        nunique = df[c].nunique(dropna=True)
        if 2 <= nunique <= 200 and df[c].dtype != 'float64' and df[c].dtype != 'int64':
            label_col = c
            print(f"Auto-detected possible label column: {c} (unique={nunique})")
            break

if label_col is None:
    raise SystemExit("لم أوجد عمود تصنيف تلقائياً. لو عندكم label سمّوه 'label' أو أعطوني اسمه.")

print("Using label column:", label_col)

# 3. prepare features X and y
y = df[label_col].copy()
X = df.drop(columns=[label_col])
# تأكد أن الlabels كلها نصوص صغيرة وموحدة
y = y.astype(str).str.strip().str.lower()

# لو هي binary (Normal vs Attack مثلاً) نحولهم لأرقام
if y.nunique() == 2:
    mapping = {lbl: i for i, lbl in enumerate(sorted(y.unique()))}
    print("Label mapping:", mapping)
    y = y.map(mapping)
else:
    # لو فئات متعددة نعمل ترقيم لكل فئة
    mapping = {lbl: i for i, lbl in enumerate(sorted(y.unique()))}
    print("Multiclass mapping:", mapping)
    y = y.map(mapping)

# 4. basic cleaning: drop columns with too many unique values like raw payloads or timestamps if you want
# يمكنك تعديل هذه القائمة حسب أعمدتك
DROP_LIKE = []
# Example: drop text payload column if exists:
for col in ['payload','raw_payload','data','timestamp']:
    if col in X.columns:
        DROP_LIKE.append(col)
if DROP_LIKE:
    X = X.drop(columns=DROP_LIKE)
    print("Dropped cols:", DROP_LIKE)

# 5. separate numeric vs categorical
num_cols = X.select_dtypes(include=[np.number]).columns.tolist()
cat_cols = X.select_dtypes(exclude=[np.number]).columns.tolist()
print("Numeric cols:", len(num_cols), "Categorical cols:", len(cat_cols))

# 6. encode categoricals with OrdinalEncoder (LightGBM handles categorical indices)
if cat_cols:
    oe = OrdinalEncoder(handle_unknown='use_encoded_value', unknown_value=-1)
    X[cat_cols] = oe.fit_transform(X[cat_cols].astype(str))
else:
    oe = None

# 7. train-test split (stratify if possible)
stratify = y if y.nunique() <= 100 else None
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=TEST_SIZE, random_state=RANDOM_SEED, stratify=stratify)
print("Train / Test:", len(X_train), len(X_test))

# 8. LightGBM dataset
train_data = lgb.Dataset(X_train, label=y_train)
valid_data = lgb.Dataset(X_test, label=y_test, reference=train_data)

params = {
    'objective': 'multiclass' if y.nunique() > 2 else 'binary',
    'num_class': y.nunique() if y.nunique() > 2 else 1,
    'metric': 'multi_logloss' if y.nunique() > 2 else 'binary_logloss',
    'learning_rate': 0.1,
    'num_leaves': 127,
    'seed': RANDOM_SEED,
    'verbosity': -1
}

from lightgbm import early_stopping, log_evaluation

bst = lgb.train(
    params,
    train_data,
    valid_sets=[train_data, valid_data],
    num_boost_round=1000,
    callbacks=[
        early_stopping(stopping_rounds=50),
        log_evaluation(period=50)
    ]
)

# 9. predict & evaluate
y_pred_prob = bst.predict(X_test)
if y.nunique() > 2:
    y_pred = np.argmax(y_pred_prob, axis=1)
else:
    y_pred = (y_pred_prob > 0.5).astype(int)

print(classification_report(y_test, y_pred))
print("Confusion matrix:")
print(confusion_matrix(y_test, y_pred))

# 10. save model + preprocessing
MODEL_PATH = "lgb_model.txt"
bst.save_model(MODEL_PATH)
joblib.dump({'ordinal_encoder': oe, 'num_cols': num_cols, 'cat_cols': cat_cols}, "preproc.joblib")
print("Saved model and preprocessor.")
