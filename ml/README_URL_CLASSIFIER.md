# URL Classifier Model Training - Improved Version

## نظرة عامة
هذا الموديل المحسّن يستخدم بيانات متعددة المصادر (PhishTank + phishing_site_urls) لتدريب موديل ML محسّن لتصنيف الروابط (آمنة/خبيثة) بدقة أعلى.

## التحسينات الجديدة ✨

### 1. استخدام بيانات متعددة المصادر
- **PhishTank.csv**: بيانات phishing موثقة ومتحقق منها
- **phishing_site_urls.csv**: بيانات إضافية تحتوي على ~549K رابط (156K خبيث + 392K آمن)

### 2. تحسين استخراج الميزات (Features)
- إضافة ميزات جديدة: Brand keywords detection, Typosquatting indicators
- ميزات Entropy للكشف عن URLs عشوائية/مشبوهة
- كشف Shortened URLs (bit.ly, tinyurl, etc.)
- تحسين نسب الأحرف والرموز

### 3. تحسين معاملات الموديل (Hyperparameters)
- زيادة `num_leaves` من 31 إلى 64
- تقليل `learning_rate` من 0.05 إلى 0.03
- إضافة Regularization (L1 & L2)
- زيادة `num_boost_round` من 150 إلى 300
- تحسين Early stopping patience

### 4. تحسين التقييم
- إضافة ROC-AUC Score
- عرض Feature Importance
- تحسين Optimal Threshold finding

## المتطلبات
- Python 3.7+
- pandas
- numpy
- scikit-learn
- lightgbm
- joblib

## كيفية التدريب

### 1. التأكد من وجود الملفات المطلوبة
الملفات يجب أن تكون في المجلد الرئيسي للمشروع:
```
NGFW_Project/
  ├── PhishTank.csv
  ├── phishing_site_urls.csv
  └── ml/
      └── train_url_classifier.py
```

### 2. تشغيل التدريب
```bash
cd ml
python train_url_classifier.py
```

### 3. الملفات الناتجة
بعد التدريب، سيتم إنشاء:
- `ml/url_classifier_model.txt` - الموديل المدرب
- `ml/url_preprocessor.joblib` - معالج البيانات (feature columns)

## استخدام الموديل

الموديل يتم تحميله تلقائياً عند تشغيل backend:
```python
# في app.py
load_url_model_and_preproc()
```

يتم استخدامه في endpoint `/api/test-url`:
```python
POST /api/test-url
{
  "url": "https://example.com"
}
```

## Features المستخرجة (المحسّنة)

الموديل يستخدم الميزات التالية:

### الميزات الأساسية:
- URL length, domain length, path length, query length
- Number of dots, hyphens, underscores, slashes, question marks, equals, ampersands
- Character counts (digits, letters)

### ميزات Domain:
- IP address detection
- Number of subdomains
- TLD features (length, common TLDs)
- Domain has digits

### ميزات Path:
- Path depth
- File extension detection

### ميزات مشبوهة (Suspicious Patterns):
- **Suspicious keywords count**: login, verify, secure, banking, etc.
- **Brand keywords count**: paypal, amazon, microsoft, etc. (للكشف عن brand impersonation)
- **Typosquatting indicators**: أنماط URLs مشبوهة

### ميزات Encoding:
- Has encoding (%)
- Encoding ratio

### ميزات Entropy:
- **URL entropy**: للكشف عن URLs عشوائية/مشبوهة

### ميزات إضافية:
- Shortened URL detection (bit.ly, tinyurl, etc.)
- Character ratios (digits, letters, special chars, dots, slashes)
- Has HTTPS/HTTP
- Has @ symbol
- Has port number

## الأداء

بعد التدريب، سترى:
- **ROC-AUC Score**: مقياس شامل للأداء
- **Accuracy scores**: مع threshold افتراضي (0.5) و optimal threshold
- **Classification report**: Precision, Recall, F1-score لكل فئة
- **Confusion Matrix**: مصفوفة الارتباك
- **Top 15 Most Important Features**: أهم الميزات المستخدمة في التصنيف

## ملاحظات

- الموديل يستخدم بيانات متوازنة تلقائياً (40% safe, 60% malicious)
- البيانات من phishing_site_urls يتم دمجها تلقائياً مع PhishTank
- Safe URLs الإضافية يتم توليدها تلقائياً من domains موثوقة إذا لزم الأمر
- الموديل المحسّن يجب أن يعطي دقة أعلى في الكشف عن phishing URLs


