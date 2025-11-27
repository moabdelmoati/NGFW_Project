# دليل تدريب النموذج المحسّن

## 📋 نظرة عامة

تم إنشاء سكربتات تدريب محسّنة للنموذج مع الميزات التالية:

### ✨ الميزات الجديدة

1. **معالجة بيانات محسّنة**
   - إزالة الأعمدة ذات القيم المفقودة الكثيرة (>80%)
   - إزالة الأعمدة الثابتة (zero variance)
   - إزالة الأعمدة عالية الارتباط (>95%)
   - معالجة القيم المفقودة (median للرقمية، 'unknown' للنصية)
   - تطبيق RobustScaler للخصائص الرقمية (أكثر مقاومة للقيم الشاذة)

2. **ضبط المعاملات (Hyperparameter Tuning)**
   - **train_supervised_improved.py**: يستخدم Optuna للبحث الأمثل
   - **train_supervised_improved_simple.py**: يستخدم Grid Search مبسط

3. **Cross-Validation**
   - Stratified K-Fold (5 folds) لضمان توزيع متوازن للفئات

4. **معالجة عدم التوازن في الفئات**
   - حساب class weights تلقائياً
   - تحسين الأداء على الفئات النادرة

5. **تقييم شامل**
   - Accuracy, Precision, Recall, F1-Score
   - AUC-ROC (للتصنيف الثنائي)
   - Confusion Matrix
   - Classification Report
   - Feature Importance (أهم 20 خاصية)

## 🚀 الاستخدام

### الخيار 1: استخدام Optuna (موصى به)

```bash
cd ml
python train_supervised_improved.py
```

**المميزات:**
- بحث ذكي عن أفضل المعاملات
- أداء أفضل عادة
- يستغرق وقت أطول (50 trial افتراضياً)

### الخيار 2: استخدام Grid Search (أسرع)

```bash
cd ml
python train_supervised_improved_simple.py
```

**المميزات:**
- أسرع في التنفيذ
- لا يحتاج Optuna
- أداء جيد جداً

## 📊 الملفات الناتجة

بعد التدريب، سيتم إنشاء:

1. **lgb_model.txt**: النموذج المدرب
2. **preproc.joblib**: معالج البيانات (encoder, scaler, mappings)
3. **model_metrics.joblib**: مقاييس الأداء والمعاملات الأفضل

## ⚙️ التخصيص

يمكنك تعديل المعاملات في بداية السكربت:

```python
PARQUET = "sampled_600k.parquet"  # ملف البيانات
N_TRIALS = 50                      # عدد محاولات Optuna (للنسخة المحسّنة)
CV_FOLDS = 5                       # عدد folds للـ cross-validation
TEST_SIZE = 0.2                    # نسبة بيانات الاختبار
```

## 🔄 الترقية من النموذج القديم

1. احفظ النموذج القديم كنسخة احتياطية:
   ```bash
   cp ml/lgb_model.txt ml/lgb_model_old.txt
   cp ml/preproc.joblib ml/preproc_old.joblib
   ```

2. قم بتدريب النموذج الجديد:
   ```bash
   cd ml
   python train_supervised_improved.py
   ```

3. اختبر النموذج الجديد في الـ backend

4. إذا كان الأداء أفضل، احذف النسخ القديمة

## 📈 مقارنة الأداء

النموذج المحسّن عادة ما يحقق:
- **دقة أعلى** (Accuracy)
- **F1-Score أفضل** خاصة للفئات النادرة
- **استقرار أفضل** (أقل overfitting)

## 🐛 استكشاف الأخطاء

### خطأ: "ModuleNotFoundError: No module named 'optuna'"
**الحل**: استخدم `train_supervised_improved_simple.py` أو ثبت Optuna:
```bash
pip install optuna>=3.0.0
```

### خطأ: "Memory Error"
**الحل**: قلل حجم البيانات أو استخدم sample أصغر:
```python
# في ml.py، غيّر:
SAMPLE_SIZE = 300_000  # بدلاً من 600_000
```

### خطأ: "Label column not found"
**الحل**: تأكد من وجود عمود التصنيف بأحد الأسماء:
- `label`, `Label`, `attack`, `Attack`, `class`, `Class`

## 📝 ملاحظات

- النموذج المحسّن متوافق مع الـ backend الحالي
- معالج البيانات الجديد يحفظ معلومات أكثر (scaler, mappings)
- يمكن استخدام النموذج مباشرة دون تعديلات على الـ backend








