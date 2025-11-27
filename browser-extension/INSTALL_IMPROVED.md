# 🚀 تثبيت NGFW Extension المحسّن

## ✨ المميزات الجديدة

- ✅ **اعتراض أسرع**: يعمل قبل Microsoft Defender SmartScreen
- ✅ **فحص فوري**: يستخدم cache ذكي للروابط
- ✅ **وضع سريع**: فحص في أقل من 2 ثانية
- ✅ **اعتراض مزدوج**: يعترض في مرحلتين (onBeforeRequest + webNavigation)

## 📦 خطوات التثبيت

### 1. فتح صفحة Extensions في Chrome/Edge

```
chrome://extensions/
```
أو
```
edge://extensions/
```

### 2. تفعيل Developer Mode

- اضغط على **Developer mode** في الزاوية اليمنى العلوية

### 3. تحميل Extension

- اضغط على **Load unpacked**
- اختر مجلد `browser-extension`

### 4. التحقق من التثبيت

- يجب أن تظهر أيقونة NGFW في شريط الأدوات
- اضغط عليها للتأكد من أنها تعمل

## ⚙️ الإعدادات

### تفعيل Extension

1. افتح Extension popup
2. تأكد من أن **Enabled** مفعّل
3. يمكنك تعديل إعدادات API URL إذا لزم الأمر

### اختبار Extension

1. افتح أي رابط مشبوه (مثل: `https://example-phishing-site.com`)
2. يجب أن يظهر تحذير NGFW قبل SmartScreen
3. الرابط سيتم حظره فوراً

## 🔧 استكشاف الأخطاء

### Extension لا يعمل

1. تأكد من أن Backend يعمل على `http://localhost:5000`
2. افتح Developer Console في Extension:
   - اذهب إلى `chrome://extensions/`
   - اضغط على **Details** تحت Extension
   - اضغط على **Inspect views: service worker**
3. تحقق من الأخطاء في Console

### الروابط لا تُحظر

1. تأكد من أن `settings.enabled = true`
2. تحقق من أن API يعمل: `http://localhost:5000/api/health`
3. افتح Network tab في Developer Tools للتحقق من الطلبات

### SmartScreen يظهر قبل Extension

- هذا طبيعي أحياناً، لكن Extension يعمل في الخلفية
- Extension يحظر الروابط في `onBeforeRequest` قبل SmartScreen
- إذا ظهر SmartScreen، Extension قد حظر الرابط بالفعل

## 📝 ملاحظات

- Extension يستخدم **webRequest API** للاعتراض الفوري
- يستخدم **webNavigation API** كطبقة إضافية
- Cache يدوم 5 دقائق للروابط المفحوصة
- Timeout للفحص: 2 ثانية (قابل للتعديل)

## 🎯 الميزات

### اعتراض مزدوج
- **onBeforeRequest**: اعتراض فوري قبل تحميل الصفحة
- **webNavigation**: اعتراض إضافي في مرحلة التنقل

### Cache ذكي
- روابط محظورة: حفظ فوري
- روابط آمنة: حفظ لتسريع الفحص
- Cache يدوم 5 دقائق

### وضع سريع
- فحص فوري للروابط المشبوهة
- Timeout 2 ثانية
- Fail-open في حالة الخطأ


