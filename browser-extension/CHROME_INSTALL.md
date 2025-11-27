# 🚀 تثبيت NGFW Extension على Chrome

## الخطوات:

### 1. فتح Chrome Extensions
- افتح Chrome
- اذهب إلى: `chrome://extensions/`
- أو: القائمة (☰) → More tools → Extensions

### 2. تفعيل Developer Mode
- في أعلى الصفحة، فعّل "Developer mode" (وضع المطور)
- سترى زر "Load unpacked" يظهر

### 3. تحميل Extension
- اضغط على "Load unpacked"
- اختر مجلد: `browser-extension`
- سيتم تحميل Extension تلقائياً

### 4. التحقق من Permissions
- تأكد أن Extension لديه permissions:
  - ✅ Read and change all your data on all websites
  - ✅ Display notifications
  - ✅ Manage tabs

### 5. التحقق من العمل
- افتح Console: `chrome://extensions/` → Extension → Service Worker → Console
- يجب أن ترى: `✅ Loaded X declarative blocking rules`
- يجب أن ترى: `✅ Loaded X blocked URLs from backend`

### 6. الاختبار
- افتح رابط محظور: `https://exclusivofimdeanomlivre.com/754256983`
- يجب أن يتم منعه فوراً

## Troubleshooting

### إذا لم يعمل:
1. **تحقق من Backend:**
   - تأكد أن Backend يعمل على `http://127.0.0.1:5000`
   - افتح: `http://127.0.0.1:5000/health`

2. **تحقق من Console:**
   - افتح Service Worker Console
   - ابحث عن أخطاء (errors)

3. **إعادة التحميل:**
   - اضغط "Reload" على Extension
   - أعد تحميل الصفحة

4. **تحقق من Permissions:**
   - تأكد أن Extension لديه جميع الـ permissions المطلوبة

## ملاحظات:
- Extension يعمل على Chrome و Edge معاً
- Manifest V3 متوافق مع كلا المتصفحين
- لا حاجة لتغيير الكود


