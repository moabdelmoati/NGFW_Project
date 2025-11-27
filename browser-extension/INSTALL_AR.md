# 📥 دليل التثبيت السريع - Browser Extension

## Chrome / Edge

1. افتح المتصفح
2. اذهب إلى: `chrome://extensions/` (أو `edge://extensions/`)
3. فعّل **Developer mode** (في الزاوية اليمنى العلوية)
4. اضغط **Load unpacked**
5. اختر مجلد `browser-extension`
6. تم! ✅

## Firefox

1. افتح Firefox
2. اذهب إلى: `about:debugging`
3. اضغط **This Firefox**
4. اضغط **Load Temporary Add-on**
5. اختر ملف `manifest.json` من مجلد `browser-extension`
6. تم! ✅

## ⚠️ ملاحظة مهمة

- يجب أن يكون Backend يعمل على `http://127.0.0.1:5000`
- بدون Backend، لن يعمل Extension
- يمكنك تفعيل/تعطيل Extension من popup

## 🎯 بعد التثبيت

1. افتح أي رابط في المتصفح
2. سيتم فحصه تلقائياً
3. إذا كان مشبوهاً، سيتم حظره
4. شاهد الروابط المحظورة في Dashboard

---

**للمزيد من التفاصيل، راجع `URL_INTERCEPTION_GUIDE.md`**


