# 🔒 دليل منع الروابط - Blocking Guide

## المشكلة
النظام يكتشف الروابط لكن لا يمنعها من الفتح مرة أخرى.

## الحل المطبق

### 1. تحسين Background Script
- ✅ تحميل الروابط المحظورة من Backend عند بدء التشغيل
- ✅ تحديث القائمة كل 30 ثانية
- ✅ فحص فوري من القائمة المحلية (أسرع)
- ✅ فحص غير متزامن مع Backend (للاكتشاف الجديد)

### 2. تحسين Content Script
- ✅ منع تحميل الصفحة فوراً عند اكتشاف رابط محظور
- ✅ اعتراض جميع الروابط في الصفحة
- ✅ منع التنقل حتى يتم الفحص

### 3. آلية المنع
1. **الفحص الفوري**: من القائمة المحلية (blockedUrls Set)
2. **الفحص من الكاش**: إذا كان الرابط فُحص مؤخراً
3. **الفحص من Backend**: إذا لم يكن في القائمة المحلية

### 4. Manifest V3
- ✅ إضافة `webRequestBlocking` permission
- ✅ استخدام `blocking` في `onBeforeRequest`
- ✅ Content script يعمل في `document_start`

## كيفية التثبيت

1. **افتح Chrome Extensions**:
   - `chrome://extensions/`

2. **فعّل Developer Mode**

3. **Load Extension**:
   - اضغط "Load unpacked"
   - اختر مجلد `browser-extension`

4. **تحقق من Permissions**:
   - تأكد أن Extension لديه permissions للوصول لجميع المواقع

## الاختبار

1. افتح رابط مشبوه: `https://exclusivofimdeanomlivre.com/429518763`
2. يجب أن يظهر:
   - صفحة حظر فوراً
   - رسالة "Blocked URL - NGFW Security"
   - زر "Go Back"

## Troubleshooting

### إذا لم يعمل المنع:
1. تحقق من أن Backend يعمل: http://localhost:5000/health
2. تحقق من Console في Extension (F12)
3. تحقق من Console في Content Script
4. تأكد من أن Extension مُفعّل

### Logs للتحقق:
- Background Script: `chrome://extensions/` → Extension → Service Worker → Console
- Content Script: F12 في الصفحة → Console

## الملفات المحدثة
- `browser-extension/background.js` - تحسين آلية المنع
- `browser-extension/content.js` - تحسين منع تحميل الصفحة
- `browser-extension/manifest.json` - إضافة webRequestBlocking


