// Enhanced Blocking Engine for NGFW Extension
// محرك منع محسّن يعمل بشكل فوري

const API_BASE = 'http://127.0.0.1:5000/api';

// قائمة الروابط المحظورة (محلية - فورية)
const blockedUrlsSet = new Set();
const safeUrlsSet = new Set();

// قائمة انتظار للفحص
const pendingChecks = new Map();

// تحميل القائمة المحظورة من Backend عند بدء التشغيل
async function loadBlockedUrls() {
  try {
    const response = await fetch(`${API_BASE}/blocked-urls?n=1000`);
    const data = await response.json();
    
    if (Array.isArray(data)) {
      data.forEach(item => {
        if (item.url && item.is_blocked) {
          blockedUrlsSet.add(item.url);
        } else if (item.url && item.is_safe) {
          safeUrlsSet.add(item.url);
        }
      });
      console.log(`✅ Loaded ${blockedUrlsSet.size} blocked URLs and ${safeUrlsSet.size} safe URLs`);
    }
  } catch (error) {
    console.error('Error loading blocked URLs:', error);
  }
}

// فحص URL مع Backend
async function checkUrlWithBackend(url) {
  // التحقق من القوائم المحلية أولاً (فوري)
  if (blockedUrlsSet.has(url)) {
    return { blocked: true, cached: true };
  }
  if (safeUrlsSet.has(url)) {
    return { blocked: false, cached: true };
  }

  // إذا كان هناك فحص قيد التنفيذ، انتظر نتيجته
  if (pendingChecks.has(url)) {
    return await pendingChecks.get(url);
  }

  // إنشاء Promise للفحص
  const checkPromise = (async () => {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 1500); // timeout 1.5 ثانية

      const response = await fetch(`${API_BASE}/intercept-url`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url: url,
          src_ip: 'browser-extension'
        }),
        signal: controller.signal
      });

      clearTimeout(timeoutId);
      const result = await response.json();
      
      // حفظ في القوائم المحلية
      if (result.blocked) {
        blockedUrlsSet.add(url);
      } else if (result.is_safe) {
        safeUrlsSet.add(url);
      }

      // إزالة من قائمة الانتظار
      pendingChecks.delete(url);

      return result;
    } catch (error) {
      pendingChecks.delete(url);
      
      if (error.name === 'AbortError') {
        console.warn('URL check timeout:', url);
        return { blocked: false, timeout: true };
      }
      
      console.error('Error checking URL:', error);
      return { blocked: false, error: error.message };
    }
  })();

  // إضافة للقائمة الانتظار
  pendingChecks.set(url, checkPromise);
  
  return checkPromise;
}

// Export للاستخدام في background.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { loadBlockedUrls, checkUrlWithBackend, blockedUrlsSet, safeUrlsSet };
}


