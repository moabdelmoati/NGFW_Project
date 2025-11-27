// NGFW URL Interceptor - Background Service Worker
// محسّن لاعتراض الروابط قبل Microsoft Defender SmartScreen
const API_BASE = 'http://127.0.0.1:5000/api';

// Declarative Net Request Blocker - أقوى تقنية لمنع الروابط
let declarativeBlocker = null;

// دالة للتحقق من أن URL ليس localhost أو IP محلي
function isLocalUrl(url) {
  if (!url) return false;
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    return hostname === 'localhost' || 
           hostname === '127.0.0.1' || 
           hostname === '0.0.0.0' ||
           hostname === '::1' ||
           hostname.startsWith('127.') ||
           hostname.startsWith('192.168.') ||
           hostname.startsWith('10.') ||
           hostname.startsWith('172.');
  } catch (e) {
    return false;
  }
}

// تحميل قواعد declarativeNetRequest
async function loadDeclarativeRules() {
  try {
    const response = await fetch(`${API_BASE}/blocked-urls?n=1000`);
    if (!response.ok) return;
    
    const blockedUrls = await response.json();
    if (!Array.isArray(blockedUrls)) return;

    const rules = [];
    const seenUrls = new Set();
    let ruleId = 1;

    // إضافة قواعد السماح لـ localhost أولاً (أولوية عالية)
    // استخدام regex patterns للسماح بجميع المنافذ
    const allowRules = [
      {
        id: 1,
        priority: 1000, // أولوية عالية جداً
        action: { type: 'allow' },
        condition: {
          regexFilter: '^https?://localhost(:\\d+)?(/.*)?$',
          resourceTypes: ['main_frame', 'sub_frame']
        }
      },
      {
        id: 2,
        priority: 1000,
        action: { type: 'allow' },
        condition: {
          regexFilter: '^https?://127\\.0\\.0\\.1(:\\d+)?(/.*)?$',
          resourceTypes: ['main_frame', 'sub_frame']
        }
      },
      {
        id: 3,
        priority: 1000,
        action: { type: 'allow' },
        condition: {
          regexFilter: '^https?://0\\.0\\.0\\.0(:\\d+)?(/.*)?$',
          resourceTypes: ['main_frame', 'sub_frame']
        }
      },
      {
        id: 4,
        priority: 1000,
        action: { type: 'allow' },
        condition: {
          regexFilter: '^https?://192\\.168\\.[\\d.]+(:\\d+)?(/.*)?$',
          resourceTypes: ['main_frame', 'sub_frame']
        }
      },
      {
        id: 5,
        priority: 1000,
        action: { type: 'allow' },
        condition: {
          regexFilter: '^https?://10\\.[\\d.]+(:\\d+)?(/.*)?$',
          resourceTypes: ['main_frame', 'sub_frame']
        }
      },
      {
        id: 6,
        priority: 1000,
        action: { type: 'allow' },
        condition: {
          regexFilter: '^https?://172\\.(1[6-9]|2[0-9]|3[0-1])\\.[\\d.]+(:\\d+)?(/.*)?$',
          resourceTypes: ['main_frame', 'sub_frame']
        }
      }
    ];
    rules.push(...allowRules);
    ruleId = 7;

    blockedUrls.forEach((item) => {
      if (item.url && item.is_blocked && !seenUrls.has(item.url)) {
        // تجاهل localhost و IPs محلية تماماً
        if (isLocalUrl(item.url)) {
          console.log('⚠️ Skipping localhost URL from blocking rules:', item.url);
          return;
        }
        seenUrls.add(item.url);
        rules.push({
          id: ruleId++,
          priority: 1,
          action: { type: 'block' },
          condition: {
            urlFilter: item.url,
            resourceTypes: ['main_frame', 'sub_frame']
          }
        });
      }
    });

    if (rules.length > 0) {
      // حذف القواعد القديمة أولاً
      const oldRules = await chrome.declarativeNetRequest.getDynamicRules();
      if (oldRules.length > 0) {
        await chrome.declarativeNetRequest.updateDynamicRules({
          removeRuleIds: oldRules.map(r => r.id)
        });
      }
      
      // إضافة القواعد الجديدة
      await chrome.declarativeNetRequest.updateDynamicRules({
        addRules: rules
      });
      
      console.log(`✅ Loaded ${rules.length} declarative blocking rules`);
    }
  } catch (error) {
    console.error('Error loading declarative rules:', error);
  }
}

// تحميل القواعد عند بدء التشغيل
if (chrome.declarativeNetRequest) {
  loadDeclarativeRules();
  setInterval(loadDeclarativeRules, 30000);
  
  declarativeBlocker = {
    loadBlockingRules: loadDeclarativeRules,
    addBlockingRule: async (url) => {
      try {
        // عدم إضافة localhost للقواعد المحظورة
        if (isLocalUrl(url)) {
          console.log('⚠️ Skipping localhost URL from blocking:', url);
          return;
        }
        const oldRules = await chrome.declarativeNetRequest.getDynamicRules();
        const maxId = oldRules.length > 0 ? Math.max(...oldRules.map(r => r.id)) : 0;
        const newRule = {
          id: maxId + 1,
          priority: 1,
          action: { type: 'block' },
          condition: {
            urlFilter: url,
            resourceTypes: ['main_frame', 'sub_frame']
          }
        };
        await chrome.declarativeNetRequest.updateDynamicRules({
          addRules: [newRule]
        });
      } catch (e) {
        console.error('Error adding declarative rule:', e);
      }
    }
  };
}

// Cache للروابط المفحوصة (لتجنب فحص نفس الرابط مرات متعددة)
const urlCache = new Map();
const CACHE_DURATION = 5 * 60 * 1000; // 5 دقائق

// قائمة الروابط المحظورة مؤقتاً (للوصول السريع)
const blockedUrls = new Set();
const safeUrls = new Set(); // قائمة الروابط الآمنة المعروفة

// قائمة انتظار للفحص السريع (للروابط المشبوهة)
const pendingChecks = new Map();

// تحميل الروابط المحظورة من Backend عند بدء التشغيل
async function loadBlockedUrlsFromBackend() {
  try {
    const response = await fetch(`${API_BASE}/blocked-urls?n=1000`);
    if (!response.ok) {
      console.warn('Failed to load blocked URLs:', response.status);
      return;
    }
    const data = await response.json();
    
    if (Array.isArray(data)) {
      let loaded = 0;
      data.forEach(item => {
        if (item.url && item.is_blocked) {
          // عدم إضافة localhost للقائمة المحظورة
          if (!isLocalUrl(item.url)) {
            blockedUrls.add(item.url);
            loaded++;
          } else {
            console.log('⚠️ Skipping localhost from blocked list:', item.url);
          }
        } else if (item.url && !item.is_blocked) {
          safeUrls.add(item.url);
        }
      });
      console.log(`✅ Loaded ${loaded} blocked URLs from backend (total cached: ${blockedUrls.size})`);
    }
  } catch (error) {
    console.error('Error loading blocked URLs from backend:', error);
    // لا نوقف التطبيق في حالة الخطأ
  }
}

// تحميل عند بدء التشغيل
loadBlockedUrlsFromBackend();
// إعادة التحميل كل 30 ثانية
setInterval(loadBlockedUrlsFromBackend, 30000);

// تحميل قواعد declarativeNetRequest
if (declarativeBlocker) {
  declarativeBlocker.loadBlockingRules();
  setInterval(() => {
    declarativeBlocker.loadBlockingRules();
  }, 30000);
}

// إعدادات
let settings = {
  enabled: true,
  apiUrl: API_BASE,
  showNotifications: true,
  fastMode: true, // وضع سريع - فحص فوري
  timeout: 2000 // timeout للفحص (2 ثانية)
};

// تحميل الإعدادات
chrome.storage.sync.get(['ngfwSettings'], (result) => {
  if (result.ngfwSettings) {
    settings = { ...settings, ...result.ngfwSettings };
  }
});

// حفظ الإعدادات
function saveSettings() {
  chrome.storage.sync.set({ ngfwSettings: settings });
}

// فحص URL بشكل سريع (مع timeout)
async function checkUrl(url, fastCheck = false) {
  // السماح فوراً لـ localhost و IPs محلية
  if (isLocalUrl(url)) {
    return { blocked: false, cached: true, is_safe: true, message: 'Local URL - Always allowed' };
  }

  // التحقق من الكاش أولاً (أسرع طريقة)
  const cached = urlCache.get(url);
  if (cached && (Date.now() - cached.timestamp) < CACHE_DURATION) {
    return cached.result;
  }

  // التحقق من القوائم المحلية
  if (blockedUrls.has(url)) {
    return { blocked: true, cached: true };
  }
  if (safeUrls.has(url)) {
    return { blocked: false, cached: true };
  }

  // إذا كان هناك فحص قيد التنفيذ، انتظر نتيجته
  if (pendingChecks.has(url)) {
    return pendingChecks.get(url);
  }

  // إنشاء Promise للفحص
  const checkPromise = (async () => {
    try {
      // استخدام AbortController للـ timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), settings.timeout);

      const response = await fetch(`${settings.apiUrl}/intercept-url`, {
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
      
      // حفظ في الكاش
      urlCache.set(url, {
        result: result,
        timestamp: Date.now()
      });

      // إضافة للقوائم المحلية
      if (result.blocked) {
        blockedUrls.add(url);
      } else {
        safeUrls.add(url);
      }

      // إزالة من قائمة الانتظار
      pendingChecks.delete(url);

      return result;
    } catch (error) {
      // إزالة من قائمة الانتظار
      pendingChecks.delete(url);
      
      if (error.name === 'AbortError') {
        console.warn('URL check timeout:', url);
        // في حالة timeout، نفحص بشكل سريع من الكاش أو نسمح بالوصول
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

// اعتراض طلبات المتصفح - المرحلة الأولى (أسرع)
// هذا يعمل قبل SmartScreen لأنه يعترض في onBeforeRequest
// محسّن لـ Manifest V3 مع blocking صحيح
chrome.webRequest.onBeforeRequest.addListener(
  async function(details) {
    if (!settings.enabled) {
      return {};
    }

    const url = details.url;
    
    // تجاهل طلبات داخلية (Chrome, Edge, Firefox)
    if (url.startsWith('chrome://') || 
        url.startsWith('chrome-extension://') || 
        url.startsWith('moz-extension://') ||
        url.startsWith('edge://') ||
        url.startsWith('about:') ||
        url.startsWith('data:') ||
        url.startsWith('blob:')) {
      return {};
    }
    
    // Always allow localhost and local IPs - يجب أن يكون هذا أول شيء
    if (isLocalUrl(url)) {
      console.log('✅ Allowing local URL:', url);
      return {}; // Allow local URLs immediately
    }

    // التحقق السريع من الروابط المحظورة محلياً (أسرع طريقة - فوري)
    // لكن تأكد من أن localhost غير محظور
    if (blockedUrls.has(url) && !isLocalUrl(url)) {
      console.log('🚫 Blocked URL (cached):', url);
      
      // إرسال للـ Backend لتسجيل المحاولة (حتى لو كان محظوراً مسبقاً)
      fetch(`${API_BASE}/intercept-url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url, src_ip: 'browser-extension' })
      }).catch(() => {}); // لا ننتظر - نمنع فوراً
      
      // إرسال رسالة للتبويب
      chrome.tabs.sendMessage(details.tabId, {
        type: 'URL_BLOCKED',
        url: url,
        reason: 'Blocked URL - Previously detected'
      }).catch(() => {});
      
      // محاولة إعادة توجيه لصفحة الحظر
      try {
            // حفظ URL السابق قبل إعادة التوجيه
            chrome.tabs.get(details.tabId, (tab) => {
              if (tab && tab.url && !tab.url.startsWith('chrome-extension://') && !tab.url.startsWith('chrome://')) {
                // حفظ URL السابق في storage.local
                chrome.storage.local.set({ [`prevUrl_${details.tabId}`]: tab.url }, () => {
                  console.log('Saved previous URL:', tab.url, 'for tab:', details.tabId);
                });
              }
              chrome.tabs.update(details.tabId, {
                url: `chrome-extension://${chrome.runtime.id}/blocked.html?url=${encodeURIComponent(url)}&tabId=${details.tabId}`
              });
            });
      } catch (e) {}
      
      return { cancel: true };
    }

    // التحقق من الروابط الآمنة المعروفة
    if (safeUrls.has(url)) {
      return {};
    }

    // فحص URL من الكاش (فوري)
    const cached = urlCache.get(url);
    if (cached && (Date.now() - cached.timestamp) < CACHE_DURATION) {
      if (cached.result && cached.result.blocked && !isLocalUrl(url)) {
        if (!isLocalUrl(url)) {
          blockedUrls.add(url);
          chrome.tabs.sendMessage(details.tabId, {
            type: 'URL_BLOCKED',
            url: url,
            reason: cached.result.message || 'Suspicious URL detected'
          }).catch(() => {});
          
          // إضافة قاعدة declarativeNetRequest
          if (declarativeBlocker) {
            declarativeBlocker.addBlockingRule(url);
          }
          
          try {
            // حفظ URL السابق قبل إعادة التوجيه
            chrome.tabs.get(details.tabId, async (tab) => {
              if (tab && tab.url && !tab.url.startsWith('chrome-extension://')) {
                chrome.storage.local.set({ [`prevUrl_${details.tabId}`]: tab.url }, () => {
                  console.log('Saved previous URL:', tab.url, 'for tab:', details.tabId);
                });
              }
              await chrome.tabs.update(details.tabId, {
                url: `chrome-extension://${chrome.runtime.id}/blocked.html?url=${encodeURIComponent(url)}&tabId=${details.tabId}`
              });
            });
          } catch (e) {}
          
          return { cancel: true };
        }
      }
      return {};
    }

    // فحص فوري من Backend (مع timeout قصير)
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 500); // 500ms فقط
      
      const response = await fetch(`${API_BASE}/intercept-url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url, src_ip: 'browser-extension' }),
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      
      if (response.ok) {
        const result = await response.json();
        
        if (result && result.blocked) {
          // عدم إضافة localhost للقائمة المحظورة
          if (!isLocalUrl(url)) {
            // إضافة للقائمة المحظورة فوراً
            blockedUrls.add(url);
            
            // حفظ في الكاش
            urlCache.set(url, {
              result: result,
              timestamp: Date.now()
            });
            
            // إضافة قاعدة declarativeNetRequest
            if (declarativeBlocker) {
              declarativeBlocker.addBlockingRule(url);
            }
          } else {
            console.log('⚠️ Backend tried to block localhost, ignoring:', url);
            return {};
          }
          
          // إرسال رسالة للتبويب
          chrome.tabs.sendMessage(details.tabId, {
            type: 'URL_BLOCKED',
            url: url,
            reason: result.message || 'Suspicious URL detected by NGFW'
          }).catch(() => {});
          
          // إعادة توجيه لصفحة الحظر
          try {
            // حفظ URL السابق قبل إعادة التوجيه
            chrome.tabs.get(details.tabId, async (tab) => {
              if (tab && tab.url && !tab.url.startsWith('chrome-extension://')) {
                chrome.storage.local.set({ [`prevUrl_${details.tabId}`]: tab.url }, () => {
                  console.log('Saved previous URL:', tab.url, 'for tab:', details.tabId);
                });
              }
              await chrome.tabs.update(details.tabId, {
                url: `chrome-extension://${chrome.runtime.id}/blocked.html?url=${encodeURIComponent(url)}&tabId=${details.tabId}`
              });
            });
          } catch (e) {}
          
          // إرسال إشعار
          if (settings.showNotifications) {
            chrome.notifications.create({
              type: 'basic',
              iconUrl: 'icon48.png',
              title: '🚫 Blocked URL - NGFW',
              message: `Blocked: ${url.substring(0, 50)}...`,
              buttons: [{ title: 'View Details' }]
            });
          }
          
          console.log('🚫 Blocked URL (NGFW):', url);
          return { cancel: true };
        } else {
          // رابط آمن - حفظ في القائمة الآمنة
          safeUrls.add(url);
          urlCache.set(url, {
            result: result,
            timestamp: Date.now()
          });
        }
      }
    } catch (error) {
      if (error.name !== 'AbortError') {
        console.error('Error checking URL:', error);
      }
      // في حالة timeout أو خطأ، نسمح بالوصول (fail-open)
    }

    return {};
  },
  {
    urls: ["<all_urls>"]
  },
  ["blocking"]
);

// اعتراض التنقل - المرحلة الثانية (للتأكد)
// هذا يعمل في مرحلة مبكرة جداً قبل تحميل الصفحة
chrome.webNavigation.onBeforeNavigate.addListener(
  async function(details) {
    if (!settings.enabled || details.frameId !== 0) {
      return; // نتجاهل الإطارات الفرعية
    }

    const url = details.url;
    
    // تجاهل طلبات داخلية
    if (url.startsWith('chrome://') || 
        url.startsWith('chrome-extension://') || 
        url.startsWith('moz-extension://') ||
        url.startsWith('edge://') ||
        url.startsWith('about:')) {
      return;
    }

    // فحص سريع إضافي (للروابط التي قد فاتت في onBeforeRequest)
    // لكن تأكد من أن localhost غير محظور
    if (blockedUrls.has(url) && !isLocalUrl(url)) {
      // حفظ URL السابق قبل إعادة التوجيه
      chrome.tabs.get(details.tabId, (tab) => {
        if (tab && tab.url && !tab.url.startsWith('chrome-extension://')) {
          chrome.storage.session.set({ [`prevUrl_${details.tabId}`]: tab.url });
        }
        chrome.tabs.update(details.tabId, { 
          url: `chrome-extension://${chrome.runtime.id}/blocked.html?url=${encodeURIComponent(url)}&tabId=${details.tabId}`
        }).catch(() => {});
      });
      return;
    }

    // فحص غير متزامن (لا يمنع التنقل، لكن يحذّر)
    checkUrl(url).then(result => {
      if (result && result.blocked) {
        // إرسال رسالة للتبويب
        chrome.tabs.sendMessage(details.tabId, {
          type: 'URL_BLOCKED',
          url: url,
          reason: result.message || 'رابط مشبوه'
        }).catch(() => {});
      }
    });
  },
  {
    url: [{ schemes: ['http', 'https'] }]
  }
);

// استقبال الرسائل من popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'checkUrl') {
    checkUrl(request.url).then(result => {
      sendResponse(result);
    });
    return true; // إبقاء القناة مفتوحة للاستجابة غير المتزامنة
  } else if (request.action === 'getSettings') {
    sendResponse(settings);
  } else if (request.action === 'updateSettings') {
    settings = { ...settings, ...request.settings };
    saveSettings();
    sendResponse({ success: true });
  } else if (request.action === 'getBlockedCount') {
    sendResponse({ count: blockedUrls.size });
  } else if (request.action === 'reportFalsePositive') {
    // معالج للإبلاغ عن false positive
    const url = request.url;
    console.log('📝 False positive reported for URL:', url);
    
    // إزالة الرابط من القائمة المحظورة
    if (blockedUrls.has(url)) {
      blockedUrls.delete(url);
      console.log('✅ Removed URL from blocked list:', url);
    }
    
    // إزالة من safeUrls إذا كان موجوداً
    safeUrls.add(url);
    
    // إزالة من الكاش
    urlCache.delete(url);
    
    // إزالة قاعدة declarativeNetRequest إذا كانت موجودة
    if (declarativeBlocker) {
      try {
        chrome.declarativeNetRequest.getDynamicRules().then(rules => {
          const ruleToRemove = rules.find(r => r.condition.urlFilter === url);
          if (ruleToRemove) {
            chrome.declarativeNetRequest.updateDynamicRules({
              removeRuleIds: [ruleToRemove.id]
            });
            console.log('✅ Removed declarative rule for URL:', url);
          }
        });
      } catch (e) {
        console.error('Error removing declarative rule:', e);
      }
    }
    
    // إرسال إشعار
    if (settings.showNotifications) {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icon48.png',
        title: '✅ False Positive Reported',
        message: `URL removed from blocked list: ${url.substring(0, 50)}...`
      });
    }
    
    sendResponse({ success: true, message: 'False positive reported successfully' });
  }
});

// تنظيف الكاش القديم
setInterval(() => {
  const now = Date.now();
  for (const [url, data] of urlCache.entries()) {
    if (now - data.timestamp > CACHE_DURATION) {
      urlCache.delete(url);
    }
  }
}, 60000); // كل دقيقة

console.log('🛡️ NGFW URL Interceptor loaded');

