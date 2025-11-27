// Content Script - يعرض رسالة عند حظر رابط
// محسّن للعمل قبل SmartScreen

// منع تحميل الصفحة فوراً عند استقبال رسالة الحظر
let isBlocked = false;
let blockedUrl = null;

// اعتراض الصفحة فوراً قبل تحميلها
if (document.readyState === 'loading') {
  // الصفحة لم تُحمّل بعد - اعتراض فوري
  document.addEventListener('DOMContentLoaded', () => {
    if (isBlocked) {
      preventPageLoad();
    }
  }, { once: true });
} else {
  // الصفحة محمّلة - تحقق فوراً
  if (isBlocked) {
    preventPageLoad();
  }
}

// استقبال الرسائل من background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'URL_BLOCKED') {
    isBlocked = true;
    blockedUrl = request.url;
    preventPageLoad();
    showBlockedPage(request);
    sendResponse({ received: true });
  }
  return true; // إبقاء القناة مفتوحة
});

// منع تحميل الصفحة
function preventPageLoad() {
  // إيقاف جميع الطلبات
  if (document.body) {
    document.body.innerHTML = '';
    document.body.style.display = 'none';
  }
  
  // منع تحميل الموارد
  const observer = new MutationObserver(() => {
    if (document.body && !isBlocked) {
      document.body.innerHTML = '';
    }
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });
  
  // منع التنقل
  window.stop();
  if (document.readyState !== 'complete') {
    document.addEventListener('readystatechange', () => {
      if (document.readyState === 'loading') {
        window.stop();
      }
    });
  }
}

// عرض صفحة الحظر
function showBlockedPage(request) {
  // منع تحميل الصفحة
  preventPageLoad();
  
  // إيقاف تحميل الصفحة
  if (document.body) {
    document.body.innerHTML = '';
    document.body.style.display = 'block';
  } else {
    // إذا لم يكن body موجوداً بعد، ننتظر
    const observer = new MutationObserver(() => {
      if (document.body) {
        observer.disconnect();
        document.body.innerHTML = '';
        document.body.style.display = 'block';
        showBlockedPage(request);
      }
    });
    observer.observe(document.documentElement, { childList: true });
    return;
  }

  // إنشاء overlay لإظهار رسالة الحظر
  const overlay = document.createElement('div');
  overlay.id = 'ngfw-blocked-overlay';
  overlay.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
    z-index: 999999;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    animation: fadeIn 0.3s ease-in;
  `;
  
  // إضافة animation
  const style = document.createElement('style');
  style.textContent = `
    @keyframes fadeIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }
    #ngfw-blocked-overlay button:hover {
      transform: scale(1.05);
      box-shadow: 0 4px 20px rgba(88, 166, 255, 0.4);
    }
  `;
  document.head.appendChild(style);
  
  overlay.innerHTML = `
    <div style="
      background: linear-gradient(135deg, #1e1e2e 0%, #2d2d44 100%);
      padding: 50px;
      border-radius: 20px;
      text-align: center;
      max-width: 600px;
      border: 3px solid rgba(239, 68, 68, 0.6);
      box-shadow: 0 12px 48px rgba(239, 68, 68, 0.4);
      animation: slideIn 0.4s ease-out;
    ">
      <div style="font-size: 80px; margin-bottom: 24px; animation: pulse 2s infinite;">🚫</div>
      <h1 style="color: #ef4444; margin-bottom: 16px; font-size: 28px; font-weight: 700;">
        Blocked URL - NGFW Security
      </h1>
      <p style="color: #e6edf3; margin-bottom: 24px; font-size: 18px; line-height: 1.6;">
        ${request.reason || 'This URL has been blocked as suspicious'}
      </p>
      <div style="
        background: rgba(239, 68, 68, 0.1);
        padding: 16px;
        border-radius: 12px;
        margin-bottom: 30px;
        border: 1px solid rgba(239, 68, 68, 0.3);
      ">
        <p style="color: #9aa6b2; font-size: 14px; word-break: break-all; margin: 0;">
          ${request.url}
        </p>
      </div>
      <div style="display: flex; gap: 12px; justify-content: center;">
        <button id="goBackBtn" style="
          padding: 14px 28px;
          background: linear-gradient(135deg, #58a6ff 0%, #7ee787 100%);
          border: none;
          border-radius: 10px;
          color: #fff;
          font-size: 16px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.3s ease;
        ">العودة للصفحة السابقة</button>
        <button id="reportBtn" style="
          padding: 14px 28px;
          background: rgba(239, 68, 68, 0.2);
          border: 2px solid rgba(239, 68, 68, 0.5);
          border-radius: 10px;
          color: #ef4444;
          font-size: 16px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.3s ease;
        ">الإبلاغ عن خطأ</button>
      </div>
      <p style="color: #6e7681; margin-top: 24px; font-size: 12px;">
        🛡️ Blocked by NGFW before Microsoft Defender SmartScreen
      </p>
    </div>
  `;
  
  // إضافة animation للـ container
  const containerStyle = document.createElement('style');
  containerStyle.textContent = `
    @keyframes slideIn {
      from { transform: translateY(-20px); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }
    @keyframes pulse {
      0%, 100% { transform: scale(1); }
      50% { transform: scale(1.1); }
    }
  `;
  document.head.appendChild(containerStyle);
  
  document.body.appendChild(overlay);
  
  // إغلاق عند الضغط على الزر
  overlay.querySelector('#goBackBtn').addEventListener('click', () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = 'about:blank';
    }
  });
  
  // زر الإبلاغ
  overlay.querySelector('#reportBtn').addEventListener('click', () => {
    chrome.runtime.sendMessage({
      action: 'reportFalsePositive',
      url: request.url
    });
    alert('Thank you! Report has been sent.');
  });
  
  // منع أي تفاعل مع الصفحة
  document.addEventListener('click', (e) => {
    if (!overlay.contains(e.target)) {
      e.preventDefault();
      e.stopPropagation();
    }
  }, true);
  
  // منع تحميل أي موارد إضافية
  document.addEventListener('DOMContentLoaded', () => {
    if (isBlocked) {
      const links = document.querySelectorAll('a, link');
      links.forEach(link => {
        link.addEventListener('click', (e) => {
          e.preventDefault();
          e.stopPropagation();
        }, true);
      });
    }
  });
}

// اعتراض الروابط في الصفحة
document.addEventListener('click', (e) => {
  if (isBlocked) {
    e.preventDefault();
    e.stopPropagation();
    return false;
  }
  
  const link = e.target.closest('a');
  if (link && link.href) {
    // إرسال الرابط للفحص
    chrome.runtime.sendMessage({
      action: 'checkUrl',
      url: link.href
    }, (response) => {
      if (response && response.blocked) {
        e.preventDefault();
        e.stopPropagation();
        showBlockedPage({
          type: 'URL_BLOCKED',
          url: link.href,
          reason: response.message || 'رابط مشبوه'
        });
      }
    });
  }
}, true);

