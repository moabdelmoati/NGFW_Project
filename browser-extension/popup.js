// Popup Script
let settings = {
  enabled: true,
  apiUrl: 'http://127.0.0.1:5000/api',
  showNotifications: true
};

// تحميل الإعدادات
chrome.storage.sync.get(['ngfwSettings'], (result) => {
  if (result.ngfwSettings) {
    settings = { ...settings, ...result.ngfwSettings };
    updateUI();
  }
});

// تحديث واجهة المستخدم
function updateUI() {
  const toggle = document.getElementById('toggleSwitch');
  const statusText = document.getElementById('statusText');
  
  if (settings.enabled) {
    toggle.classList.add('active');
    statusText.textContent = 'نشط';
  } else {
    toggle.classList.remove('active');
    statusText.textContent = 'معطل';
  }
}

// تبديل الحالة
document.getElementById('toggleSwitch').addEventListener('click', () => {
  settings.enabled = !settings.enabled;
  chrome.storage.sync.set({ ngfwSettings: settings });
  chrome.runtime.sendMessage({
    action: 'updateSettings',
    settings: settings
  });
  updateUI();
});

// فحص URL
document.getElementById('checkBtn').addEventListener('click', async () => {
  const urlInput = document.getElementById('urlInput');
  const url = urlInput.value.trim();
  const resultDiv = document.getElementById('result');
  const checkBtn = document.getElementById('checkBtn');
  
  if (!url) {
    resultDiv.textContent = '⚠️ الرجاء إدخال رابط';
    resultDiv.className = 'result show blocked';
    return;
  }
  
  checkBtn.disabled = true;
  checkBtn.textContent = 'جاري الفحص...';
  resultDiv.className = 'result';
  resultDiv.textContent = '';
  
  try {
    const response = await chrome.runtime.sendMessage({
      action: 'checkUrl',
      url: url
    });
    
    resultDiv.className = 'result show';
    if (response.blocked) {
      resultDiv.className += ' blocked';
      resultDiv.innerHTML = `
        <strong>🚫 رابط محظور!</strong><br>
        ${response.message || 'رابط مشبوه'}<br>
        ${response.threat_indicators && response.threat_indicators.length > 0 ? 
          '<br>مؤشرات التهديد:<br>' + response.threat_indicators.map(t => `• ${t}`).join('<br>') : ''}
      `;
    } else {
      resultDiv.className += ' safe';
      resultDiv.innerHTML = `
        <strong>✅ رابط آمن</strong><br>
        ${response.message || 'يمكنك فتح هذا الرابط بأمان'}
      `;
    }
  } catch (error) {
    resultDiv.className = 'result show blocked';
    resultDiv.textContent = `⚠️ خطأ: ${error.message}`;
  } finally {
    checkBtn.disabled = false;
    checkBtn.textContent = 'فحص الرابط';
  }
});

// Enter key support
document.getElementById('urlInput').addEventListener('keypress', (e) => {
  if (e.key === 'Enter') {
    document.getElementById('checkBtn').click();
  }
});

// تحديث عدد الروابط المحظورة
async function updateBlockedCount() {
  try {
    const response = await chrome.runtime.sendMessage({
      action: 'getBlockedCount'
    });
    document.getElementById('blockedCount').textContent = response.count || 0;
  } catch (error) {
    console.error('Error getting blocked count:', error);
  }
}

// تحديث العدد كل 5 ثوان
updateBlockedCount();
setInterval(updateBlockedCount, 5000);


