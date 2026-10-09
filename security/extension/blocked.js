// ============================================
// Sentinel-MCP Phishing Guard - Blocked Page Logic
// ============================================

// Parse URL parameters
const params = new URLSearchParams(window.location.search);
const blockedUrl = params.get('url') || 'Unknown URL';
const reasonParam = params.get('reason') || 'Suspicious URL pattern detected';
let riskParam = parseFloat(params.get('risk') || '0');

if (!riskParam || riskParam === 0 || isNaN(riskParam)) {
  riskParam = 0.9;
}

// ============================================
// Populate page
// ============================================

// Blocked URL
document.getElementById('blockedUrl').textContent = blockedUrl;

// Risk score
const riskPercent = Math.min(100, Math.max(0, Math.round(riskParam * 100)));
document.getElementById('riskScore').textContent = riskPercent + '%';

// Animate the risk bar
setTimeout(() => {
  document.getElementById('riskFill').style.width = riskPercent + '%';
}, 150);

// ============================================
// Reasons list
// ============================================
const reasons = reasonParam
  .split(';')
  .map(r => r.trim())
  .filter(r => r.length > 0);

const reasonList = document.getElementById('reasonList');
reasonList.innerHTML = '';

if (reasons.length === 0) {
  const li = document.createElement('li');
  li.textContent = 'Suspicious URL pattern detected';
  reasonList.appendChild(li);
} else {
  reasons.forEach(r => {
    const li = document.createElement('li');
    li.textContent = r;
    reasonList.appendChild(li);
  });
}

// ============================================
// Go back to safety
// ============================================
function goBack() {
  window.location.href = 'about:newtab';
}

// ============================================
// Proceed anyway — sends message to service worker
// ============================================
function proceedAnyway() {
  const confirmed = window.confirm(
    '⚠️ WARNING: This site was flagged as dangerous by Sentinel-MCP.\n\n' +
    'Proceeding can result in:\n' +
    '• Credential theft\n' +
    '• Malware infection\n' +
    '• Financial loss\n\n' +
    'Are you absolutely sure you want to proceed?'
  );

  if (!confirmed) return;

  const finalConfirm = window.confirm(
    'This is your LAST warning.\n\n' +
    'Only proceed if you 100% trust this URL.\n\n' +
    'Click OK to proceed at your own risk.'
  );

  if (!finalConfirm) return;

  // Send message to background service worker to unblock
  chrome.runtime.sendMessage(
    {
      type: 'UNBLOCK_URL',
      url: blockedUrl,
    },
    (response) => {
      if (response?.success) {
        window.location.href = blockedUrl;
      } else {
        alert('Failed to unblock. Try disabling the extension manually.');
      }
    }
  );
}

// Attach event listeners
document.addEventListener('DOMContentLoaded', () => {
  const backBtn = document.getElementById('backBtn');
  const proceedBtn = document.getElementById('proceedBtn');

  if (backBtn) backBtn.addEventListener('click', goBack);
  if (proceedBtn) proceedBtn.addEventListener('click', proceedAnyway);
});