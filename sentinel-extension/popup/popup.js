// ============================================
// Sentinel-MCP Phishing Guard - Popup Logic
// ============================================

document.addEventListener('DOMContentLoaded', async () => {
  // Fetch stats from background worker
  chrome.runtime.sendMessage({ type: 'GET_STATS' }, (response) => {
    if (response) {
      document.getElementById('total').textContent = response.total || 0;
      document.getElementById('blocked').textContent = response.blocked || 0;
    }
  });

  // Check protection state
  const { protectionEnabled = true } = await chrome.storage.local.get(['protectionEnabled']);
  updateStatus(protectionEnabled);

  // Toggle protection
  document.getElementById('toggle').addEventListener('click', async () => {
    const currentState = document.getElementById('toggle').classList.contains('on');
    const newState = !currentState;

    await chrome.storage.local.set({ protectionEnabled: newState });
    updateStatus(newState);

    chrome.runtime.sendMessage({
      type: 'TOGGLE_PROTECTION',
      enabled: newState
    });
  });

  // Clear cache
  document.getElementById('clearCache').addEventListener('click', () => {
    if (!confirm('Clear all cached URL results?\n\nThis will force re-analysis of all URLs.')) {
      return;
    }

    chrome.runtime.sendMessage({ type: 'CLEAR_CACHE' }, (response) => {
      if (response?.success) {
        document.getElementById('total').textContent = '0';
        document.getElementById('blocked').textContent = '0';

        // Show brief success feedback
        const btn = document.getElementById('clearCache');
        const originalText = btn.textContent;
        btn.textContent = '✅ Cache Cleared';
        btn.style.color = '#4caf50';
        btn.style.borderColor = '#4caf50';

        setTimeout(() => {
          btn.textContent = originalText;
          btn.style.color = '';
          btn.style.borderColor = '';
        }, 1500);
      }
    });
  });
});

// ============ UPDATE UI STATUS ============
function updateStatus(enabled) {
  const status = document.getElementById('status');
  const statusText = document.getElementById('statusText');
  const toggle = document.getElementById('toggle');

  if (enabled) {
    status.className = 'status active';
    statusText.textContent = 'Protection Active';
    toggle.classList.add('on');
  } else {
    status.className = 'status off';
    statusText.textContent = 'Protection Disabled';
    toggle.classList.remove('on');
  }
}