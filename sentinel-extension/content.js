// ============================================
// Sentinel-MCP Phishing Guard - Content Script
// Injected into every page to communicate with our website
// ============================================

console.log('[Sentinel] Content script loaded on:', window.location.href);

// ============================================
// Method 1: Respond to ping from Sentinel-MCP website
// ============================================
window.addEventListener('message', (event) => {
  // Only respond to messages from our own window
  if (event.source !== window) return;

  if (event.data?.type === 'SENTINEL_PING') {
    window.postMessage({
      type: 'SENTINEL_PONG',
      version: chrome.runtime.getManifest().version,
      installedAt: new Date().toISOString(),
    }, '*');
    console.log('[Sentinel] Responded to website ping');
  }
});

// ============================================
// Method 2: Inject a hidden marker element
// Website can detect extension via document.getElementById()
// ============================================
function injectMarker() {
  // Don't inject twice
  if (document.getElementById('sentinel-mcp-extension-marker')) {
    return;
  }

  const marker = document.createElement('div');
  marker.id = 'sentinel-mcp-extension-marker';
  marker.style.display = 'none';
  marker.setAttribute('data-version', chrome.runtime.getManifest().version);
  marker.setAttribute('data-installed', 'true');

  // Append to body or documentElement
  (document.body || document.documentElement).appendChild(marker);
  console.log('[Sentinel] Marker injected');
}

// Inject marker when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', injectMarker);
} else {
  injectMarker();
}

// Also re-inject if page dynamically changes (SPA)
const observer = new MutationObserver(() => {
  if (!document.getElementById('sentinel-mcp-extension-marker')) {
    injectMarker();
  }
});

observer.observe(document.documentElement, {
  childList: true,
  subtree: true,
});

console.log('[Sentinel] Content script ready');