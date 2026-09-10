// ============================================
// Sentinel-MCP Phishing Guard - Background Worker
// ============================================

const API_URL = 'http://localhost:8001/ml/analyze/url';
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const RISK_THRESHOLD = 0.5;
const BLOCK_RULE_ID_START = 10000;

let urlCache = {};
const blockedTabs = new Set(); // Prevent double-blocking per tab

// Load cache on startup
chrome.storage.local.get(['urlCache', 'protectionEnabled']).then(result => {
  if (result.urlCache) {
    urlCache = result.urlCache;
    console.log(`[Sentinel] Loaded ${Object.keys(urlCache).length} cached URLs`);
  }
  console.log(`[Sentinel] Protection enabled: ${result.protectionEnabled !== false}`);
});

function persistCache() {
  chrome.storage.local.set({ urlCache });
}

// ============ QUICK LOCAL CHECK ============
function quickLocalCheck(url) {
  try {
    const parsed = new URL(url);
    const domain = parsed.hostname.toLowerCase();
    const urlLower = url.toLowerCase();

    const badTlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.club', '.site'];
    for (const tld of badTlds) {
      if (domain.endsWith(tld)) {
        return {
          is_suspicious: true,
          risk_score: 0.95,
          risk_factors: [`Suspicious TLD: ${tld}`],
          source: 'local',
        };
      }
    }

    const typos = ['paypa1', 'amaz0n', 'go0gle', 'faceb00k', 'app1e', 'micr0soft', 'netfl1x'];
    for (const typo of typos) {
      if (urlLower.includes(typo)) {
        return {
          is_suspicious: true,
          risk_score: 0.99,
          risk_factors: [`Typosquatting detected: ${typo}`],
          source: 'local',
        };
      }
    }

    if (/^\d+\.\d+\.\d+\.\d+$/.test(domain)) {
      return {
        is_suspicious: true,
        risk_score: 0.85,
        risk_factors: ['IP address used instead of domain'],
        source: 'local',
      };
    }

    if (url.includes('@') && parsed.username) {
      return {
        is_suspicious: true,
        risk_score: 0.9,
        risk_factors: ['@ symbol used to obfuscate destination'],
        source: 'local',
      };
    }

    return null;
  } catch {
    return null;
  }
}

// ============ CORE: ANALYZE URL ============
async function analyzeUrl(url) {
  const cached = urlCache[url];
  if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
    console.log(`[Sentinel] Cache hit: ${url} → ${cached.is_suspicious ? 'BLOCK' : 'ALLOW'}`);
    return cached;
  }

  const localResult = quickLocalCheck(url);
  if (localResult) {
    localResult.timestamp = Date.now();
    urlCache[url] = localResult;
    persistCache();
    console.log(`[Sentinel] Local check BLOCK: ${url}`);
    return localResult;
  }

  try {
    const response = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
      console.error('[Sentinel] API error:', response.status);
      return { is_suspicious: false, risk_score: 0, error: true };
    }

    const data = await response.json();
    const result = {
      is_suspicious: data.is_suspicious,
      risk_score: data.risk_score,
      risk_factors: data.risk_factors || [],
      source: 'ml',
      timestamp: Date.now(),
    };

    urlCache[url] = result;
    persistCache();

    console.log(`[Sentinel] ML check: ${url} → Risk ${(result.risk_score * 100).toFixed(1)}%`);
    return result;

  } catch (error) {
    console.error('[Sentinel] Network error:', error);
    return { is_suspicious: false, risk_score: 0, error: true };
  }
}

// ============ BLOCK URL (Loop-Safe) ============
async function blockUrl(url, reason, riskScore, tabId) {
  try {
    const domain = new URL(url).hostname;

    // Mark tab as blocked to prevent re-processing
    blockedTabs.add(tabId);

    // Add dynamic rule (idempotent — same domain uses same rule ID)
    const ruleId = BLOCK_RULE_ID_START + hashString(domain) % 1000;

    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: [ruleId],
      addRules: [{
        id: ruleId,
        priority: 1,
        action: {
          type: 'redirect',
          redirect: {
            url: chrome.runtime.getURL('blocked.html') +
                 `?url=${encodeURIComponent(url)}` +
                 `&reason=${encodeURIComponent(reason)}` +
                 `&risk=${riskScore}`
          }
        },
        condition: {
          urlFilter: `||${domain}`,
          resourceTypes: ['main_frame']
        }
      }]
    });

    console.log(`[Sentinel] 🚫 BLOCKED: ${domain}`);

    // Only reload ONCE per tab
    if (tabId && !blockedTabs.has(tabId + '_reloaded')) {
      blockedTabs.add(tabId + '_reloaded');
      chrome.tabs.update(tabId, { url: url });
    }

    // Notification (once)
    const notifId = `block_${domain}_${Date.now()}`;
    chrome.notifications.create(notifId, {
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: '🚫 Phishing Blocked!',
      message: `Sentinel-MCP blocked ${domain}\n\n${reason}`,
      priority: 2,
    });

    // Auto-clear the notification after 5 seconds
    setTimeout(() => {
      chrome.notifications.clear(notifId);
    }, 5000);

  } catch (error) {
    console.error('[Sentinel] Block error:', error);
  }
}

// Simple string hash to generate stable rule IDs
function hashString(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash);
}

// ============ CLEANUP BLOCKED TABS ============
chrome.tabs.onRemoved.addListener((tabId) => {
  blockedTabs.delete(tabId);
  blockedTabs.delete(tabId + '_reloaded');
});

// ============ NAVIGATION INTERCEPT ============
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;

  const url = details.url;
  const tabId = details.tabId;

  // Skip internal URLs
  if (url.startsWith('chrome://') ||
      url.startsWith('chrome-extension://') ||
      url.startsWith('about:') ||
      url.startsWith('edge://') ||
      url.startsWith('http://localhost') ||
      url.startsWith('http://127.0.0.1')) {
    return;
  }

  // Skip if we already blocked this tab
  if (blockedTabs.has(tabId)) {
    console.log(`[Sentinel] Tab ${tabId} already processed, skipping`);
    return;
  }

  const { protectionEnabled = true } = await chrome.storage.local.get(['protectionEnabled']);
  if (!protectionEnabled) return;

  console.log(`[Sentinel] Checking: ${url}`);

  const result = await analyzeUrl(url);

  if (result.is_suspicious && result.risk_score > RISK_THRESHOLD) {
    const reason = (result.risk_factors || []).join('; ') || 'Suspicious URL pattern detected';
    await blockUrl(url, reason, result.risk_score, tabId);
  }
});

// ============ MESSAGING ============
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'ANALYZE_URL') {
    analyzeUrl(message.url).then(result => sendResponse(result));
    return true;
  }

  if (message.type === 'GET_STATS') {
    const total = Object.keys(urlCache).length;
    const blocked = Object.values(urlCache).filter(r => r.is_suspicious).length;
    sendResponse({ total, blocked });
    return true;
  }

  if (message.type === 'CLEAR_CACHE') {
    urlCache = {};
    persistCache();
    sendResponse({ success: true });
    return true;
  }

  if (message.type === 'TOGGLE_PROTECTION') {
    chrome.storage.local.set({ protectionEnabled: message.enabled });
    sendResponse({ success: true });
    return true;
  }
});

// Clear old cache entries every hour
setInterval(() => {
  const now = Date.now();
  let removed = 0;
  for (const [url, entry] of Object.entries(urlCache)) {
    if (now - entry.timestamp > CACHE_TTL_MS) {
      delete urlCache[url];
      removed++;
    }
  }
  if (removed > 0) {
    console.log(`[Sentinel] Cleaned ${removed} old cache entries`);
    persistCache();
  }
}, 60 * 60 * 1000);

console.log('[Sentinel] Background service worker started');