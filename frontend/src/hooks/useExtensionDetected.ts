// hooks/useExtensionDetected.ts
import { useEffect, useState } from 'react';

export const useExtensionDetected = () => {
  const [isInstalled, setIsInstalled] = useState<boolean | null>(null);

  useEffect(() => {
    let resolved = false;

    // ============================================
    // Method 1: Check for DOM marker (fastest)
    // ============================================
    const checkMarker = (): boolean => {
      const marker = document.getElementById('sentinel-mcp-extension-marker');
      if (marker) {
        setIsInstalled(true);
        resolved = true;
        console.log('[Sentinel] Extension detected via DOM marker');
        return true;
      }
      return false;
    };

    // ============================================
    // Method 2: Post-message ping (fallback)
    // ============================================
    const handler = (event: MessageEvent) => {
      if (event.source !== window) return;
      if (event.data?.type === 'SENTINEL_PONG') {
        setIsInstalled(true);
        resolved = true;
        console.log('[Sentinel] Extension detected via ping');
      }
    };

    window.addEventListener('message', handler);

    // Try immediate check
    if (!checkMarker()) {
      // Send ping
      window.postMessage({ type: 'SENTINEL_PING' }, '*');

      // Retry marker check a few times (for slow content script injection)
      const retryTimers: NodeJS.Timeout[] = [];
      [100, 300, 500, 1000, 2000].forEach((delay) => {
        retryTimers.push(
          setTimeout(() => {
            if (!resolved) checkMarker();
          }, delay)
        );
      });

      // Final timeout — if no response, assume not installed
      const finalTimer = setTimeout(() => {
        if (!resolved) {
          setIsInstalled(false);
          console.log('[Sentinel] Extension NOT detected');
        }
      }, 2500);

      return () => {
        window.removeEventListener('message', handler);
        retryTimers.forEach(clearTimeout);
        clearTimeout(finalTimer);
      };
    }

    return () => window.removeEventListener('message', handler);
  }, []);

  return isInstalled;
};