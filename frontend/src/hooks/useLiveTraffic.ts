// hooks/useLiveTraffic.ts
import { useEffect, useRef, useState, useCallback } from 'react';

export interface TrafficEvent {
  timestamp: string;
  agent_id: string;
  method: string;
  params: Record<string, any>;
  allowed: boolean;
  reason: string;
  ml_anomaly: boolean;
  total_requests: number;
  total_blocked: number;
  total_anomalies: number;
}

interface SnapshotData {
  total_requests: number;
  total_blocked: number;
  total_anomalies: number;
  recent_logs: any[];
}

interface UseLiveTrafficOptions {
  url?: string;
  enabled?: boolean;
  onEvent?: (event: TrafficEvent) => void;
  maxEvents?: number;
}

interface UseLiveTrafficReturn {
  connected: boolean;
  events: TrafficEvent[];
  liveStats: {
    total_requests: number;
    total_blocked: number;
    total_anomalies: number;
  };
  clearEvents: () => void;
  reconnect: () => void;
}

const WS_URL = 'ws://localhost:8001/mcp/ws/traffic';

export const useLiveTraffic = (
  options: UseLiveTrafficOptions = {}
): UseLiveTrafficReturn => {
  const {
    url = WS_URL,
    enabled = true,
    onEvent,
    maxEvents = 100,
  } = options;

  const [connected, setConnected] = useState(false);
  const [events, setEvents] = useState<TrafficEvent[]>([]);
  const [liveStats, setLiveStats] = useState({
    total_requests: 0,
    total_blocked: 0,
    total_anomalies: 0,
  });

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const isMountedRef = useRef(true);
  const onEventRef = useRef(onEvent);

  // Keep onEvent ref updated (avoid reconnect on handler change)
  useEffect(() => {
    onEventRef.current = onEvent;
  }, [onEvent]);

  const connect = useCallback(() => {
    if (!enabled) return;
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    try {
      console.log('[Sentinel WS] Connecting to', url);
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!isMountedRef.current) return;
        console.log('[Sentinel WS] ✅ Connected');
        setConnected(true);
        reconnectAttemptsRef.current = 0;

        // Send initial ping
        try {
          ws.send('ping');
        } catch {}
      };

      ws.onmessage = (event) => {
        if (!isMountedRef.current) return;

        try {
          const message = JSON.parse(event.data);

          if (message.type === 'snapshot') {
            console.log('[Sentinel WS] 📸 Snapshot received', message.data);
            setLiveStats({
              total_requests: message.data.total_requests || 0,
              total_blocked: message.data.total_blocked || 0,
              total_anomalies: message.data.total_anomalies || 0,
            });
          } else if (message.type === 'new_request') {
            const newEvent: TrafficEvent = message.data;
            console.log('[Sentinel WS] 🔔 New event:', newEvent.method);

            setEvents((prev) => {
              const updated = [newEvent, ...prev];
              return updated.slice(0, maxEvents);
            });

            setLiveStats({
              total_requests: newEvent.total_requests,
              total_blocked: newEvent.total_blocked,
              total_anomalies: newEvent.total_anomalies,
            });

            if (onEventRef.current) {
              onEventRef.current(newEvent);
            }
          } else if (message.type === 'pong') {
            // Heartbeat acknowledged
          } else if (message.type === 'heartbeat') {
            // Server heartbeat, respond with ping
            try {
              ws.send('ping');
            } catch {}
          }
        } catch (err) {
          console.error('[Sentinel WS] Parse error:', err);
        }
      };

      ws.onerror = (error) => {
        console.error('[Sentinel WS] ❌ Error:', error);
      };

      ws.onclose = () => {
        if (!isMountedRef.current) return;
        console.log('[Sentinel WS] Disconnected');
        setConnected(false);

        // Auto-reconnect with exponential backoff
        if (enabled && reconnectAttemptsRef.current < 10) {
          const delay = Math.min(1000 * Math.pow(2, reconnectAttemptsRef.current), 30000);
          reconnectAttemptsRef.current += 1;
          console.log(`[Sentinel WS] Reconnecting in ${delay}ms (attempt ${reconnectAttemptsRef.current})`);

          reconnectTimeoutRef.current = setTimeout(() => {
            if (isMountedRef.current) connect();
          }, delay);
        }
      };
    } catch (error) {
      console.error('[Sentinel WS] Connection failed:', error);
    }
  }, [url, enabled, maxEvents]);

  // Connect on mount
  useEffect(() => {
    isMountedRef.current = true;
    connect();

    return () => {
      isMountedRef.current = false;

      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }

      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [connect]);

  const clearEvents = useCallback(() => {
    setEvents([]);
  }, []);

  const reconnect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close();
    }
    reconnectAttemptsRef.current = 0;
    setTimeout(() => connect(), 100);
  }, [connect]);

  return {
    connected,
    events,
    liveStats,
    clearEvents,
    reconnect,
  };
};

export default useLiveTraffic;