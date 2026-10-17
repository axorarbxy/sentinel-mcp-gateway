// hooks/useLiveTraffic.ts
import { useEffect, useRef, useState, useCallback } from 'react';

export interface TrafficEvent {
  event_id: string;
  timestamp: string;
  agent_id: number | string;
  agent_name: string;
  method: string;
  tool_name: string | null;
  environment: string | null;
  latency_ms: number | null;
  decision: string;
  decision_reason: string;
  rule_risk_score: number | null;
  ml_score: number | null;
  decision_source: string;
  matched_rule_ids: string[];
  sqli_findings: Record<string, unknown>[];
  allowed: boolean;
  reason: string;
  ml_anomaly: boolean;
  total_requests?: number;
  total_blocked?: number;
  total_anomalies?: number;
}

const normalizeTrafficEvent = (value: unknown): TrafficEvent | null => {
  if (!value || typeof value !== 'object') return null;
  const raw = value as Record<string, unknown>;
  if (typeof raw.timestamp !== 'string' || typeof raw.method !== 'string') return null;

  const decision = typeof raw.decision === 'string'
    ? raw.decision
    : raw.allowed === false || raw.policy_allowed === false
      ? 'block'
      : 'allow';
  const reason = typeof raw.decision_reason === 'string'
    ? raw.decision_reason
    : typeof raw.reason === 'string'
      ? raw.reason
      : typeof raw.policy_reason === 'string'
        ? raw.policy_reason
        : '';
  const agentId = typeof raw.agent_id === 'number' || typeof raw.agent_id === 'string'
    ? raw.agent_id
    : 'unknown';
  const eventPayload = raw.payload && typeof raw.payload === 'object'
    ? raw.payload as Record<string, unknown>
    : {};

  return {
    event_id: typeof raw.event_id === 'string' ? raw.event_id : `${raw.timestamp}:${agentId}:${raw.method}`,
    timestamp: raw.timestamp,
    agent_id: agentId,
    agent_name: typeof raw.agent_name === 'string'
      ? raw.agent_name
      : typeof raw.agent_id === 'string'
        ? raw.agent_id
        : `Agent ${agentId}`,
    method: raw.method,
    tool_name: typeof raw.tool_name === 'string' ? raw.tool_name : null,
    environment: typeof raw.environment === 'string' ? raw.environment : null,
    latency_ms: typeof raw.latency_ms === 'number' ? raw.latency_ms : null,
    decision,
    decision_reason: reason,
    rule_risk_score: typeof raw.rule_risk_score === 'number' ? raw.rule_risk_score : null,
    ml_score: typeof raw.ml_score === 'number'
      ? raw.ml_score
      : typeof eventPayload.ml_score === 'number'
        ? eventPayload.ml_score
        : null,
    decision_source: typeof raw.decision_source === 'string' ? raw.decision_source : 'rule',
    matched_rule_ids: Array.isArray(raw.matched_rule_ids)
      ? raw.matched_rule_ids.filter((ruleId): ruleId is string => typeof ruleId === 'string')
      : [],
    sqli_findings: Array.isArray(raw.sqli_findings)
      ? raw.sqli_findings.filter((finding): finding is Record<string, unknown> => !!finding && typeof finding === 'object')
      : [],
    allowed: decision !== 'block',
    reason,
    ml_anomaly: raw.ml_anomaly === true || eventPayload.behavioral_anomaly === true,
  };
};

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
const API_URL = 'http://localhost:8001';

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
  const manualCloseRef = useRef(false);
  const connectInProgressRef = useRef(false);
  const seenEventIdsRef = useRef(new Set<string>());

  const addEvent = useCallback((event: TrafficEvent) => {
    if (seenEventIdsRef.current.has(event.event_id)) return;
    seenEventIdsRef.current.add(event.event_id);
    setEvents((prev) => [event, ...prev].slice(0, maxEvents));
    setLiveStats((prev) => ({
      total_requests: event.total_requests ?? prev.total_requests + (event.decision_source === 'cep' ? 0 : 1),
      total_blocked: event.total_blocked ?? prev.total_blocked + (event.decision === 'block' ? 1 : 0),
      total_anomalies: event.total_anomalies ?? prev.total_anomalies + (event.ml_anomaly || event.decision_source === 'cep' ? 1 : 0),
    }));
    onEventRef.current?.(event);
  }, [maxEvents]);

  // Keep onEvent ref updated (avoid reconnect on handler change)
  useEffect(() => {
    onEventRef.current = onEvent;
  }, [onEvent]);

  const connect = useCallback(async () => {
    if (!enabled) return;
    if (wsRef.current && wsRef.current.readyState !== WebSocket.CLOSED) return;
    if (connectInProgressRef.current) return;
    const operatorToken = localStorage.getItem('access_token');
    if (!operatorToken) return;

    try {
      connectInProgressRef.current = true;
      console.log('[Sentinel WS] Connecting to', url);
      const ticketResponse = await fetch(`${API_URL}/auth/ws-ticket`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${operatorToken}` },
      });
      if (!ticketResponse.ok) {
        throw new Error(`Unable to authorize live traffic feed (${ticketResponse.status})`);
      }
      const { ticket } = await ticketResponse.json();
      if (!isMountedRef.current) return;
      const ws = new WebSocket(url, ['cybereye.v1', `cybereye-ticket.${ticket}`]);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!isMountedRef.current) return;
        console.log('[Sentinel WS] ✅ Connected');
        setConnected(true);
        reconnectAttemptsRef.current = 0;

        // Send initial ping
        try {
          ws.send('ping');
          // Subscription filters stay on the authenticated gateway connection and
          // are never propagated to the Redis broker.
          ws.send(JSON.stringify({ type: 'subscribe', filters: { event_types: ['mcp_event', 'security_correlation'] } }));
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
          } else if (message.type === 'mcp_event' || message.type === 'new_request' || message.type === 'security_correlation') {
            const newEvent = normalizeTrafficEvent(message.data);
            if (!newEvent) {
              console.error('[Sentinel WS] Invalid traffic event payload:', message.data);
              return;
            }
            console.log('[Sentinel WS] 🔔 New event:', newEvent.method);
            addEvent(newEvent);
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

        // Skip auto-reconnect if this close was triggered manually
        // (e.g. via reconnect()), which schedules its own reconnect.
        if (manualCloseRef.current) {
          manualCloseRef.current = false;
          return;
        }

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
    } finally {
      connectInProgressRef.current = false;
    }
  }, [url, enabled, addEvent]);

  // Connect on mount
  useEffect(() => {
    isMountedRef.current = true;
    const token = localStorage.getItem('access_token');
    if (token) {
      fetch(`${API_URL}/mcp/events?limit=${maxEvents}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
        .then(async (response) => {
          if (!response.ok) {
            throw new Error(`Unable to load recent MCP events (${response.status})`);
          }
          const data = await response.json();
          const history = Array.isArray(data.events)
            ? data.events.map(normalizeTrafficEvent).filter((event: TrafficEvent | null): event is TrafficEvent => event !== null)
            : [];
          if (!isMountedRef.current) return;
          history.forEach((event: TrafficEvent) => seenEventIdsRef.current.add(event.event_id));
          setEvents((current) => {
            const existing = new Set(current.map((event) => event.event_id));
            return [...current, ...history.filter((event: TrafficEvent) => !existing.has(event.event_id))]
              .slice(0, maxEvents);
          });
        })
        .catch((error) => {
          console.error('[Sentinel WS] Unable to load recent MCP events:', error);
        });
    }
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
  }, [connect, maxEvents]);

  const clearEvents = useCallback(() => {
    setEvents([]);
  }, []);

  const reconnect = useCallback(() => {
    if (wsRef.current) {
      manualCloseRef.current = true;
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
