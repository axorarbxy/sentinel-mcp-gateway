// types/index.ts
export interface LogEntry {
  event_id?: string;
  timestamp: string;
  agent_id: string;
  method: string;
  params: Record<string, any>;
  id?: number;
  policy_allowed: boolean;
  policy_reason: string;
  analysis_anomaly: boolean;
  analysis_reason: string;
  ml_anomaly: boolean;
  event_category?: 'security' | 'system';
}

export interface StatsResponse {
  total_requests: number;
  blocked: number;
  block_rate: number;
  anomaly_alerts: number;
  system_events?: number;
  ml_models: number;
  methods: Record<string, number>;
  monitor_stats: {
    total_requests: number;
    anomalies_detected: number;
    agents_monitored: number;
    total_alerts: number;
  };
}

export interface HealthResponse {
  status: string;
  requests_processed: number;
  blocked: number;
  anomalies: number;
  ml_models: number;
  policies: string;
}

export interface Alert {
  id: string;
  event_ids: string[];
  timestamp: string;
  agent_id: string;
  type: 'rule_based' | 'ml_based';
  title: string;
  category: string;
  reason: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
  score?: number | null;
  first_seen: string;
  last_seen: string;
  occurrence_count: number;
  status: 'NEW' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE';
  decision: string;
  rule_id: string;
  risk: { score: number; rule_score: number; anomaly_score?: number | null };
  evidence: { rule: string; method: string; explanation: string; latest_request: Record<string, any> };
  request: {
    timestamp: string;
    method: string;
    params: Record<string, any>;
    agent_id: string;
  };
}

export interface AgentStats {
  agent_id: string;
  request_count: number;
  method_distribution: Record<string, number>;
  is_monitored: boolean;
  anomaly_count: number;
  last_request: string | null;
}
