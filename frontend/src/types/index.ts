// types/index.ts
export interface LogEntry {
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
}

export interface StatsResponse {
  total_requests: number;
  blocked: number;
  block_rate: number;
  anomaly_alerts: number;
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
  timestamp: string;
  agent_id: string;
  type: 'rule_based' | 'ml_based';
  reason: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
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