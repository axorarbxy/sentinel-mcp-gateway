// services/api.ts
import axios from 'axios';
import { StatsResponse, HealthResponse, LogEntry, Alert, AgentStats } from '../types';

const API_BASE_URL = 'http://localhost:8001';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add interceptor to include auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Clears stored auth tokens and notifies the app to update its
// authenticated state (App.tsx listens for this event).
export const logout = () => {
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  window.dispatchEvent(new Event('auth:logout'));
};

// If the backend ever rejects our token (expired/revoked), log out
// automatically instead of leaving the UI stuck in a broken state.
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      logout();
    }
    return Promise.reject(error);
  }
);

export const gatewayApi = {
  getHealth: async (): Promise<HealthResponse> => {
    const response = await api.get('/health');
    return response.data;
  },

  getStats: async (): Promise<StatsResponse> => {
    const response = await api.get('/stats');
    return response.data;
  },

  getLogs: async (limit: number = 50): Promise<{ total: number; blocked: number; anomalies: number; logs: LogEntry[] }> => {
    const response = await api.get(`/logs?limit=${limit}`);
    return response.data;
  },

  getBlockedLogs: async (limit: number = 50): Promise<{ total: number; logs: LogEntry[] }> => {
    const response = await api.get(`/logs/blocked?limit=${limit}`);
    return response.data;
  },

  getAnomalies: async (limit: number = 50): Promise<{ total: number; alerts: Alert[] }> => {
    const response = await api.get(`/logs/anomalies?limit=${limit}`);
    return response.data;
  },

  updateAlertStatus: async (alertId: string, status: Alert['status']): Promise<Alert> => {
    const response = await api.patch(`/logs/anomalies/${alertId}/status?status=${encodeURIComponent(status)}`);
    return response.data;
  },

  getAgentStats: async (agentId: string): Promise<AgentStats> => {
    const response = await api.get(`/agent/${agentId}`);
    return response.data;
  },

  getAgentsSummary: async (): Promise<{ total_agents: number; agents: AgentSecuritySummary[] }> => {
    const response = await api.get('/agents/summary');
    return response.data;
  },
};

export interface AgentSecuritySummary {
  agent_id: string;
  requests: number;
  blocked: number;
  anomalies: number;
  tools: Record<string, number>;
  last_seen: string | null;
  risk_score: number;
  trust_level: 'TRUSTED' | 'MONITORED' | 'RESTRICTED' | 'QUARANTINED';
  behavior_status: 'NORMAL' | 'ANOMALOUS';
  recent_events: LogEntry[];
}

export default api;
