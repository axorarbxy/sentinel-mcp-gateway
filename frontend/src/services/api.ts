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

  getAgentStats: async (agentId: string): Promise<AgentStats> => {
    const response = await api.get(`/agent/${agentId}`);
    return response.data;
  },
};

export default api;