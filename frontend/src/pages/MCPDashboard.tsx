// pages/MCPDashboard.tsx
import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
  Tabs,
  Tab,
  Chip,
  Button,
  IconButton,
  Tooltip,
  Avatar,
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Alert,
  Snackbar,
  CircularProgress,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
} from '@mui/material';
import {
  Person as PersonIcon,
  Security as SecurityIcon,
  Refresh as RefreshIcon,
  Add as AddIcon,
  Delete as DeleteIcon,
  PlayArrow as PlayArrowIcon,
  Pause as PauseIcon,
  Speed as SpeedIcon,
  VpnKey as KeyIcon,
  Cloud as CloudIcon,
  FiberManualRecord as LiveIcon,
  WifiOff as WifiOffIcon,
} from '@mui/icons-material';
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip as ChartTooltip, XAxis, YAxis } from 'recharts';
import useLiveTraffic from '../hooks/useLiveTraffic';

import { API_BASE_URL as API_URL } from '../services/urls';

const getAuthHeaders = (extra: Record<string, string> = {}) => {
  const token = localStorage.getItem('access_token');
  return {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...extra,
  };
};

const fetchWithAuth = async (url: string, options: RequestInit = {}) => {
  return fetch(url, {
    ...options,
    headers: {
      ...getAuthHeaders(),
      ...(options.headers || {}),
    },
  });
};

const getApiErrorMessage = (detail: unknown, fallback: string): string => {
  if (typeof detail === 'string' && detail.trim()) return detail;
  if (Array.isArray(detail)) {
    const messages = detail.map((item: any) => {
      if (typeof item === 'string') return item;
      if (item && typeof item === 'object' && typeof item.msg === 'string') {
        const location = Array.isArray(item.loc) ? item.loc.filter(Boolean).join('.') : '';
        return location ? `${location}: ${item.msg}` : item.msg;
      }
      return '';
    }).filter(Boolean);
    if (messages.length) return messages.join('; ');
  }
  return fallback;
};

// ============ TYPES ============
interface MCPOverview {
  agents: { total: number; active: number; inactive: number };
  servers: { total: number; online: number; offline: number };
  policies: { total: number; enabled: number; disabled: number };
  traffic: { total_requests: number; blocked_requests: number; allowed_requests: number };
}

interface MCPAgent {
  id: number;
  name: string;
  description: string | null;
  credential_prefix: string;
  status: 'active' | 'suspended' | 'revoked';
  policies: number[];
  is_active: boolean;
  total_requests: number;
  blocked_requests: number;
  created_at: string;
  last_seen: string | null;
}

interface MCPPolicy {
  id: number;
  name: string;
  description: string | null;
  rule_type: string;
  config: Record<string, any>;
  severity: string;
  is_enabled: boolean;
  created_at: string;
}

interface MCPServer {
  id: number;
  name: string;
  description: string | null;
  url: string;
  server_type: string;
  is_active: boolean;
  health_status: string;
  last_health_check: string | null;
  created_at: string;
}

// ============ MAIN COMPONENT ============
const MCPDashboard: React.FC = () => {
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);
  const [overview, setOverview] = useState<MCPOverview | null>(null);
  const [agents, setAgents] = useState<MCPAgent[]>([]);
  const [policies, setPolicies] = useState<MCPPolicy[]>([]);
  const [servers, setServers] = useState<MCPServer[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Live traffic via WebSocket
  const {
    connected: wsConnected,
    events: liveEvents,
    liveStats,
    clearEvents,
  } = useLiveTraffic({ enabled: true, maxEvents: 50 });

  // Dialog states
  const [addAgentOpen, setAddAgentOpen] = useState(false);
  const [addPolicyOpen, setAddPolicyOpen] = useState(false);
  const [addServerOpen, setAddServerOpen] = useState(false);

  // Form states
  const [newAgent, setNewAgent] = useState({
    name: '',
    description: '',
    owner: '',
    team: '',
    environment: 'dev',
    risk_level: 'low',
    allowed_tools: '',
    upstream_url: '',
    upstream_name: '',
    upstream_token_env: '',
  });
  const [newPolicy, setNewPolicy] = useState({
    name: '',
    description: '',
    rule_type: 'path_traversal',
    severity: 'medium',
  });
  const [newServer, setNewServer] = useState({
    name: '',
    description: '',
    url: '',
    server_type: 'filesystem',
  });

  // Snackbar
  const [snackbar, setSnackbar] = useState({
    open: false,
    message: '',
    severity: 'info' as 'success' | 'error' | 'info' | 'warning',
  });
  const [createdCredential, setCreatedCredential] = useState<string | null>(null);

  const showSnackbar = useCallback((message: string, severity: 'success' | 'error' | 'info' | 'warning') => {
    setSnackbar({ open: true, message, severity });
  }, []);

  // ============ FETCH DATA ============
  const fetchAll = useCallback(async (showLoader = false) => {
    if (showLoader) setRefreshing(true);
    try {
      const [overviewRes, agentsRes, policiesRes, serversRes] = await Promise.all([
        fetchWithAuth(`${API_URL}/mcp/overview`),
        fetchWithAuth(`${API_URL}/mcp/agents`),
        fetchWithAuth(`${API_URL}/mcp/policies`),
        fetchWithAuth(`${API_URL}/mcp/servers`),
      ]);

      if (overviewRes.ok) setOverview(await overviewRes.json());
      if (agentsRes.ok) setAgents(await agentsRes.json());
      if (policiesRes.ok) setPolicies(await policiesRes.json());
      if (serversRes.ok) setServers(await serversRes.json());
    } catch (error) {
      console.error('Fetch error:', error);
      showSnackbar('Failed to fetch MCP data', 'error');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [showSnackbar]);

  useEffect(() => {
    fetchAll();
    // Slower fallback polling (WebSocket handles real-time)
    const interval = setInterval(() => fetchAll(), 30000);
    return () => clearInterval(interval);
  }, [fetchAll]);

  // Auto-refresh agents table when live events arrive
  const latestLiveEventId = liveEvents[0]?.event_id;
  useEffect(() => {
    if (latestLiveEventId) {
      fetchWithAuth(`${API_URL}/mcp/agents`)
        .then((res) => res.ok && res.json())
        .then((data) => data && setAgents(data))
        .catch((error) => console.error('Failed to refresh agents after live traffic:', error));
    }
  }, [latestLiveEventId]);

  // ============ CREATE AGENT ============
  const handleCreateAgent = async () => {
    if (!newAgent.name.trim()) {
      showSnackbar('Agent name is required', 'warning');
      return;
    }
    try {
      const res = await fetchWithAuth(`${API_URL}/mcp/agents`, {
        method: 'POST',
        body: JSON.stringify({
          ...newAgent,
          allowed_tools: newAgent.allowed_tools
            ? newAgent.allowed_tools.split(',').map((item) => item.trim()).filter(Boolean)
            : [],
        }),
      });
      const payload = await res.json().catch(() => ({}));
      if (res.ok) {
        const nextCredential = payload.credential || null;
        setCreatedCredential(nextCredential);
        showSnackbar('Agent created successfully. Copy the key now.', 'success');
        setAddAgentOpen(false);
        setNewAgent({ name: '', description: '', owner: '', team: '', environment: 'dev', risk_level: 'low', allowed_tools: '', upstream_url: '', upstream_name: '', upstream_token_env: '' });
        fetchAll();
      } else {
        showSnackbar(getApiErrorMessage(payload.detail, 'Failed to create agent'), 'error');
      }
    } catch (error) {
      console.error('Failed to create MCP agent:', error);
      showSnackbar(
        'Could not reach the Sentinel API. Check that the backend is running on port 8001 and that this frontend origin is allowed by SENTINEL_CORS_ORIGINS.',
        'error',
      );
    }
  };

  // ============ CREATE POLICY ============
  const handleCreatePolicy = async () => {
    if (!newPolicy.name.trim()) {
      showSnackbar('Policy name is required', 'warning');
      return;
    }
    try {
      const res = await fetchWithAuth(`${API_URL}/mcp/policies`, {
        method: 'POST',
        body: JSON.stringify({ ...newPolicy, config: {} }),
      });
      if (res.ok) {
        showSnackbar('Policy created successfully', 'success');
        setAddPolicyOpen(false);
        setNewPolicy({ name: '', description: '', rule_type: 'path_traversal', severity: 'medium' });
        fetchAll();
      } else {
        showSnackbar('Failed to create policy', 'error');
      }
    } catch {
      showSnackbar('Network error', 'error');
    }
  };

  // ============ CREATE SERVER ============
  const handleCreateServer = async () => {
    if (!newServer.name.trim() || !newServer.url.trim()) {
      showSnackbar('Name and URL are required', 'warning');
      return;
    }
    try {
      const res = await fetchWithAuth(`${API_URL}/mcp/servers`, {
        method: 'POST',
        body: JSON.stringify(newServer),
      });
      if (res.ok) {
        showSnackbar('Server created successfully', 'success');
        setAddServerOpen(false);
        setNewServer({ name: '', description: '', url: '', server_type: 'filesystem' });
        fetchAll();
      } else {
        showSnackbar('Failed to create server', 'error');
      }
    } catch {
      showSnackbar('Network error', 'error');
    }
  };

  // ============ DELETE HANDLERS ============
  const handleDeleteAgent = async (id: number) => {
    if (!window.confirm('Delete this agent?')) return;
    try {
      const res = await fetchWithAuth(`${API_URL}/mcp/agents/${id}`, { method: 'DELETE' });
      const payload = await res.json().catch(() => ({}));
      if (!res.ok) {
        showSnackbar(getApiErrorMessage(payload.detail, 'Failed to delete agent'), 'error');
        return;
      }
      showSnackbar('Agent deleted', 'success');
      fetchAll();
    } catch {
      showSnackbar('Failed to delete agent', 'error');
    }
  };

  const handleDeletePolicy = async (id: number) => {
    if (!window.confirm('Delete this policy?')) return;
    try {
      await fetchWithAuth(`${API_URL}/mcp/policies/${id}`, { method: 'DELETE' });
      showSnackbar('Policy deleted', 'success');
      fetchAll();
    } catch {
      showSnackbar('Failed to delete policy', 'error');
    }
  };

  const handleDeleteServer = async (id: number) => {
    if (!window.confirm('Delete this server?')) return;
    try {
      await fetchWithAuth(`${API_URL}/mcp/servers/${id}`, { method: 'DELETE' });
      showSnackbar('Server deleted', 'success');
      fetchAll();
    } catch {
      showSnackbar('Failed to delete server', 'error');
    }
  };

  // ============ SUSPEND/RESUME ============
  const handleToggleAgent = async (agent: MCPAgent) => {
    const endpoint = agent.is_active ? 'suspend' : 'resume';
    try {
      await fetchWithAuth(`${API_URL}/mcp/agents/${agent.id}/${endpoint}`, { method: 'POST' });
      showSnackbar(`Agent ${agent.is_active ? 'suspended' : 'resumed'}`, 'success');
      fetchAll();
    } catch {
      showSnackbar('Failed to toggle agent', 'error');
    }
  };

  const handleTogglePolicy = async (policy: MCPPolicy) => {
    try {
      await fetchWithAuth(`${API_URL}/mcp/policies/${policy.id}/toggle`, { method: 'PUT' });
      showSnackbar(`Policy ${policy.is_enabled ? 'disabled' : 'enabled'}`, 'success');
      fetchAll();
    } catch {
      showSnackbar('Failed to toggle policy', 'error');
    }
  };

  // ============ RENDERING HELPERS ============
  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
      case 'high':
        return 'error';
      case 'medium':
        return 'warning';
      case 'low':
        return 'info';
      default:
        return 'default';
    }
  };

  const getHealthColor = (status: string) => {
    if (status === 'online') return 'success';
    if (status === 'offline') return 'error';
    return 'default';
  };

  // Use live stats if available, else DB stats
  const effectiveTotal = wsConnected && liveStats.total_requests > 0
    ? liveStats.total_requests
    : overview?.traffic.total_requests || 0;
  const effectiveBlocked = wsConnected && liveStats.total_requests > 0
    ? liveStats.total_blocked
    : overview?.traffic.blocked_requests || 0;

  const trafficSeries = React.useMemo(() => {
    const now = Date.now();
    return Array.from({ length: 12 }, (_, index) => {
      const bucketStart = now - (11 - index) * 5 * 60_000;
      const bucketEnd = bucketStart + 5 * 60_000;
      const bucketEvents = liveEvents.filter((event) => {
        const timestamp = new Date(event.timestamp).getTime();
        return timestamp >= bucketStart && timestamp < bucketEnd;
      });
      return {
        time: new Date(bucketStart).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        requests: bucketEvents.length,
        blocked: bucketEvents.filter((event) => event.decision === 'block').length,
        flagged: bucketEvents.filter((event) => event.decision === 'flag').length,
      };
    });
  }, [liveEvents]);

  const decisionMix = React.useMemo(() => {
    const recent = liveEvents.slice(0, 50);
    if (recent.length) {
      return [
        { name: 'Allowed', value: recent.filter((event) => event.decision === 'allow').length, color: '#56E0C3' },
        { name: 'Flagged', value: recent.filter((event) => event.decision === 'flag').length, color: '#F4B85E' },
        { name: 'Blocked', value: recent.filter((event) => event.decision === 'block').length, color: '#FF6E78' },
      ];
    }
    const blocked = overview?.traffic.blocked_requests || 0;
    const allowed = overview?.traffic.allowed_requests || 0;
    return [
      { name: 'Allowed', value: allowed, color: '#56E0C3' },
      { name: 'Flagged', value: Math.max(0, (overview?.traffic.total_requests || 0) - blocked - allowed), color: '#F4B85E' },
      { name: 'Blocked', value: blocked, color: '#FF6E78' },
    ];
  }, [liveEvents, overview]);

  const agentActivity = React.useMemo(() => agents
    .filter((agent) => agent.total_requests > 0)
    .sort((a, b) => b.total_requests - a.total_requests)
    .slice(0, 6)
    .map((agent) => ({
      name: agent.name.length > 16 ? `${agent.name.slice(0, 14)}…` : agent.name,
      requests: agent.total_requests,
      blocked: agent.blocked_requests,
    })), [agents]);

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '80vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3, maxWidth: 1400, mx: 'auto' }}>
      {/* Header */}
      {createdCredential && (
        <Alert severity="warning" sx={{ mb: 3 }} action={
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Button color="inherit" size="small" onClick={() => navigator.clipboard.writeText(createdCredential)}>
              Copy key
            </Button>
            <Button color="inherit" size="small" onClick={() => navigator.clipboard.writeText(
              `[mcp_servers.sentinel]\ncommand = "python"\nargs = ["R:\\\\sentinel-mcp-gateway\\\\backend\\\\sentinel_mcp_stdio_bridge.py"]\nenv = { SENTINEL_AGENT_API_KEY = "${createdCredential}" }`
            )}>
              Copy Codex config
            </Button>
          </Box>
        }>
          <strong>Credential created:</strong> {createdCredential}
          <Typography variant="caption" sx={{ display: 'block', mt: 1 }}>
            This credential is shown once. The Codex config connects the local stdio bridge to Sentinel. Keep config.toml private.
          </Typography>
        </Alert>
      )}

      <Paper sx={{ p: 3, mb: 3, bgcolor: 'rgba(23, 18, 20,0.8)' }}>
        <Box
          sx={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: 2,
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Avatar sx={{ bgcolor: 'primary.main', width: 56, height: 56 }}>
              <SecurityIcon sx={{ fontSize: 32 }} />
            </Avatar>
            <Box>
              <Typography variant="h4" sx={{ fontWeight: 600 }}>
                MCP Control Center
              </Typography>
              <Typography variant="body2" color="textSecondary">
                Manage AI agents, security policies, and connected MCP servers
              </Typography>
            </Box>
          </Box>
          <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
            {/* WebSocket Status */}
            <Chip
              icon={wsConnected ? <LiveIcon /> : <WifiOffIcon />}
              label={wsConnected ? 'LIVE' : 'OFFLINE'}
              color={wsConnected ? 'success' : 'error'}
              size="small"
              sx={{
                fontWeight: 700,
                animation: wsConnected ? 'pulse 2s infinite' : 'none',
                '@keyframes pulse': {
                  '0%, 100%': { opacity: 1 },
                  '50%': { opacity: 0.6 },
                },
              }}
            />
            <Tooltip title="Refresh">
              <IconButton onClick={() => fetchAll(true)} disabled={refreshing}>
                {refreshing ? <CircularProgress size={24} /> : <RefreshIcon />}
              </IconButton>
            </Tooltip>
          </Box>
        </Box>
      </Paper>

      {/* Overview Stats */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid size={{ xs: 6, sm: 3 }}>
          <Card sx={{ bgcolor: 'rgba(23,18,20,0.8)', border: '1px solid rgba(213,107,130,0.18)' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <PersonIcon color="primary" />
                <Typography variant="caption" color="textSecondary">
                  AGENTS
                </Typography>
              </Box>
              <Typography variant="h4" sx={{ fontWeight: 700 }}>
                {overview?.agents.total || 0}
              </Typography>
              <Typography variant="caption" color="success.main">
                {overview?.agents.active || 0} active
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <Card sx={{ bgcolor: 'rgba(23, 18, 20,0.8)', border: '1px solid rgba(76,175,80,0.15)' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <CloudIcon color="success" />
                <Typography variant="caption" color="textSecondary">
                  SERVERS
                </Typography>
              </Box>
              <Typography variant="h4" sx={{ fontWeight: 700 }}>
                {overview?.servers.total || 0}
              </Typography>
              <Typography variant="caption" color="success.main">
                {overview?.servers.online || 0} online
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <Card sx={{ bgcolor: 'rgba(23, 18, 20,0.8)', border: '1px solid rgba(255,152,0,0.15)' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <SecurityIcon color="warning" />
                <Typography variant="caption" color="textSecondary">
                  POLICIES
                </Typography>
              </Box>
              <Typography variant="h4" sx={{ fontWeight: 700 }}>
                {overview?.policies.total || 0}
              </Typography>
              <Typography variant="caption" color="warning.main">
                {overview?.policies.enabled || 0} enabled
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <Card
            sx={{
              bgcolor: 'rgba(23, 18, 20,0.8)',
              border: wsConnected ? '2px solid rgba(76,175,80,0.5)' : '1px solid rgba(244,67,54,0.15)',
              transition: 'all 0.3s',
            }}
          >
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <SpeedIcon color="error" />
                <Typography variant="caption" color="textSecondary">
                  TRAFFIC {wsConnected && '🔴'}
                </Typography>
              </Box>
              <Typography variant="h4" sx={{ fontWeight: 700 }}>
                {effectiveTotal}
              </Typography>
              <Typography variant="caption" color="error.main">
                {effectiveBlocked} blocked
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid size={{ xs: 12, lg: 7 }}>
          <Paper sx={{ p: { xs: 2, md: 2.6 }, height: 350, background: 'linear-gradient(145deg,rgba(16,26,37,.98),rgba(12,19,28,.98))' }}>
            <Box sx={{ display: 'flex', alignItems: 'start', justifyContent: 'space-between', gap: 1, mb: 1.8 }}>
              <Box><Typography sx={{ fontWeight: 800 }}>Request activity</Typography><Typography variant="caption" color="text.secondary">5-minute windows · live gateway events</Typography></Box>
              <Chip size="small" label={wsConnected ? 'STREAMING' : 'RECENT DATA'} color={wsConnected ? 'success' : 'default'} sx={{ fontSize: 9, fontWeight: 800, letterSpacing: .5 }} />
            </Box>
            <ResponsiveContainer width="100%" height="82%">
              <AreaChart data={trafficSeries} margin={{ top: 8, right: 5, left: -22, bottom: 0 }}>
                <defs><linearGradient id="mcpRequestFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#56E0C3" stopOpacity={.35} /><stop offset="100%" stopColor="#56E0C3" stopOpacity={0} /></linearGradient></defs>
                <CartesianGrid stroke="rgba(154,175,193,.10)" vertical={false} />
                <XAxis dataKey="time" tick={{ fill: '#8293A0', fontSize: 10 }} axisLine={false} tickLine={false} minTickGap={24} />
                <YAxis allowDecimals={false} tick={{ fill: '#8293A0', fontSize: 10 }} axisLine={false} tickLine={false} />
                <ChartTooltip contentStyle={{ background: '#111c27', border: '1px solid rgba(154,175,193,.18)', borderRadius: 10, color: '#eef7f6' }} />
                <Area type="monotone" dataKey="requests" stroke="#56E0C3" strokeWidth={2.5} fill="url(#mcpRequestFill)" name="Requests" />
                <Area type="monotone" dataKey="flagged" stroke="#F4B85E" strokeWidth={1.6} fill="none" name="Flagged" />
                <Area type="monotone" dataKey="blocked" stroke="#FF6E78" strokeWidth={1.6} fill="none" name="Blocked" />
              </AreaChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>
        <Grid size={{ xs: 12, md: 6, lg: 2.5 }}>
          <Paper sx={{ p: { xs: 2, md: 2.6 }, height: 350, background: 'linear-gradient(145deg,rgba(16,26,37,.98),rgba(12,19,28,.98))' }}>
            <Typography sx={{ fontWeight: 800 }}>Decision mix</Typography><Typography variant="caption" color="text.secondary">{liveEvents.length ? 'Last 50 live events' : 'All recorded requests'}</Typography>
            <Box sx={{ height: 200, position: 'relative', mt: 1 }}>
              <ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={decisionMix.filter((entry) => entry.value > 0)} dataKey="value" nameKey="name" innerRadius={57} outerRadius={82} paddingAngle={4} stroke="none">{decisionMix.map((entry) => <Cell key={entry.name} fill={entry.color} />)}</Pie><ChartTooltip contentStyle={{ background: '#111c27', border: '1px solid rgba(154,175,193,.18)', borderRadius: 10 }} /></PieChart></ResponsiveContainer>
              <Box sx={{ position: 'absolute', inset: 0, display: 'grid', placeContent: 'center', pointerEvents: 'none', textAlign: 'center' }}><Typography variant="h5" sx={{ fontWeight: 850 }}>{effectiveTotal.toLocaleString()}</Typography><Typography sx={{ color: '#8293A0', fontSize: 9, letterSpacing: 1 }}>REQUESTS</Typography></Box>
            </Box>
            <Box sx={{ display: 'grid', gap: .9, mt: .4 }}>{decisionMix.map((entry) => <Box key={entry.name} sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><Box sx={{ width: 7, height: 7, bgcolor: entry.color, borderRadius: '50%' }} /><Typography sx={{ flex: 1, color: '#9BAAB7', fontSize: 11 }}>{entry.name}</Typography><Typography sx={{ fontSize: 11, fontWeight: 800 }}>{entry.value.toLocaleString()}</Typography></Box>)}</Box>
          </Paper>
        </Grid>
        <Grid size={{ xs: 12, md: 6, lg: 2.5 }}>
          <Paper sx={{ p: { xs: 2, md: 2.6 }, height: 350, background: 'linear-gradient(145deg,rgba(16,26,37,.98),rgba(12,19,28,.98))' }}>
            <Typography sx={{ fontWeight: 800 }}>Agent activity</Typography><Typography variant="caption" color="text.secondary">Requests by registered agent</Typography>
            {agentActivity.length ? <ResponsiveContainer width="100%" height="86%"><BarChart data={agentActivity} layout="vertical" margin={{ top: 14, right: 8, left: 2, bottom: 0 }}><CartesianGrid stroke="rgba(154,175,193,.09)" horizontal={false} /><XAxis type="number" allowDecimals={false} hide /><YAxis type="category" dataKey="name" width={88} tick={{ fill: '#A9B7C2', fontSize: 9 }} axisLine={false} tickLine={false} /><ChartTooltip contentStyle={{ background: '#111c27', border: '1px solid rgba(154,175,193,.18)', borderRadius: 10 }} /><Bar dataKey="requests" fill="#56E0C3" radius={[0, 5, 5, 0]} barSize={12} name="Requests" /><Bar dataKey="blocked" fill="#FF6E78" radius={[0, 5, 5, 0]} barSize={12} name="Blocked" /></BarChart></ResponsiveContainer> : <Box sx={{ height: '82%', display: 'grid', placeItems: 'center', textAlign: 'center' }}><Typography variant="body2" color="text.secondary">Agent request totals will appear as traffic is recorded.</Typography></Box>}
          </Paper>
        </Grid>
      </Grid>

      {/* Live Traffic Feed */}
      <Paper
        sx={{
          p: 2,
          mb: 3,
          bgcolor: 'rgba(23, 18, 20,0.8)',
          border: `1px solid ${wsConnected ? 'rgba(76,175,80,0.3)' : 'rgba(213,107,130,0.25)'}`,
        }}
      >
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <LiveIcon sx={{ color: wsConnected ? '#4caf50' : '#D56B82', animation: wsConnected ? 'pulse 1.5s infinite' : 'none' }} />
            <Typography variant="h6">Agent Events</Typography>
            <Chip size="small" label={wsConnected ? 'LIVE' : 'RECONNECTING'} color={wsConnected ? 'success' : 'warning'} />
            <Chip size="small" label={`${liveEvents.length} events`} />
          </Box>
          <Button size="small" onClick={clearEvents} disabled={liveEvents.length === 0}>
            Clear
          </Button>
        </Box>
        <Divider sx={{ mb: 2 }} />
        {liveEvents.length === 0 ? (
          <Box sx={{ py: 3, textAlign: 'center' }}>
            <Typography variant="body2" color="textSecondary">
              No agent events yet. Send MCP requests through an agent’s API key to see activity here.
            </Typography>
          </Box>
        ) : (
          <Box sx={{ maxHeight: 360, overflowY: 'auto' }}>
            {liveEvents.slice(0, 25).map((event) => (
              <Box
                key={event.event_id}
                sx={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 1.5,
                  p: 1,
                  mb: 0.5,
                  borderRadius: 1,
                  flexWrap: 'wrap',
                  bgcolor: event.decision === 'block' ? 'rgba(244,67,54,0.05)' : 'rgba(76,175,80,0.05)',
                  borderLeft: `3px solid ${event.decision === 'block' ? '#f44336' : event.decision === 'flag' ? '#ff9800' : '#4caf50'}`,
                }}
              >
                <Typography variant="caption" sx={{ fontFamily: 'monospace', minWidth: 90 }}>
                  {new Date(event.timestamp).toLocaleTimeString()}
                </Typography>
                <Chip
                  size="small"
                  label={event.decision.toUpperCase()}
                  color={event.decision === 'block' ? 'error' : event.decision === 'flag' ? 'warning' : 'success'}
                  sx={{ minWidth: 70 }}
                />
                <Button
                  size="small"
                  color="primary"
                  onClick={() => typeof event.agent_id === 'number' && navigate(`/mcp/agents/${event.agent_id}`)}
                  disabled={typeof event.agent_id !== 'number'}
                  sx={{ textTransform: 'none', minWidth: 120 }}
                >
                  {event.agent_name}
                </Button>
                <Typography variant="caption" sx={{ fontFamily: 'monospace', minWidth: 150 }}>
                  {event.tool_name || event.method}
                </Typography>
                <Typography variant="caption" color="textSecondary" noWrap sx={{ flex: 1, minWidth: 120 }}>
                  {event.decision_reason || 'No policy reason reported'}
                </Typography>
                <Typography variant="caption" color="textSecondary" sx={{ minWidth: 145 }}>
                  ML {event.ml_score === null ? 'n/a' : `${(event.ml_score * 100).toFixed(1)}%`} · Rule {event.rule_risk_score === null ? 'n/a' : `${(event.rule_risk_score * 100).toFixed(1)}%`}
                </Typography>
                <Typography variant="caption" color="textSecondary" sx={{ minWidth: 65, textAlign: 'right' }}>
                  {event.latency_ms === null ? '—' : `${event.latency_ms.toFixed(1)} ms`}
                </Typography>
              </Box>
            ))}
          </Box>
        )}
      </Paper>

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs value={tabValue} onChange={(e, v) => setTabValue(v)}>
          <Tab icon={<PersonIcon />} label={`Agents (${agents.length})`} />
          <Tab icon={<SecurityIcon />} label={`Policies (${policies.length})`} />
          <Tab icon={<CloudIcon />} label={`Servers (${servers.length})`} />
        </Tabs>
      </Paper>

      {/* ============ AGENTS TAB ============ */}
      {tabValue === 0 && (
        <Paper sx={{ p: 3 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="h6">AI Agents</Typography>
            <Button variant="contained" startIcon={<AddIcon />} onClick={() => setAddAgentOpen(true)}>
              Add Agent
            </Button>
          </Box>
          <Divider sx={{ mb: 2 }} />

          {agents.length === 0 ? (
            <Box sx={{ py: 6, textAlign: 'center' }}>
              <PersonIcon sx={{ fontSize: 64, opacity: 0.3, mb: 2 }} />
              <Typography variant="h6" color="textSecondary" sx={{ mb: 1 }}>
                No agents registered
              </Typography>
              <Typography variant="body2" color="textSecondary" sx={{ mb: 3 }}>
                Register your first AI agent to start monitoring
              </Typography>
              <Button variant="outlined" startIcon={<AddIcon />} onClick={() => setAddAgentOpen(true)}>
                Register Agent
              </Button>
            </Box>
          ) : (
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>ID</TableCell>
                    <TableCell>Name</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Requests</TableCell>
                    <TableCell>Blocked</TableCell>
                    <TableCell>API Key</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {agents.map((agent) => (
                    <TableRow key={agent.id} hover>
                      <TableCell>#{agent.id}</TableCell>
                      <TableCell>
                        <Typography
                          variant="body2"
                          sx={{
                            fontWeight: 600,
                            cursor: 'pointer',
                            color: 'primary.main',
                            '&:hover': { textDecoration: 'underline' },
                          }}
                          onClick={() => navigate(`/mcp/agents/${agent.id}`)}
                        >
                          {agent.name}
                        </Typography>
                        <Typography variant="caption" color="textSecondary">
                          {agent.description || 'No description'}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          label={agent.is_active ? 'ACTIVE' : 'SUSPENDED'}
                          color={agent.is_active ? 'success' : 'default'}
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">{agent.total_requests}</Typography>
                      </TableCell>
                      <TableCell>
                        <Typography
                          variant="body2"
                          color={agent.blocked_requests > 0 ? 'error.main' : 'text.primary'}
                        >
                          {agent.blocked_requests}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          icon={<KeyIcon />}
                          label={agent.credential_prefix || 'Key prefix unavailable'}
                          sx={{ fontFamily: 'monospace' }}
                        />
                      </TableCell>
                      <TableCell align="right">
                        <Tooltip title={agent.is_active ? 'Suspend' : 'Resume'}>
                          <IconButton size="small" onClick={() => handleToggleAgent(agent)}>
                            {agent.is_active ? (
                              <PauseIcon fontSize="small" />
                            ) : (
                              <PlayArrowIcon fontSize="small" />
                            )}
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Delete">
                          <IconButton
                            size="small"
                            color="error"
                            onClick={() => handleDeleteAgent(agent.id)}
                          >
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </Paper>
      )}

      {/* ============ POLICIES TAB ============ */}
      {tabValue === 1 && (
        <Paper sx={{ p: 3 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="h6">Security Policies</Typography>
            <Button variant="contained" startIcon={<AddIcon />} onClick={() => setAddPolicyOpen(true)}>
              Add Policy
            </Button>
          </Box>
          <Divider sx={{ mb: 2 }} />

          {policies.length === 0 ? (
            <Box sx={{ py: 6, textAlign: 'center' }}>
              <SecurityIcon sx={{ fontSize: 64, opacity: 0.3, mb: 2 }} />
              <Typography variant="h6" color="textSecondary" sx={{ mb: 1 }}>
                No policies configured
              </Typography>
              <Typography variant="body2" color="textSecondary" sx={{ mb: 3 }}>
                Add security policies to protect your agents
              </Typography>
              <Button variant="outlined" startIcon={<AddIcon />} onClick={() => setAddPolicyOpen(true)}>
                Create Policy
              </Button>
            </Box>
          ) : (
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>ID</TableCell>
                    <TableCell>Name</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {policies.map((policy) => (
                    <TableRow key={policy.id} hover>
                      <TableCell>#{policy.id}</TableCell>
                      <TableCell>
                        <Typography
                          variant="body2"
                          sx={{
                            fontWeight: 600,
                            cursor: 'pointer',
                            color: 'primary.main',
                            '&:hover': { textDecoration: 'underline' },
                          }}
                          onClick={() => navigate(`/mcp/policies/${policy.id}`)}
                        >
                          {policy.name}
                        </Typography>
                        <Typography variant="caption" color="textSecondary">
                          {policy.description || 'No description'}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip size="small" label={policy.rule_type} variant="outlined" />
                      </TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          label={policy.severity.toUpperCase()}
                          color={getSeverityColor(policy.severity) as any}
                        />
                      </TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          label={policy.is_enabled ? 'ENABLED' : 'DISABLED'}
                          color={policy.is_enabled ? 'success' : 'default'}
                          onClick={() => handleTogglePolicy(policy)}
                          sx={{ cursor: 'pointer' }}
                        />
                      </TableCell>
                      <TableCell align="right">
                        <Tooltip title="Delete">
                          <IconButton
                            size="small"
                            color="error"
                            onClick={() => handleDeletePolicy(policy.id)}
                          >
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </Paper>
      )}

      {/* ============ SERVERS TAB ============ */}
      {tabValue === 2 && (
        <Paper sx={{ p: 3 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="h6">MCP Servers</Typography>
            <Button variant="contained" startIcon={<AddIcon />} onClick={() => setAddServerOpen(true)}>
              Add Server
            </Button>
          </Box>
          <Divider sx={{ mb: 2 }} />

          {servers.length === 0 ? (
            <Box sx={{ py: 6, textAlign: 'center' }}>
              <CloudIcon sx={{ fontSize: 64, opacity: 0.3, mb: 2 }} />
              <Typography variant="h6" color="textSecondary" sx={{ mb: 1 }}>
                No servers connected
              </Typography>
              <Typography variant="body2" color="textSecondary" sx={{ mb: 3 }}>
                Connect your MCP servers to proxy through the gateway
              </Typography>
              <Button variant="outlined" startIcon={<AddIcon />} onClick={() => setAddServerOpen(true)}>
                Connect Server
              </Button>
            </Box>
          ) : (
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>ID</TableCell>
                    <TableCell>Name</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>URL</TableCell>
                    <TableCell>Health</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {servers.map((server) => (
                    <TableRow key={server.id} hover>
                      <TableCell>#{server.id}</TableCell>
                      <TableCell>
                        <Typography
                          variant="body2"
                          sx={{
                            fontWeight: 600,
                            cursor: 'pointer',
                            color: 'primary.main',
                            '&:hover': { textDecoration: 'underline' },
                          }}
                          onClick={() => navigate(`/mcp/servers/${server.id}`)}
                        >
                          {server.name}
                        </Typography>
                        <Typography variant="caption" color="textSecondary">
                          {server.description || 'No description'}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip size="small" label={server.server_type} variant="outlined" />
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption" sx={{ fontFamily: 'monospace' }}>
                          {server.url}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          label={server.health_status.toUpperCase()}
                          color={getHealthColor(server.health_status) as any}
                        />
                      </TableCell>
                      <TableCell align="right">
                        <Tooltip title="Delete">
                          <IconButton
                            size="small"
                            color="error"
                            onClick={() => handleDeleteServer(server.id)}
                          >
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </Paper>
      )}

      {/* ============ ADD AGENT DIALOG ============ */}
      <Dialog open={addAgentOpen} onClose={() => setAddAgentOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Register New Agent</DialogTitle>
        <DialogContent>
          <TextField
            fullWidth
            label="Agent Name"
            value={newAgent.name}
            onChange={(e) => setNewAgent({ ...newAgent, name: e.target.value })}
            margin="normal"
            required
          />
          <TextField
            fullWidth
            label="Description"
            value={newAgent.description}
            onChange={(e) => setNewAgent({ ...newAgent, description: e.target.value })}
            margin="normal"
            multiline
            rows={2}
          />
          <TextField
            fullWidth
            label="Allowed tools"
            value={newAgent.allowed_tools}
            onChange={(e) => setNewAgent({ ...newAgent, allowed_tools: e.target.value })}
            margin="normal"
            helperText="Optional, comma-separated tool names. Set this to create a restricted agent for policy demos."
          />
          <TextField
            fullWidth
            label="MCP upstream URL"
            placeholder="http://127.0.0.1:8765/mcp"
            value={newAgent.upstream_url}
            onChange={(e) => setNewAgent({ ...newAgent, upstream_url: e.target.value })}
            margin="normal"
            helperText="Optional. Routes this agent to its own Streamable HTTP MCP server; blank uses the gateway default."
          />
          <TextField
            fullWidth
            label="Upstream display name"
            value={newAgent.upstream_name}
            onChange={(e) => setNewAgent({ ...newAgent, upstream_name: e.target.value })}
            margin="normal"
            helperText="Optional label shown in event records."
          />
          <TextField
            fullWidth
            label="Upstream bearer token environment variable"
            placeholder="MY_MCP_SERVER_TOKEN"
            value={newAgent.upstream_token_env}
            onChange={(e) => setNewAgent({ ...newAgent, upstream_token_env: e.target.value })}
            margin="normal"
            helperText="Optional. Store the upstream secret in the gateway process environment under this name."
          />
          <Alert severity="info" sx={{ mt: 2 }}>
            An API key will be generated automatically. Save it securely.
          </Alert>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAddAgentOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={handleCreateAgent}>
            Create Agent
          </Button>
        </DialogActions>
      </Dialog>

      {/* ============ ADD POLICY DIALOG ============ */}
      <Dialog open={addPolicyOpen} onClose={() => setAddPolicyOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Create Security Policy</DialogTitle>
        <DialogContent>
          <TextField
            fullWidth
            label="Policy Name"
            value={newPolicy.name}
            onChange={(e) => setNewPolicy({ ...newPolicy, name: e.target.value })}
            margin="normal"
            required
          />
          <TextField
            fullWidth
            label="Description"
            value={newPolicy.description}
            onChange={(e) => setNewPolicy({ ...newPolicy, description: e.target.value })}
            margin="normal"
            multiline
            rows={2}
          />
          <FormControl fullWidth margin="normal">
            <InputLabel>Rule Type</InputLabel>
            <Select
              value={newPolicy.rule_type}
              label="Rule Type"
              onChange={(e) => setNewPolicy({ ...newPolicy, rule_type: e.target.value })}
            >
              <MenuItem value="path_traversal">Path Traversal</MenuItem>
              <MenuItem value="command_whitelist">Command Whitelist</MenuItem>
              <MenuItem value="sql_injection">SQL Injection</MenuItem>
              <MenuItem value="network_restriction">Network Restriction</MenuItem>
              <MenuItem value="rate_limit">Rate Limit</MenuItem>
            </Select>
          </FormControl>
          <FormControl fullWidth margin="normal">
            <InputLabel>Severity</InputLabel>
            <Select
              value={newPolicy.severity}
              label="Severity"
              onChange={(e) => setNewPolicy({ ...newPolicy, severity: e.target.value })}
            >
              <MenuItem value="low">Low</MenuItem>
              <MenuItem value="medium">Medium</MenuItem>
              <MenuItem value="high">High</MenuItem>
              <MenuItem value="critical">Critical</MenuItem>
            </Select>
          </FormControl>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAddPolicyOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={handleCreatePolicy}>
            Create Policy
          </Button>
        </DialogActions>
      </Dialog>

      {/* ============ ADD SERVER DIALOG ============ */}
      <Dialog open={addServerOpen} onClose={() => setAddServerOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Connect MCP Server</DialogTitle>
        <DialogContent>
          <TextField
            fullWidth
            label="Server Name"
            value={newServer.name}
            onChange={(e) => setNewServer({ ...newServer, name: e.target.value })}
            margin="normal"
            required
          />
          <TextField
            fullWidth
            label="Description"
            value={newServer.description}
            onChange={(e) => setNewServer({ ...newServer, description: e.target.value })}
            margin="normal"
          />
          <TextField
            fullWidth
            label="Server URL"
            value={newServer.url}
            onChange={(e) => setNewServer({ ...newServer, url: e.target.value })}
            margin="normal"
            placeholder="http://localhost:3001"
            required
          />
          <FormControl fullWidth margin="normal">
            <InputLabel>Server Type</InputLabel>
            <Select
              value={newServer.server_type}
              label="Server Type"
              onChange={(e) => setNewServer({ ...newServer, server_type: e.target.value })}
            >
              <MenuItem value="filesystem">Filesystem</MenuItem>
              <MenuItem value="database">Database</MenuItem>
              <MenuItem value="shell">Shell</MenuItem>
              <MenuItem value="network">Network</MenuItem>
              <MenuItem value="custom">Custom</MenuItem>
            </Select>
          </FormControl>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAddServerOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={handleCreateServer}>
            Connect Server
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert severity={snackbar.severity} onClose={() => setSnackbar({ ...snackbar, open: false })}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default MCPDashboard;
