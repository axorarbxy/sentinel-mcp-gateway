// pages/MCPDashboard.tsx
import React, { useEffect, useState } from 'react';
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
} from '@mui/icons-material';

const API_URL = 'http://localhost:8001';

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
  api_key: string;
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
  const [tabValue, setTabValue] = useState(0);
  const [overview, setOverview] = useState<MCPOverview | null>(null);
  const [agents, setAgents] = useState<MCPAgent[]>([]);
  const [policies, setPolicies] = useState<MCPPolicy[]>([]);
  const [servers, setServers] = useState<MCPServer[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Dialog states
  const [addAgentOpen, setAddAgentOpen] = useState(false);
  const [addPolicyOpen, setAddPolicyOpen] = useState(false);
  const [addServerOpen, setAddServerOpen] = useState(false);

  // Form states
  const [newAgent, setNewAgent] = useState({ name: '', description: '' });
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

  const showSnackbar = (message: string, severity: 'success' | 'error' | 'info' | 'warning') => {
    setSnackbar({ open: true, message, severity });
  };

  // ============ FETCH DATA ============
  const fetchAll = async (showLoader = false) => {
    if (showLoader) setRefreshing(true);
    try {
      const [overviewRes, agentsRes, policiesRes, serversRes] = await Promise.all([
        fetch(`${API_URL}/mcp/overview`),
        fetch(`${API_URL}/mcp/agents`),
        fetch(`${API_URL}/mcp/policies`),
        fetch(`${API_URL}/mcp/servers`),
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
  };

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 10000);
    return () => clearInterval(interval);
  }, []);

  // ============ CREATE AGENT ============
  const handleCreateAgent = async () => {
    if (!newAgent.name.trim()) {
      showSnackbar('Agent name is required', 'warning');
      return;
    }
    try {
      const res = await fetch(`${API_URL}/mcp/agents`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newAgent),
      });
      if (res.ok) {
        showSnackbar('Agent created successfully', 'success');
        setAddAgentOpen(false);
        setNewAgent({ name: '', description: '' });
        fetchAll();
      } else {
        showSnackbar('Failed to create agent', 'error');
      }
    } catch {
      showSnackbar('Network error', 'error');
    }
  };

  // ============ CREATE POLICY ============
  const handleCreatePolicy = async () => {
    if (!newPolicy.name.trim()) {
      showSnackbar('Policy name is required', 'warning');
      return;
    }
    try {
      const res = await fetch(`${API_URL}/mcp/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
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
      const res = await fetch(`${API_URL}/mcp/servers`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
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
      await fetch(`${API_URL}/mcp/agents/${id}`, { method: 'DELETE' });
      showSnackbar('Agent deleted', 'success');
      fetchAll();
    } catch {
      showSnackbar('Failed to delete agent', 'error');
    }
  };

  const handleDeletePolicy = async (id: number) => {
    if (!window.confirm('Delete this policy?')) return;
    try {
      await fetch(`${API_URL}/mcp/policies/${id}`, { method: 'DELETE' });
      showSnackbar('Policy deleted', 'success');
      fetchAll();
    } catch {
      showSnackbar('Failed to delete policy', 'error');
    }
  };

  const handleDeleteServer = async (id: number) => {
    if (!window.confirm('Delete this server?')) return;
    try {
      await fetch(`${API_URL}/mcp/servers/${id}`, { method: 'DELETE' });
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
      await fetch(`${API_URL}/mcp/agents/${agent.id}/${endpoint}`, { method: 'POST' });
      showSnackbar(`Agent ${agent.is_active ? 'suspended' : 'resumed'}`, 'success');
      fetchAll();
    } catch {
      showSnackbar('Failed to toggle agent', 'error');
    }
  };

  const handleTogglePolicy = async (policy: MCPPolicy) => {
    try {
      await fetch(`${API_URL}/mcp/policies/${policy.id}/toggle`, { method: 'PUT' });
      showSnackbar(`Policy ${policy.is_enabled ? 'disabled' : 'enabled'}`, 'success');
      fetchAll();
    } catch {
      showSnackbar('Failed to toggle policy', 'error');
    }
  };

  // ============ COPY API KEY ============
  const copyApiKey = (key: string) => {
    navigator.clipboard.writeText(key);
    showSnackbar('API key copied to clipboard', 'success');
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
      <Paper sx={{ p: 3, mb: 3, bgcolor: 'rgba(26,35,50,0.8)' }}>
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
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Tooltip title="Refresh">
              <IconButton onClick={() => fetchAll(true)} disabled={refreshing}>
                {refreshing ? <CircularProgress size={24} /> : <RefreshIcon />}
              </IconButton>
            </Tooltip>
          </Box>
        </Box>
      </Paper>

      {/* Overview Stats */}
      {overview && (
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid size={{ xs: 6, sm: 3 }}>
            <Card sx={{ bgcolor: 'rgba(26,35,50,0.8)', border: '1px solid rgba(144,202,249,0.15)' }}>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                  <PersonIcon color="primary" />
                  <Typography variant="caption" color="textSecondary">
                    AGENTS
                  </Typography>
                </Box>
                <Typography variant="h4" sx={{ fontWeight: 700 }}>
                  {overview.agents.total}
                </Typography>
                <Typography variant="caption" color="success.main">
                  {overview.agents.active} active
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid size={{ xs: 6, sm: 3 }}>
            <Card sx={{ bgcolor: 'rgba(26,35,50,0.8)', border: '1px solid rgba(76,175,80,0.15)' }}>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                  <CloudIcon color="success" />
                  <Typography variant="caption" color="textSecondary">
                    SERVERS
                  </Typography>
                </Box>
                <Typography variant="h4" sx={{ fontWeight: 700 }}>
                  {overview.servers.total}
                </Typography>
                <Typography variant="caption" color="success.main">
                  {overview.servers.online} online
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid size={{ xs: 6, sm: 3 }}>
            <Card sx={{ bgcolor: 'rgba(26,35,50,0.8)', border: '1px solid rgba(255,152,0,0.15)' }}>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                  <SecurityIcon color="warning" />
                  <Typography variant="caption" color="textSecondary">
                    POLICIES
                  </Typography>
                </Box>
                <Typography variant="h4" sx={{ fontWeight: 700 }}>
                  {overview.policies.total}
                </Typography>
                <Typography variant="caption" color="warning.main">
                  {overview.policies.enabled} enabled
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid size={{ xs: 6, sm: 3 }}>
            <Card sx={{ bgcolor: 'rgba(26,35,50,0.8)', border: '1px solid rgba(244,67,54,0.15)' }}>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                  <SpeedIcon color="error" />
                  <Typography variant="caption" color="textSecondary">
                    TRAFFIC
                  </Typography>
                </Box>
                <Typography variant="h4" sx={{ fontWeight: 700 }}>
                  {overview.traffic.total_requests}
                </Typography>
                <Typography variant="caption" color="error.main">
                  {overview.traffic.blocked_requests} blocked
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

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
                        <Typography variant="body2" sx={{ fontWeight: 600 }}>
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
                        <Tooltip title="Click to copy">
                          <Chip
                            size="small"
                            icon={<KeyIcon />}
                            label={`${agent.api_key.slice(0, 20)}...`}
                            onClick={() => copyApiKey(agent.api_key)}
                            sx={{ cursor: 'pointer', fontFamily: 'monospace' }}
                          />
                        </Tooltip>
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
                        <Typography variant="body2" sx={{ fontWeight: 600 }}>
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
                        <Typography variant="body2" sx={{ fontWeight: 600 }}>
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