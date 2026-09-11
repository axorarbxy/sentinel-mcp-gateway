// pages/MCPAgentDetail.tsx
import React, { useEffect, useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
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
  Alert,
  Snackbar,
  CircularProgress,
  LinearProgress,
  Tabs,
  Tab,
  List,
  ListItem,
  ListItemText,
  ListItemAvatar,
} from '@mui/material';
import {
  ArrowBack as ArrowBackIcon,
  Person as PersonIcon,
  PlayArrow as PlayArrowIcon,
  Pause as PauseIcon,
  Delete as DeleteIcon,
  VpnKey as KeyIcon,
  Speed as SpeedIcon,
  CheckCircle as CheckCircleIcon,
  Block as BlockIcon,
  Warning as WarningIcon,
  Security as SecurityIcon,
  Timeline as TimelineIcon,
  Refresh as RefreshIcon,
  ContentCopy as CopyIcon,
  TrendingUp as TrendingUpIcon,
  Code as CodeIcon,
  Terminal as TerminalIcon,
  Lock as LockIcon,
} from '@mui/icons-material';
import { useParams, useNavigate } from 'react-router-dom';

const API_URL = 'http://localhost:8001';

// ============ TYPES ============
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

interface LogEntry {
  timestamp: string;
  agent_id: string;
  method: string;
  params: any;
  policy_allowed: boolean;
  policy_reason: string;
  ml_anomaly: boolean;
}

// ============ MAIN COMPONENT ============
const MCPAgentDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [agent, setAgent] = useState<MCPAgent | null>(null);
  const [agentLogs, setAgentLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [tabValue, setTabValue] = useState(0);
  const [snackbar, setSnackbar] = useState({
    open: false,
    message: '',
    severity: 'info' as 'success' | 'error' | 'info' | 'warning',
  });

  const showSnackbar = (message: string, severity: 'success' | 'error' | 'info' | 'warning') => {
    setSnackbar({ open: true, message, severity });
  };

  // ============ FETCH AGENT DATA ============
  const fetchAgent = async () => {
    try {
      const [agentRes, logsRes] = await Promise.all([
        fetch(`${API_URL}/mcp/agents/${id}`),
        fetch(`${API_URL}/logs?limit=200`),
      ]);

      if (agentRes.ok) {
        setAgent(await agentRes.json());
      } else if (agentRes.status === 404) {
        showSnackbar('Agent not found', 'error');
        setTimeout(() => navigate('/mcp'), 2000);
      }

      if (logsRes.ok) {
        const data = await logsRes.json();
        const filtered = (data.logs || []).filter(
          (log: LogEntry) => log.agent_id === `agent-${id}` || log.agent_id === String(id)
        );
        setAgentLogs(filtered.slice(0, 50));
      }
    } catch (error) {
      console.error('Fetch error:', error);
      showSnackbar('Failed to fetch agent data', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAgent();
    const interval = setInterval(fetchAgent, 10000);
    return () => clearInterval(interval);
  }, [id]);

  // ============ ACTIONS ============
  const handleToggle = async () => {
    if (!agent) return;
    const endpoint = agent.is_active ? 'suspend' : 'resume';
    try {
      await fetch(`${API_URL}/mcp/agents/${agent.id}/${endpoint}`, { method: 'POST' });
      showSnackbar(`Agent ${agent.is_active ? 'suspended' : 'resumed'}`, 'success');
      fetchAgent();
    } catch {
      showSnackbar('Failed to toggle agent', 'error');
    }
  };

  const handleDelete = async () => {
    if (!agent) return;
    if (!window.confirm(`Delete agent "${agent.name}"? This cannot be undone.`)) return;
    try {
      await fetch(`${API_URL}/mcp/agents/${agent.id}`, { method: 'DELETE' });
      showSnackbar('Agent deleted', 'success');
      setTimeout(() => navigate('/mcp'), 1000);
    } catch {
      showSnackbar('Failed to delete agent', 'error');
    }
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    showSnackbar(`${label} copied to clipboard`, 'success');
  };

  // ============ COMPUTED ============
  const blockRate = agent && agent.total_requests > 0
    ? (agent.blocked_requests / agent.total_requests) * 100
    : 0;

  const allowedRequests = agent ? agent.total_requests - agent.blocked_requests : 0;

  // cURL command generator
  const curlCommand = agent ? `curl -X POST http://localhost:8001/mcp/proxy \\
  -H "Authorization: Bearer ${agent.api_key}" \\
  -H "Content-Type: application/json" \\
  -d '{
    "jsonrpc": "2.0",
    "method": "filesystem/read",
    "params": {"path": "/home/user/test.txt"},
    "id": 1
  }'` : '';

  // Python sample code
  const pythonCode = agent ? `import httpx

response = httpx.post(
    "http://localhost:8001/mcp/proxy",
    headers={
        "Authorization": "Bearer ${agent.api_key}",
        "Content-Type": "application/json",
    },
    json={
        "jsonrpc": "2.0",
        "method": "filesystem/read",
        "params": {"path": "/home/user/test.txt"},
        "id": 1
    }
)
print(response.json())` : '';

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '80vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  if (!agent) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">Agent not found</Alert>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3, maxWidth: 1400, mx: 'auto' }}>
      {/* Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
        <IconButton onClick={() => navigate('/mcp')} size="large">
          <ArrowBackIcon />
        </IconButton>
        <Box sx={{ flexGrow: 1 }}>
          <Typography variant="h4" sx={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1 }}>
            <PersonIcon sx={{ fontSize: 32 }} />
            {agent.name}
          </Typography>
          <Typography variant="body2" color="textSecondary">
            {agent.description || 'No description provided'}
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="Refresh">
            <IconButton onClick={fetchAgent}>
              <RefreshIcon />
            </IconButton>
          </Tooltip>
          <Button
            variant="outlined"
            startIcon={agent.is_active ? <PauseIcon /> : <PlayArrowIcon />}
            onClick={handleToggle}
            color={agent.is_active ? 'warning' : 'success'}
          >
            {agent.is_active ? 'Suspend' : 'Resume'}
          </Button>
          <Button variant="outlined" color="error" startIcon={<DeleteIcon />} onClick={handleDelete}>
            Delete
          </Button>
        </Box>
      </Box>

      {/* Status Banner */}
      <Paper
        sx={{
          p: 2,
          mb: 3,
          bgcolor: agent.is_active ? 'rgba(76,175,80,0.1)' : 'rgba(158,158,158,0.1)',
          border: `1px solid ${agent.is_active ? 'rgba(76,175,80,0.3)' : 'rgba(158,158,158,0.3)'}`,
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
          <Box
            sx={{
              width: 10,
              height: 10,
              borderRadius: '50%',
              bgcolor: agent.is_active ? '#4caf50' : '#9e9e9e',
              boxShadow: agent.is_active ? '0 0 10px #4caf50' : 'none',
              animation: agent.is_active ? 'pulse 2s infinite' : 'none',
              '@keyframes pulse': {
                '0%, 100%': { opacity: 1 },
                '50%': { opacity: 0.4 },
              },
            }}
          />
          <Typography variant="body2" sx={{ fontWeight: 600 }}>
            {agent.is_active ? 'Agent is ACTIVE and processing requests' : 'Agent is SUSPENDED'}
          </Typography>
          <Chip
            size="small"
            icon={<LockIcon />}
            label="API KEY PROTECTED"
            color="primary"
            variant="outlined"
          />
          <Typography variant="caption" color="textSecondary" sx={{ ml: 'auto' }}>
            Created: {new Date(agent.created_at).toLocaleString()}
          </Typography>
          {agent.last_seen && (
            <Typography variant="caption" color="textSecondary">
              Last seen: {new Date(agent.last_seen).toLocaleString()}
            </Typography>
          )}
        </Box>
      </Paper>

      {/* ============ KPI CARDS ============ */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card sx={{ bgcolor: 'rgba(26,35,50,0.8)', border: '1px solid rgba(144,202,249,0.15)' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <SpeedIcon color="primary" />
                <Typography variant="caption" color="textSecondary">
                  TOTAL REQUESTS
                </Typography>
              </Box>
              <Typography variant="h3" sx={{ fontWeight: 700 }}>
                {agent.total_requests}
              </Typography>
              <Typography variant="caption" color="textSecondary">
                All-time requests
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card sx={{ bgcolor: 'rgba(26,35,50,0.8)', border: '1px solid rgba(76,175,80,0.15)' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <CheckCircleIcon sx={{ color: '#4caf50' }} />
                <Typography variant="caption" color="textSecondary">
                  ALLOWED
                </Typography>
              </Box>
              <Typography variant="h3" sx={{ fontWeight: 700, color: '#4caf50' }}>
                {allowedRequests}
              </Typography>
              <Typography variant="caption" color="success.main">
                {agent.total_requests > 0
                  ? `${(((agent.total_requests - agent.blocked_requests) / agent.total_requests) * 100).toFixed(1)}% success`
                  : 'No data'}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card sx={{ bgcolor: 'rgba(26,35,50,0.8)', border: '1px solid rgba(244,67,54,0.15)' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <BlockIcon sx={{ color: '#f44336' }} />
                <Typography variant="caption" color="textSecondary">
                  BLOCKED
                </Typography>
              </Box>
              <Typography variant="h3" sx={{ fontWeight: 700, color: '#f44336' }}>
                {agent.blocked_requests}
              </Typography>
              <Typography variant="caption" color="error.main">
                {blockRate.toFixed(1)}% block rate
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card sx={{ bgcolor: 'rgba(26,35,50,0.8)', border: '1px solid rgba(255,152,0,0.15)' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <SecurityIcon sx={{ color: '#ff9800' }} />
                <Typography variant="caption" color="textSecondary">
                  POLICIES
                </Typography>
              </Box>
              <Typography variant="h3" sx={{ fontWeight: 700, color: '#ff9800' }}>
                {agent.policies.length}
              </Typography>
              <Typography variant="caption" color="warning.main">
                Active policies
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* ============ API KEY ============ */}
      <Paper sx={{ p: 3, mb: 3, bgcolor: 'rgba(26,35,50,0.8)', border: '1px solid rgba(144,202,249,0.15)' }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <KeyIcon color="primary" />
            <Typography variant="h6">API Key</Typography>
            <Chip size="small" icon={<LockIcon />} label="Bearer Auth" color="primary" variant="outlined" />
          </Box>
          <Button size="small" startIcon={<CopyIcon />} onClick={() => copyToClipboard(agent.api_key, 'API key')}>
            Copy
          </Button>
        </Box>
        <Divider sx={{ mb: 2 }} />
        <Box
          sx={{
            p: 2,
            bgcolor: 'rgba(0,0,0,0.3)',
            borderRadius: 2,
            fontFamily: 'monospace',
            fontSize: '0.85rem',
            wordBreak: 'break-all',
            color: '#90caf9',
          }}
        >
          {agent.api_key}
        </Box>
        <Alert severity="warning" sx={{ mt: 2 }}>
          Keep this API key secure. Anyone with this key can make requests as this agent.
        </Alert>
      </Paper>

      {/* ============ TABS ============ */}
      <Paper sx={{ mb: 3 }}>
        <Tabs value={tabValue} onChange={(e, v) => setTabValue(v)}>
          <Tab icon={<TimelineIcon />} label="Recent Activity" />
          <Tab icon={<TrendingUpIcon />} label="Statistics" />
          <Tab icon={<CodeIcon />} label="Integration" />
        </Tabs>
      </Paper>

      {/* ============ TAB 1: ACTIVITY ============ */}
      {tabValue === 0 && (
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" gutterBottom>
            Recent Requests
          </Typography>
          <Typography variant="caption" color="textSecondary" sx={{ display: 'block', mb: 2 }}>
            Last 50 requests from this agent
          </Typography>
          <Divider sx={{ mb: 2 }} />

          {agentLogs.length === 0 ? (
            <Box sx={{ py: 6, textAlign: 'center' }}>
              <TimelineIcon sx={{ fontSize: 64, opacity: 0.3, mb: 2 }} />
              <Typography variant="h6" color="textSecondary" sx={{ mb: 1 }}>
                No activity yet
              </Typography>
              <Typography variant="body2" color="textSecondary">
                Requests from this agent will appear here
              </Typography>
            </Box>
          ) : (
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Time</TableCell>
                    <TableCell>Method</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Reason</TableCell>
                    <TableCell>ML Anomaly</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {agentLogs.map((log, index) => (
                    <TableRow key={index} hover>
                      <TableCell>
                        <Typography variant="caption" sx={{ fontFamily: 'monospace' }}>
                          {new Date(log.timestamp).toLocaleString()}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                          {log.method}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          label={log.policy_allowed ? 'Allowed' : 'Blocked'}
                          color={log.policy_allowed ? 'success' : 'error'}
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption" noWrap sx={{ maxWidth: 300, display: 'block' }}>
                          {log.policy_reason}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          label={log.ml_anomaly ? 'ANOMALY' : 'Normal'}
                          color={log.ml_anomaly ? 'warning' : 'default'}
                          variant={log.ml_anomaly ? 'filled' : 'outlined'}
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </Paper>
      )}

      {/* ============ TAB 2: STATISTICS ============ */}
      {tabValue === 1 && (
        <Grid container spacing={3}>
          <Grid size={{ xs: 12, md: 6 }}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>
                Request Distribution
              </Typography>
              <Divider sx={{ mb: 2 }} />

              <Box sx={{ mb: 2 }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                  <Typography variant="body2">Allowed Requests</Typography>
                  <Typography variant="body2" sx={{ fontWeight: 600, color: '#4caf50' }}>
                    {allowedRequests}
                  </Typography>
                </Box>
                <LinearProgress
                  variant="determinate"
                  value={agent.total_requests > 0 ? (allowedRequests / agent.total_requests) * 100 : 0}
                  sx={{
                    height: 8,
                    borderRadius: 4,
                    bgcolor: 'rgba(76,175,80,0.1)',
                    '& .MuiLinearProgress-bar': { bgcolor: '#4caf50' },
                  }}
                />
              </Box>

              <Box>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                  <Typography variant="body2">Blocked Requests</Typography>
                  <Typography variant="body2" sx={{ fontWeight: 600, color: '#f44336' }}>
                    {agent.blocked_requests}
                  </Typography>
                </Box>
                <LinearProgress
                  variant="determinate"
                  value={blockRate}
                  sx={{
                    height: 8,
                    borderRadius: 4,
                    bgcolor: 'rgba(244,67,54,0.1)',
                    '& .MuiLinearProgress-bar': { bgcolor: '#f44336' },
                  }}
                />
              </Box>

              <Box sx={{ mt: 3, p: 2, bgcolor: 'rgba(0,0,0,0.2)', borderRadius: 2 }}>
                <Typography variant="caption" color="textSecondary">
                  Block Rate
                </Typography>
                <Typography variant="h4" sx={{ fontWeight: 700 }}>
                  {blockRate.toFixed(2)}%
                </Typography>
                <Typography variant="caption" color="textSecondary">
                  {blockRate > 20 ? '⚠️ High block rate — investigate' : '✅ Normal block rate'}
                </Typography>
              </Box>
            </Paper>
          </Grid>

          <Grid size={{ xs: 12, md: 6 }}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>
                Agent Health
              </Typography>
              <Divider sx={{ mb: 2 }} />

              <List>
                <ListItem>
                  <ListItemAvatar>
                    <Avatar sx={{ bgcolor: agent.is_active ? '#4caf50' : '#9e9e9e' }}>
                      {agent.is_active ? <CheckCircleIcon /> : <WarningIcon />}
                    </Avatar>
                  </ListItemAvatar>
                  <ListItemText
                    primary="Status"
                    secondary={agent.is_active ? 'Active' : 'Suspended'}
                  />
                </ListItem>

                <ListItem>
                  <ListItemAvatar>
                    <Avatar sx={{ bgcolor: '#2196f3' }}>
                      <TimelineIcon />
                    </Avatar>
                  </ListItemAvatar>
                  <ListItemText
                    primary="Last Seen"
                    secondary={
                      agent.last_seen
                        ? new Date(agent.last_seen).toLocaleString()
                        : 'Never'
                    }
                  />
                </ListItem>

                <ListItem>
                  <ListItemAvatar>
                    <Avatar sx={{ bgcolor: '#ff9800' }}>
                      <SecurityIcon />
                    </Avatar>
                  </ListItemAvatar>
                  <ListItemText
                    primary="Active Policies"
                    secondary={`${agent.policies.length} policies applied`}
                  />
                </ListItem>

                <ListItem>
                  <ListItemAvatar>
                    <Avatar sx={{ bgcolor: '#9c27b0' }}>
                      <KeyIcon />
                    </Avatar>
                  </ListItemAvatar>
                  <ListItemText
                    primary="API Key Age"
                    secondary={`Created ${new Date(agent.created_at).toLocaleDateString()}`}
                  />
                </ListItem>
              </List>
            </Paper>
          </Grid>
        </Grid>
      )}

      {/* ============ TAB 3: INTEGRATION ============ */}
      {tabValue === 2 && (
        <Grid container spacing={3}>
          {/* Python Sample */}
          <Grid size={{ xs: 12, md: 6 }}>
            <Paper sx={{ p: 3 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                <CodeIcon color="primary" />
                <Typography variant="h6">Python Integration</Typography>
                <Button
                  size="small"
                  startIcon={<CopyIcon />}
                  sx={{ ml: 'auto' }}
                  onClick={() => copyToClipboard(pythonCode, 'Python code')}
                >
                  Copy
                </Button>
              </Box>
              <Divider sx={{ mb: 2 }} />

              <Box
                component="pre"
                sx={{
                  p: 2,
                  bgcolor: 'rgba(0,0,0,0.4)',
                  borderRadius: 2,
                  fontFamily: 'monospace',
                  fontSize: '0.75rem',
                  overflow: 'auto',
                  maxHeight: 400,
                  color: '#90caf9',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                }}
              >
                {pythonCode}
              </Box>
            </Paper>
          </Grid>

          {/* cURL Sample */}
          <Grid size={{ xs: 12, md: 6 }}>
            <Paper sx={{ p: 3 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                <TerminalIcon color="primary" />
                <Typography variant="h6">cURL Command</Typography>
                <Button
                  size="small"
                  startIcon={<CopyIcon />}
                  sx={{ ml: 'auto' }}
                  onClick={() => copyToClipboard(curlCommand, 'cURL command')}
                >
                  Copy
                </Button>
              </Box>
              <Divider sx={{ mb: 2 }} />

              <Box
                component="pre"
                sx={{
                  p: 2,
                  bgcolor: 'rgba(0,0,0,0.4)',
                  borderRadius: 2,
                  fontFamily: 'monospace',
                  fontSize: '0.75rem',
                  overflow: 'auto',
                  maxHeight: 400,
                  color: '#90caf9',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                }}
              >
                {curlCommand}
              </Box>
            </Paper>
          </Grid>

          {/* Integration Notes */}
          <Grid size={{ xs: 12 }}>
            <Paper sx={{ p: 3, bgcolor: 'rgba(26,35,50,0.8)' }}>
              <Typography variant="h6" gutterBottom>
                🔒 Authentication Notes
              </Typography>
              <Divider sx={{ mb: 2 }} />
              <Grid container spacing={2}>
                <Grid size={{ xs: 12, sm: 6 }}>
                  <Alert severity="info">
                    <Typography variant="body2" sx={{ fontWeight: 600 }}>
                      Required Header
                    </Typography>
                    <Typography variant="caption" sx={{ fontFamily: 'monospace' }}>
                      Authorization: Bearer {agent.api_key.slice(0, 20)}...
                    </Typography>
                  </Alert>
                </Grid>
                <Grid size={{ xs: 12, sm: 6 }}>
                  <Alert severity="warning">
                    <Typography variant="body2" sx={{ fontWeight: 600 }}>
                      Rate Limiting
                    </Typography>
                    <Typography variant="caption">
                      Default: 100 requests per minute per agent
                    </Typography>
                  </Alert>
                </Grid>
                <Grid size={{ xs: 12, sm: 6 }}>
                  <Alert severity="success">
                    <Typography variant="body2" sx={{ fontWeight: 600 }}>
                      Policies Applied
                    </Typography>
                    <Typography variant="caption">
                      {agent.policies.length} policies enforced on all requests
                    </Typography>
                  </Alert>
                </Grid>
                <Grid size={{ xs: 12, sm: 6 }}>
                  <Alert severity="error">
                    <Typography variant="body2" sx={{ fontWeight: 600 }}>
                      Suspension
                    </Typography>
                    <Typography variant="caption">
                      Use "Suspend" to immediately block all requests
                    </Typography>
                  </Alert>
                </Grid>
              </Grid>
            </Paper>
          </Grid>
        </Grid>
      )}

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

export default MCPAgentDetail;