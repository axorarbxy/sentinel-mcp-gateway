// pages/MCPPolicyDetail.tsx
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
  TextField,
  Alert,
  Snackbar,
  CircularProgress,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Switch,
  FormControlLabel,
  List,
  ListItem,
  ListItemText,
  ListItemAvatar,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from '@mui/material';
import {
  ArrowBack as ArrowBackIcon,
  Security as SecurityIcon,
  Save as SaveIcon,
  Refresh as RefreshIcon,
  Delete as DeleteIcon,
  PlayArrow as PlayArrowIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  ExpandMore as ExpandMoreIcon,
  Folder as FolderIcon,
  Terminal as TerminalIcon,
  Storage as StorageIcon,
  NetworkCheck as NetworkIcon,
  Speed as SpeedIcon,
  Code as CodeIcon,
} from '@mui/icons-material';
import { useParams, useNavigate } from 'react-router-dom';

const API_URL = 'http://localhost:8001';

// ============ TYPES ============
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

// ============ RULE TEMPLATES ============
const RULE_TEMPLATES: Record<string, { label: string; description: string; config: Record<string, any>; icon: React.ReactNode }> = {
  path_traversal: {
    label: 'Path Traversal',
    description: 'Block access to sensitive system files',
    icon: <FolderIcon />,
    config: {
      blocked_paths: ['/etc/passwd', '/etc/shadow', '/root/', '.env', '.git/', 'id_rsa'],
      allow_read_only: true,
    },
  },
  command_whitelist: {
    label: 'Command Whitelist',
    description: 'Only allow safe shell commands',
    icon: <TerminalIcon />,
    config: {
      allowed_commands: ['ls', 'pwd', 'whoami', 'cat', 'echo', 'date'],
      block_sudo: true,
      block_rm_rf: true,
    },
  },
  sql_injection: {
    label: 'SQL Injection',
    description: 'Detect dangerous SQL patterns',
    icon: <StorageIcon />,
    config: {
      blocked_keywords: ['DROP', 'DELETE', 'TRUNCATE', 'ALTER', 'GRANT'],
      allow_select: true,
    },
  },
  network_restriction: {
    label: 'Network Restriction',
    description: 'Block access to internal networks',
    icon: <NetworkIcon />,
    config: {
      blocked_networks: ['192.168.*', '10.*', '172.16.*', 'localhost', '127.0.0.1'],
      allowed_domains: [],
    },
  },
  rate_limit: {
    label: 'Rate Limit',
    description: 'Limit requests per time window',
    icon: <SpeedIcon />,
    config: {
      max_requests: 100,
      window_seconds: 60,
    },
  },
};

// ============ MAIN COMPONENT ============
const MCPPolicyDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [policy, setPolicy] = useState<MCPPolicy | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testInput, setTestInput] = useState('');
  const [testResult, setTestResult] = useState<{ status: string; reason: string } | null>(null);
  const [snackbar, setSnackbar] = useState({
    open: false,
    message: '',
    severity: 'info' as 'success' | 'error' | 'info' | 'warning',
  });

  const showSnackbar = (message: string, severity: 'success' | 'error' | 'info' | 'warning') => {
    setSnackbar({ open: true, message, severity });
  };

  // ============ FETCH POLICY ============
  const fetchPolicy = async () => {
    try {
      const res = await fetch(`${API_URL}/mcp/policies`);
      if (res.ok) {
        const policies: MCPPolicy[] = await res.json();
        const found = policies.find((p) => p.id === Number(id));
        if (found) {
          setPolicy(found);
        } else {
          showSnackbar('Policy not found', 'error');
          setTimeout(() => navigate('/mcp'), 2000);
        }
      }
    } catch (error) {
      console.error('Fetch error:', error);
      showSnackbar('Failed to fetch policy', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPolicy();
  }, [id]);

  // ============ ACTIONS ============
  const handleToggle = async () => {
    if (!policy) return;
    try {
      await fetch(`${API_URL}/mcp/policies/${policy.id}/toggle`, { method: 'PUT' });
      showSnackbar(`Policy ${policy.is_enabled ? 'disabled' : 'enabled'}`, 'success');
      fetchPolicy();
    } catch {
      showSnackbar('Failed to toggle policy', 'error');
    }
  };

  const handleDelete = async () => {
    if (!policy) return;
    if (!window.confirm(`Delete policy "${policy.name}"? This cannot be undone.`)) return;
    try {
      await fetch(`${API_URL}/mcp/policies/${policy.id}`, { method: 'DELETE' });
      showSnackbar('Policy deleted', 'success');
      setTimeout(() => navigate('/mcp'), 1000);
    } catch {
      showSnackbar('Failed to delete policy', 'error');
    }
  };

  const handleTestPolicy = () => {
    if (!policy) return;
    if (!testInput.trim()) {
      showSnackbar('Enter test input', 'warning');
      return;
    }

    // Simulate policy testing (client-side)
    const config = policy.config as Record<string, any>;
    let blocked = false;
    let reason = 'Allowed — no matching rule';

    if (policy.rule_type === 'path_traversal') {
      const blockedPaths = config.blocked_paths || [];
      for (const path of blockedPaths) {
        if (testInput.includes(path)) {
          blocked = true;
          reason = `Blocked: matches "${path}"`;
          break;
        }
      }
    } else if (policy.rule_type === 'command_whitelist') {
      const allowedCommands = config.allowed_commands || [];
      const command = testInput.trim().split(' ')[0];
      if (!allowedCommands.includes(command)) {
        blocked = true;
        reason = `Blocked: command "${command}" not whitelisted`;
      }
    } else if (policy.rule_type === 'sql_injection') {
      const blockedKeywords = config.blocked_keywords || [];
      for (const keyword of blockedKeywords) {
        if (testInput.toUpperCase().includes(keyword)) {
          blocked = true;
          reason = `Blocked: contains "${keyword}"`;
          break;
        }
      }
    } else if (policy.rule_type === 'network_restriction') {
      const blockedNetworks = config.blocked_networks || [];
      for (const network of blockedNetworks) {
        const pattern = network.replace('*', '');
        if (testInput.includes(pattern)) {
          blocked = true;
          reason = `Blocked: matches network "${network}"`;
          break;
        }
      }
    }

    setTestResult({
      status: blocked ? 'BLOCKED' : 'ALLOWED',
      reason,
    });
  };

  // ============ COMPUTED ============
  const template = policy ? RULE_TEMPLATES[policy.rule_type] : null;
  const config = policy?.config || {};

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '80vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  if (!policy) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">Policy not found</Alert>
      </Box>
    );
  }

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
      case 'high':
        return '#f44336';
      case 'medium':
        return '#ff9800';
      case 'low':
        return '#2196f3';
      default:
        return '#9e9e9e';
    }
  };

  return (
    <Box sx={{ p: 3, maxWidth: 1400, mx: 'auto' }}>
      {/* Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
        <IconButton onClick={() => navigate('/mcp')} size="large">
          <ArrowBackIcon />
        </IconButton>
        <Box sx={{ flexGrow: 1 }}>
          <Typography variant="h4" sx={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1 }}>
            <SecurityIcon sx={{ fontSize: 32 }} />
            {policy.name}
          </Typography>
          <Typography variant="body2" color="textSecondary">
            {policy.description || 'No description'}
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="Refresh">
            <IconButton onClick={fetchPolicy}>
              <RefreshIcon />
            </IconButton>
          </Tooltip>
          <Button
            variant="outlined"
            onClick={handleToggle}
            color={policy.is_enabled ? 'warning' : 'success'}
          >
            {policy.is_enabled ? 'Disable' : 'Enable'}
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
          bgcolor: policy.is_enabled ? 'rgba(76,175,80,0.1)' : 'rgba(158,158,158,0.1)',
          border: `1px solid ${policy.is_enabled ? 'rgba(76,175,80,0.3)' : 'rgba(158,158,158,0.3)'}`,
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
          <Box
            sx={{
              width: 10,
              height: 10,
              borderRadius: '50%',
              bgcolor: policy.is_enabled ? '#4caf50' : '#9e9e9e',
              boxShadow: policy.is_enabled ? '0 0 10px #4caf50' : 'none',
            }}
          />
          <Typography variant="body2" sx={{ fontWeight: 600 }}>
            {policy.is_enabled ? 'Policy is ENABLED and actively enforcing' : 'Policy is DISABLED'}
          </Typography>
          <Chip
            label={`${policy.rule_type.replace('_', ' ').toUpperCase()}`}
            size="small"
            variant="outlined"
          />
          <Chip
            label={policy.severity.toUpperCase()}
            size="small"
            sx={{
              bgcolor: `${getSeverityColor(policy.severity)}20`,
              color: getSeverityColor(policy.severity),
              border: `1px solid ${getSeverityColor(policy.severity)}40`,
              fontWeight: 700,
            }}
          />
          <Typography variant="caption" color="textSecondary" sx={{ ml: 'auto' }}>
            Created: {new Date(policy.created_at).toLocaleString()}
          </Typography>
        </Box>
      </Paper>

      {/* Main Grid */}
      <Grid container spacing={3}>
        {/* Left Column: Configuration */}
        <Grid size={{ xs: 12, md: 7 }}>
          <Paper sx={{ p: 3, mb: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
              {template?.icon}
              <Typography variant="h6">Configuration</Typography>
            </Box>
            <Divider sx={{ mb: 2 }} />

            <Alert severity="info" sx={{ mb: 3 }}>
              {template?.description || 'Policy configuration'}
            </Alert>

            {/* Config Display */}
            <Box
              sx={{
                p: 2,
                bgcolor: 'rgba(0,0,0,0.3)',
                borderRadius: 2,
                fontFamily: 'monospace',
                fontSize: '0.85rem',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
              }}
            >
              {JSON.stringify(config, null, 2)}
            </Box>
          </Paper>

          {/* Policy Testing */}
          <Paper sx={{ p: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
              <PlayArrowIcon color="primary" />
              <Typography variant="h6">Test Policy</Typography>
            </Box>
            <Divider sx={{ mb: 2 }} />

            <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>
              Enter a sample input to test how this policy would evaluate it
            </Typography>

            <TextField
              fullWidth
              multiline
              rows={2}
              placeholder={
                policy.rule_type === 'path_traversal'
                  ? 'e.g., /etc/passwd'
                  : policy.rule_type === 'command_whitelist'
                  ? 'e.g., ls -la'
                  : policy.rule_type === 'sql_injection'
                  ? 'e.g., SELECT * FROM users WHERE id=1'
                  : 'Enter test input'
              }
              value={testInput}
              onChange={(e) => setTestInput(e.target.value)}
              sx={{ mb: 2 }}
            />

            <Box sx={{ display: 'flex', gap: 1 }}>
              <Button variant="contained" startIcon={<PlayArrowIcon />} onClick={handleTestPolicy}>
                Test Policy
              </Button>
              <Button
                variant="outlined"
                onClick={() => {
                  setTestInput('');
                  setTestResult(null);
                }}
              >
                Clear
              </Button>
            </Box>

            {testResult && (
              <Alert
                severity={testResult.status === 'BLOCKED' ? 'error' : 'success'}
                sx={{ mt: 2 }}
              >
                <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                  {testResult.status}
                </Typography>
                <Typography variant="body2">{testResult.reason}</Typography>
              </Alert>
            )}
          </Paper>
        </Grid>

        {/* Right Column: Info + Rules */}
        <Grid size={{ xs: 12, md: 5 }}>
          {/* Policy Info */}
          <Paper sx={{ p: 3, mb: 3 }}>
            <Typography variant="h6" gutterBottom>
              Policy Information
            </Typography>
            <Divider sx={{ mb: 2 }} />

            <List dense>
              <ListItem>
                <ListItemAvatar>
                  <Avatar sx={{ bgcolor: 'primary.main' }}>
                    <CodeIcon />
                  </Avatar>
                </ListItemAvatar>
                <ListItemText primary="Rule Type" secondary={policy.rule_type} />
              </ListItem>

              <ListItem>
                <ListItemAvatar>
                  <Avatar sx={{ bgcolor: getSeverityColor(policy.severity) }}>
                    <WarningIcon />
                  </Avatar>
                </ListItemAvatar>
                <ListItemText primary="Severity" secondary={policy.severity.toUpperCase()} />
              </ListItem>

              <ListItem>
                <ListItemAvatar>
                  <Avatar sx={{ bgcolor: policy.is_enabled ? '#4caf50' : '#9e9e9e' }}>
                    {policy.is_enabled ? <CheckCircleIcon /> : <ErrorIcon />}
                  </Avatar>
                </ListItemAvatar>
                <ListItemText
                  primary="Status"
                  secondary={policy.is_enabled ? 'Enabled' : 'Disabled'}
                />
              </ListItem>

              <ListItem>
                <ListItemAvatar>
                  <Avatar sx={{ bgcolor: '#2196f3' }}>
                    <InfoIcon />
                  </Avatar>
                </ListItemAvatar>
                <ListItemText
                  primary="Policy ID"
                  secondary={`#${policy.id}`}
                />
              </ListItem>
            </List>
          </Paper>

          {/* Rules Preview */}
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Rules Applied
            </Typography>
            <Divider sx={{ mb: 2 }} />

            {Object.entries(config).map(([key, value], idx) => (
              <Accordion key={idx} sx={{ bgcolor: 'rgba(0,0,0,0.2)', mb: 1 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>
                    {key.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())}
                  </Typography>
                </AccordionSummary>
                <AccordionDetails>
                  {Array.isArray(value) ? (
                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                      {value.map((item, i) => (
                        <Chip key={i} size="small" label={String(item)} />
                      ))}
                    </Box>
                  ) : (
                    <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                      {String(value)}
                    </Typography>
                  )}
                </AccordionDetails>
              </Accordion>
            ))}
          </Paper>
        </Grid>
      </Grid>

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

export default MCPPolicyDetail;