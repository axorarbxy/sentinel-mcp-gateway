// pages/MCPServerDetail.tsx
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
  Alert,
  Snackbar,
  CircularProgress,
  List,
  ListItem,
  ListItemText,
  ListItemAvatar,
} from '@mui/material';
import {
  ArrowBack as ArrowBackIcon,
  Storage as StorageIcon,
  Refresh as RefreshIcon,
  Delete as DeleteIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Cloud as CloudIcon,
  Folder as FolderIcon,
  Terminal as TerminalIcon,
  NetworkCheck as NetworkIcon,
  Code as CodeIcon,
  Speed as SpeedIcon,
  Public as PublicIcon,
  Timeline as TimelineIcon,
} from '@mui/icons-material';
import { useParams, useNavigate } from 'react-router-dom';

const API_URL = 'http://localhost:8001';

// ============ TYPES ============
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

// ============ HELPERS ============
const getServerTypeIcon = (type: string) => {
  switch (type) {
    case 'filesystem':
      return <FolderIcon />;
    case 'database':
      return <StorageIcon />;
    case 'shell':
      return <TerminalIcon />;
    case 'network':
      return <NetworkIcon />;
    default:
      return <CodeIcon />;
  }
};

const getServerTypeDescription = (type: string) => {
  switch (type) {
    case 'filesystem':
      return 'Provides file system access to AI agents';
    case 'database':
      return 'Provides database query capabilities';
    case 'shell':
      return 'Provides shell command execution';
    case 'network':
      return 'Provides network resource access';
    default:
      return 'Custom MCP server';
  }
};

// ============ MAIN COMPONENT ============
const MCPServerDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [server, setServer] = useState<MCPServer | null>(null);
  const [loading, setLoading] = useState(true);
  const [checking, setChecking] = useState(false);
  const [snackbar, setSnackbar] = useState({
    open: false,
    message: '',
    severity: 'info' as 'success' | 'error' | 'info' | 'warning',
  });

  const showSnackbar = (message: string, severity: 'success' | 'error' | 'info' | 'warning') => {
    setSnackbar({ open: true, message, severity });
  };

  // ============ FETCH SERVER ============
  const fetchServer = async () => {
    try {
      const res = await fetch(`${API_URL}/mcp/servers`);
      if (res.ok) {
        const servers: MCPServer[] = await res.json();
        const found = servers.find((s) => s.id === Number(id));
        if (found) {
          setServer(found);
        } else {
          showSnackbar('Server not found', 'error');
          setTimeout(() => navigate('/mcp'), 2000);
        }
      }
    } catch (error) {
      console.error('Fetch error:', error);
      showSnackbar('Failed to fetch server', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchServer();
    const interval = setInterval(fetchServer, 15000);
    return () => clearInterval(interval);
  }, [id]);

  // ============ ACTIONS ============
  const handleHealthCheck = async () => {
    if (!server) return;
    setChecking(true);
    try {
      const res = await fetch(`${API_URL}/mcp/servers/${server.id}/health`, {
        method: 'POST',
      });
      if (res.ok) {
        const data = await res.json();
        showSnackbar(
          `Health check: ${data.status.toUpperCase()}`,
          data.status === 'online' ? 'success' : 'error'
        );
        fetchServer();
      }
    } catch {
      showSnackbar('Health check failed', 'error');
    } finally {
      setChecking(false);
    }
  };

  const handleDelete = async () => {
    if (!server) return;
    if (!window.confirm(`Delete server "${server.name}"? This cannot be undone.`)) return;
    try {
      await fetch(`${API_URL}/mcp/servers/${server.id}`, { method: 'DELETE' });
      showSnackbar('Server deleted', 'success');
      setTimeout(() => navigate('/mcp'), 1000);
    } catch {
      showSnackbar('Failed to delete server', 'error');
    }
  };

  const copyUrl = () => {
    if (!server) return;
    navigator.clipboard.writeText(server.url);
    showSnackbar('URL copied to clipboard', 'success');
  };

  // ============ COMPUTED ============
  const getHealthColor = (status: string) => {
    switch (status) {
      case 'online':
        return { color: '#4caf50', bg: 'rgba(76,175,80,0.1)', border: 'rgba(76,175,80,0.3)' };
      case 'offline':
        return { color: '#f44336', bg: 'rgba(244,67,54,0.1)', border: 'rgba(244,67,54,0.3)' };
      default:
        return { color: '#9e9e9e', bg: 'rgba(158,158,158,0.1)', border: 'rgba(158,158,158,0.3)' };
    }
  };

  const getHealthIcon = (status: string) => {
    switch (status) {
      case 'online':
        return <CheckCircleIcon />;
      case 'offline':
        return <ErrorIcon />;
      default:
        return <WarningIcon />;
    }
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '80vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  if (!server) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">Server not found</Alert>
      </Box>
    );
  }

  const healthConfig = getHealthColor(server.health_status);

  return (
    <Box sx={{ p: 3, maxWidth: 1400, mx: 'auto' }}>
      {/* Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
        <IconButton onClick={() => navigate('/mcp')} size="large">
          <ArrowBackIcon />
        </IconButton>
        <Box sx={{ flexGrow: 1 }}>
          <Typography variant="h4" sx={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1 }}>
            {getServerTypeIcon(server.server_type)}
            {server.name}
          </Typography>
          <Typography variant="body2" color="textSecondary">
            {server.description || 'No description provided'}
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="Refresh">
            <IconButton onClick={fetchServer}>
              <RefreshIcon />
            </IconButton>
          </Tooltip>
          <Button
            variant="contained"
            startIcon={checking ? <CircularProgress size={20} color="inherit" /> : <SpeedIcon />}
            onClick={handleHealthCheck}
            disabled={checking}
            color="primary"
          >
            {checking ? 'Checking...' : 'Health Check'}
          </Button>
          <Button variant="outlined" color="error" startIcon={<DeleteIcon />} onClick={handleDelete}>
            Delete
          </Button>
        </Box>
      </Box>

      {/* Health Status Banner */}
      <Paper
        sx={{
          p: 2,
          mb: 3,
          bgcolor: healthConfig.bg,
          border: `1px solid ${healthConfig.border}`,
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
          <Box
            sx={{
              width: 10,
              height: 10,
              borderRadius: '50%',
              bgcolor: healthConfig.color,
              boxShadow: `0 0 10px ${healthConfig.color}`,
              animation: server.health_status === 'online' ? 'pulse 2s infinite' : 'none',
              '@keyframes pulse': {
                '0%, 100%': { opacity: 1 },
                '50%': { opacity: 0.4 },
              },
            }}
          />
          <Typography variant="body2" sx={{ fontWeight: 600, color: healthConfig.color }}>
            Server is {server.health_status.toUpperCase()}
          </Typography>
          <Chip
            size="small"
            label={server.server_type.toUpperCase()}
            variant="outlined"
          />
          <Chip
            size="small"
            label={server.is_active ? 'ACTIVE' : 'DISABLED'}
            color={server.is_active ? 'success' : 'default'}
          />
          <Typography variant="caption" color="textSecondary" sx={{ ml: 'auto' }}>
            {server.last_health_check
              ? `Last checked: ${new Date(server.last_health_check).toLocaleString()}`
              : 'Never checked'}
          </Typography>
        </Box>
      </Paper>

      {/* KPI Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card sx={{ bgcolor: 'rgba(26,35,50,0.8)', border: '1px solid rgba(144,202,249,0.15)' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <PublicIcon color="primary" />
                <Typography variant="caption" color="textSecondary">
                  SERVER URL
                </Typography>
              </Box>
              <Typography
                variant="caption"
                sx={{
                  fontFamily: 'monospace',
                  wordBreak: 'break-all',
                  display: 'block',
                  fontSize: '0.75rem',
                }}
              >
                {server.url}
              </Typography>
              <Button size="small" sx={{ mt: 1 }} onClick={copyUrl}>
                Copy URL
              </Button>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card sx={{ bgcolor: 'rgba(26,35,50,0.8)', border: `1px solid ${healthConfig.border}` }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                {getHealthIcon(server.health_status)}
                <Typography variant="caption" color="textSecondary">
                  HEALTH
                </Typography>
              </Box>
              <Typography variant="h4" sx={{ fontWeight: 700, color: healthConfig.color }}>
                {server.health_status.toUpperCase()}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card sx={{ bgcolor: 'rgba(26,35,50,0.8)', border: '1px solid rgba(255,152,0,0.15)' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                {getServerTypeIcon(server.server_type)}
                <Typography variant="caption" color="textSecondary">
                  TYPE
                </Typography>
              </Box>
              <Typography variant="h6" sx={{ fontWeight: 700, textTransform: 'capitalize' }}>
                {server.server_type}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card sx={{ bgcolor: 'rgba(26,35,50,0.8)', border: '1px solid rgba(76,175,80,0.15)' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <TimelineIcon sx={{ color: '#4caf50' }} />
                <Typography variant="caption" color="textSecondary">
                  UPTIME
                </Typography>
              </Box>
              <Typography variant="h6" sx={{ fontWeight: 700, color: '#4caf50' }}>
                Active
              </Typography>
              <Typography variant="caption" color="textSecondary">
                Since {new Date(server.created_at).toLocaleDateString()}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Server Info + Details */}
      <Grid container spacing={3}>
        <Grid size={{ xs: 12, md: 6 }}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Server Information
            </Typography>
            <Divider sx={{ mb: 2 }} />

            <List>
              <ListItem>
                <ListItemAvatar>
                  <Avatar sx={{ bgcolor: 'primary.main' }}>
                    <CloudIcon />
                  </Avatar>
                </ListItemAvatar>
                <ListItemText primary="Server ID" secondary={`#${server.id}`} />
              </ListItem>

              <ListItem>
                <ListItemAvatar>
                  <Avatar sx={{ bgcolor: '#2196f3' }}>{getServerTypeIcon(server.server_type)}</Avatar>
                </ListItemAvatar>
                <ListItemText
                  primary="Server Type"
                  secondary={getServerTypeDescription(server.server_type)}
                />
              </ListItem>

              <ListItem>
                <ListItemAvatar>
                  <Avatar sx={{ bgcolor: 'primary.main' }}>
                    <PublicIcon />
                  </Avatar>
                </ListItemAvatar>
                <ListItemText primary="URL" secondary={server.url} />
              </ListItem>

              <ListItem>
                <ListItemAvatar>
                  <Avatar sx={{ bgcolor: healthConfig.color }}>
                    {getHealthIcon(server.health_status)}
                  </Avatar>
                </ListItemAvatar>
                <ListItemText
                  primary="Health Status"
                  secondary={server.health_status.toUpperCase()}
                />
              </ListItem>

              <ListItem>
                <ListItemAvatar>
                  <Avatar sx={{ bgcolor: '#9e9e9e' }}>
                    <TimelineIcon />
                  </Avatar>
                </ListItemAvatar>
                <ListItemText
                  primary="Created"
                  secondary={new Date(server.created_at).toLocaleString()}
                />
              </ListItem>
            </List>
          </Paper>
        </Grid>

        <Grid size={{ xs: 12, md: 6 }}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Connection Details
            </Typography>
            <Divider sx={{ mb: 2 }} />

            <Box sx={{ mb: 3 }}>
              <Typography variant="caption" color="textSecondary">
                Endpoint URL
              </Typography>
              <Box
                sx={{
                  p: 2,
                  bgcolor: 'rgba(0,0,0,0.3)',
                  borderRadius: 2,
                  fontFamily: 'monospace',
                  fontSize: '0.85rem',
                  wordBreak: 'break-all',
                  color: '#90caf9',
                  mt: 1,
                }}
              >
                {server.url}
              </Box>
            </Box>

            <Box sx={{ mb: 3 }}>
              <Typography variant="caption" color="textSecondary">
                Health Endpoint
              </Typography>
              <Box
                sx={{
                  p: 2,
                  bgcolor: 'rgba(0,0,0,0.3)',
                  borderRadius: 2,
                  fontFamily: 'monospace',
                  fontSize: '0.85rem',
                  wordBreak: 'break-all',
                  color: '#90caf9',
                  mt: 1,
                }}
              >
                {server.url}/health
              </Box>
            </Box>

            <Alert severity="info">
              <Typography variant="caption">
                The gateway will proxy all agent requests to this server. Ensure it is reachable from the gateway's network.
              </Typography>
            </Alert>

            <Button
              fullWidth
              variant="contained"
              startIcon={checking ? <CircularProgress size={20} color="inherit" /> : <SpeedIcon />}
              onClick={handleHealthCheck}
              disabled={checking}
              sx={{ mt: 3 }}
            >
              {checking ? 'Testing Connection...' : 'Test Connection Now'}
            </Button>
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

export default MCPServerDetail;