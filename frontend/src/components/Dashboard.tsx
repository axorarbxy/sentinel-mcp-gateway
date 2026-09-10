// components/Dashboard.tsx
import React, { useEffect, useState } from 'react';
import {
  Card,
  CardContent,
  Typography,
  Grid,
  Box,
  LinearProgress,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  IconButton,
  Tooltip,
  Button,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Block as BlockIcon,
  Timeline as TimelineIcon,
} from '@mui/icons-material';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { gatewayApi } from '../services/api';
import { StatsResponse, LogEntry } from '../types';
import ExtensionBanner from './ExtensionBanner';

const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884d8'];

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    try {
      const [statsData, logsData] = await Promise.all([
        gatewayApi.getStats(),
        gatewayApi.getLogs(20),
      ]);
      setStats(statsData);
      setLogs(logsData.logs);
      setError(null);
    } catch (error) {
      console.error('Error fetching data:', error);
      setError('Failed to connect to gateway. Make sure it\'s running on port 8001');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    let interval: NodeJS.Timeout;
    if (autoRefresh) {
      interval = setInterval(fetchData, 5000);
    }
    return () => clearInterval(interval);
  }, [autoRefresh]);

  if (loading) {
    return (
      <Box sx={{ width: '100%', mt: 4 }}>
        <LinearProgress />
        <Typography align="center" sx={{ mt: 2 }}>
          Loading Sentinel-MCP Dashboard...
        </Typography>
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ p: 3 }}>
        <Paper sx={{ p: 4, textAlign: 'center' }}>
          <WarningIcon sx={{ fontSize: 48, color: 'warning.main', mb: 2 }} />
          <Typography variant="h6" color="error">
            {error}
          </Typography>
          <Button
            variant="contained"
            onClick={fetchData}
            sx={{ mt: 2 }}
          >
            Retry
          </Button>
        </Paper>
      </Box>
    );
  }

  if (!stats) {
    return (
      <Typography align="center" sx={{ mt: 4, color: 'error.main' }}>
        Failed to load data. Is the gateway running?
      </Typography>
    );
  }

  const methodData = Object.entries(stats.methods || {}).map(([name, value]) => ({
    name: name.split('/')[0] || name,
    value,
  }));

  const blockRate = stats.block_rate || 0;
  const isHealthy = stats.total_requests > 0;

  return (
    <Box sx={{ flexGrow: 1, p: 3 }}>
      {/* Extension Banner */}
      <ExtensionBanner />

      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1">
          🛡️ Sentinel-MCP Dashboard
        </Typography>
        <Box>
          <Tooltip title="Refresh">
            <IconButton onClick={fetchData}>
              <RefreshIcon />
            </IconButton>
          </Tooltip>
          <Tooltip title={autoRefresh ? 'Auto-refresh on' : 'Auto-refresh off'}>
            <IconButton onClick={() => setAutoRefresh(!autoRefresh)} color={autoRefresh ? 'primary' : 'default'}>
              <TimelineIcon />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>

      {/* Stats Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Total Requests
              </Typography>
              <Typography variant="h4">{stats.total_requests}</Typography>
              <Chip
                size="small"
                icon={isHealthy ? <CheckCircleIcon /> : <WarningIcon />}
                label={isHealthy ? 'Active' : 'No traffic'}
                color={isHealthy ? 'success' : 'warning'}
              />
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Blocked Requests
              </Typography>
              <Typography variant="h4">{stats.blocked}</Typography>
              <Chip
                size="small"
                icon={<BlockIcon />}
                label={`${blockRate.toFixed(1)}% block rate`}
                color={blockRate > 20 ? 'error' : blockRate > 5 ? 'warning' : 'success'}
              />
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Anomaly Alerts
              </Typography>
              <Typography variant="h4">{stats.anomaly_alerts || 0}</Typography>
              <Chip
                size="small"
                icon={<WarningIcon />}
                label={`${stats.ml_models || 0} ML models`}
                color={stats.anomaly_alerts > 0 ? 'error' : 'default'}
              />
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                ML Models
              </Typography>
              <Typography variant="h4">{stats.ml_models || 0}</Typography>
              <Chip
                size="small"
                icon={<SecurityIcon />}
                label="Active"
                color="primary"
              />
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Charts */}
      <Grid container spacing={3}>
        <Grid size={{ xs: 12, md: 6 }}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Request Methods Distribution
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={methodData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent = 0 }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {methodData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <RechartsTooltip />
              </PieChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>
        <Grid size={{ xs: 12, md: 6 }}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Method Frequency
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={methodData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <RechartsTooltip />
                <Bar dataKey="value" fill="#8884d8">
                  {methodData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>
      </Grid>

      {/* Recent Logs */}
      <Paper sx={{ p: 2, mt: 3 }}>
        <Typography variant="h6" gutterBottom>
          Recent Requests
        </Typography>
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Time</TableCell>
                <TableCell>Agent</TableCell>
                <TableCell>Method</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Reason</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {logs.slice(0, 10).map((log, index) => (
                <TableRow key={index}>
                  <TableCell>
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </TableCell>
                  <TableCell>{log.agent_id}</TableCell>
                  <TableCell>{log.method}</TableCell>
                  <TableCell>
                    <Chip
                      size="small"
                      label={log.policy_allowed ? 'Allowed' : 'Blocked'}
                      color={log.policy_allowed ? 'success' : 'error'}
                    />
                  </TableCell>
                  <TableCell>
                    <Tooltip title={log.policy_reason}>
                      <Typography variant="body2" noWrap sx={{ maxWidth: 200 }}>
                        {log.policy_reason}
                      </Typography>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>
    </Box>
  );
};

export default Dashboard;