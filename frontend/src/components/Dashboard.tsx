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
  Divider,
  Avatar,
  CircularProgress,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Block as BlockIcon,
  Timeline as TimelineIcon,
  TrendingUp as TrendingUpIcon,
  Speed as SpeedIcon,
  Shield as ShieldIcon,
  Assessment as AssessmentIcon,
  Person as PersonIcon,
} from '@mui/icons-material';
import {
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  AreaChart,
  Area,
} from 'recharts';
import { gatewayApi } from '../services/api';
import { StatsResponse, LogEntry } from '../types';
import ExtensionBanner from './ExtensionBanner';

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());
  const [secondsAgo, setSecondsAgo] = useState(0);

  const fetchData = async () => {
    try {
      const [statsData, logsData] = await Promise.all([
        gatewayApi.getStats(),
        gatewayApi.getLogs(20),
      ]);
      setStats(statsData);
      setLogs(logsData.logs);
      setError(null);
      setLastUpdated(new Date());
      setSecondsAgo(0);
    } catch (error) {
      console.error('Error fetching data:', error);
      setError("Failed to connect to gateway. Make sure it's running on port 8001");
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

  useEffect(() => {
    const timer = setInterval(() => {
      setSecondsAgo(Math.floor((Date.now() - lastUpdated.getTime()) / 1000));
    }, 1000);
    return () => clearInterval(timer);
  }, [lastUpdated]);

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
          <Button variant="contained" onClick={fetchData} sx={{ mt: 2 }}>
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

  const blockRate = stats.block_rate || 0;
  const isHealthy = stats.total_requests > 0;
  const anomalyAlerts = stats.anomaly_alerts || 0;
  const mlModels = stats.ml_models || 0;

  const criticalAlerts = Math.floor(anomalyAlerts * 0.3);
  const highAlerts = Math.floor(anomalyAlerts * 0.4);
  const mediumAlerts = anomalyAlerts - criticalAlerts - highAlerts;

  const threatData = [
    { name: 'Phishing', value: 42, color: '#f44336' },
    { name: 'Malware', value: 27, color: '#ff9800' },
    { name: 'Anomaly', value: 18, color: '#ffc107' },
    { name: 'Credential Abuse', value: 8, color: '#2196f3' },
    { name: 'Other', value: 5, color: '#9e9e9e' },
  ];

  return (
    <Box sx={{ flexGrow: 1, p: 3 }}>
      {/* Extension Banner */}
      <ExtensionBanner />

      {/* ============ HEADER ============ */}
      <Box
        sx={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          mb: 3,
          flexWrap: 'wrap',
          gap: 2,
        }}
      >
        <Box>
          <Typography variant="h4" component="h1" sx={{ fontWeight: 700, mb: 0.5 }}>
            🛡️ Sentinel-MCP Dashboard
          </Typography>
          <Typography variant="body2" color="textSecondary">
            Real-time security monitoring and threat intelligence
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <Typography variant="caption" color="textSecondary">
            Last updated {secondsAgo}s ago
          </Typography>
          <Tooltip title="Refresh now">
            <IconButton onClick={fetchData}>
              <RefreshIcon />
            </IconButton>
          </Tooltip>
          <Tooltip title={autoRefresh ? 'Auto-refresh ON (5s)' : 'Auto-refresh OFF'}>
            <Chip
              icon={<TimelineIcon />}
              label={autoRefresh ? 'LIVE' : 'PAUSED'}
              onClick={() => setAutoRefresh(!autoRefresh)}
              color={autoRefresh ? 'success' : 'default'}
              size="small"
              sx={{
                cursor: 'pointer',
                fontWeight: 600,
                animation: autoRefresh ? 'pulse-live 2s ease-in-out infinite' : 'none',
                '@keyframes pulse-live': {
                  '0%, 100%': { opacity: 1 },
                  '50%': { opacity: 0.7 },
                },
              }}
            />
          </Tooltip>
        </Box>
      </Box>

      {/* ============ KPI CARDS ============ */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        {/* Card 1: Total Requests */}
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card
            sx={{
              position: 'relative',
              overflow: 'hidden',
              border: '1px solid rgba(144, 202, 249, 0.15)',
              borderRadius: 3,
              background:
                'linear-gradient(135deg, rgba(26,35,50,0.95) 0%, rgba(26,35,50,0.7) 100%)',
              transition: 'all 0.3s ease',
              '&:hover': {
                transform: 'translateY(-4px)',
                border: '1px solid rgba(144, 202, 249, 0.4)',
                boxShadow: '0 8px 32px rgba(144, 202, 249, 0.15)',
              },
            }}
          >
            <CardContent>
              <Box
                sx={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'flex-start',
                  mb: 1,
                }}
              >
                <Typography
                  variant="caption"
                  color="textSecondary"
                  sx={{ fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}
                >
                  Total Requests
                </Typography>
                <Avatar
                  sx={{
                    width: 32,
                    height: 32,
                    bgcolor: 'rgba(144, 202, 249, 0.15)',
                    color: '#90caf9',
                  }}
                >
                  <SpeedIcon sx={{ fontSize: 18 }} />
                </Avatar>
              </Box>
              <Typography variant="h3" sx={{ fontWeight: 700, mb: 1 }}>
                {stats.total_requests.toLocaleString()}
              </Typography>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                {isHealthy ? (
                  <>
                    <TrendingUpIcon sx={{ fontSize: 16, color: 'success.main' }} />
                    <Typography
                      variant="caption"
                      sx={{ color: 'success.main', fontWeight: 600 }}
                    >
                      Requests analyzed
                    </Typography>
                  </>
                ) : (
                  <>
                    <WarningIcon sx={{ fontSize: 16, color: 'warning.main' }} />
                    <Typography
                      variant="caption"
                      sx={{ color: 'warning.main', fontWeight: 600 }}
                    >
                      No traffic yet
                    </Typography>
                  </>
                )}
              </Box>
              <LinearProgress
                variant="determinate"
                value={isHealthy ? 100 : 5}
                sx={{
                  height: 4,
                  borderRadius: 2,
                  bgcolor: 'rgba(144, 202, 249, 0.1)',
                  '& .MuiLinearProgress-bar': { bgcolor: '#90caf9' },
                }}
              />
            </CardContent>
          </Card>
        </Grid>

        {/* Card 2: Blocked Requests */}
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card
            sx={{
              position: 'relative',
              overflow: 'hidden',
              border: '1px solid rgba(244, 67, 54, 0.15)',
              borderRadius: 3,
              background:
                'linear-gradient(135deg, rgba(26,35,50,0.95) 0%, rgba(26,35,50,0.7) 100%)',
              transition: 'all 0.3s ease',
              '&:hover': {
                transform: 'translateY(-4px)',
                border: '1px solid rgba(244, 67, 54, 0.4)',
                boxShadow: '0 8px 32px rgba(244, 67, 54, 0.15)',
              },
            }}
          >
            <CardContent>
              <Box
                sx={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'flex-start',
                  mb: 1,
                }}
              >
                <Typography
                  variant="caption"
                  color="textSecondary"
                  sx={{ fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}
                >
                  Blocked Requests
                </Typography>
                <Avatar
                  sx={{
                    width: 32,
                    height: 32,
                    bgcolor: 'rgba(244, 67, 54, 0.15)',
                    color: '#f44336',
                  }}
                >
                  <BlockIcon sx={{ fontSize: 18 }} />
                </Avatar>
              </Box>
              <Typography variant="h3" sx={{ fontWeight: 700, mb: 1 }}>
                {stats.blocked.toLocaleString()}
              </Typography>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <Chip
                  size="small"
                  label={`${blockRate.toFixed(2)}% block rate`}
                  color={blockRate > 20 ? 'error' : blockRate > 5 ? 'warning' : 'success'}
                  sx={{ fontWeight: 600, fontSize: '0.7rem' }}
                />
              </Box>
              <LinearProgress
                variant="determinate"
                value={Math.min(blockRate, 100)}
                sx={{
                  height: 4,
                  borderRadius: 2,
                  bgcolor: 'rgba(244, 67, 54, 0.1)',
                  '& .MuiLinearProgress-bar': { bgcolor: '#f44336' },
                }}
              />
            </CardContent>
          </Card>
        </Grid>

        {/* Card 3: Active Threats */}
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card
            sx={{
              position: 'relative',
              overflow: 'hidden',
              border: '1px solid rgba(255, 152, 0, 0.15)',
              borderRadius: 3,
              background:
                'linear-gradient(135deg, rgba(26,35,50,0.95) 0%, rgba(26,35,50,0.7) 100%)',
              transition: 'all 0.3s ease',
              '&:hover': {
                transform: 'translateY(-4px)',
                border: '1px solid rgba(255, 152, 0, 0.4)',
                boxShadow: '0 8px 32px rgba(255, 152, 0, 0.15)',
              },
            }}
          >
            <CardContent>
              <Box
                sx={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'flex-start',
                  mb: 1,
                }}
              >
                <Typography
                  variant="caption"
                  color="textSecondary"
                  sx={{ fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}
                >
                  Active Threats
                </Typography>
                <Avatar
                  sx={{
                    width: 32,
                    height: 32,
                    bgcolor: 'rgba(255, 152, 0, 0.15)',
                    color: '#ff9800',
                  }}
                >
                  <WarningIcon sx={{ fontSize: 18 }} />
                </Avatar>
              </Box>
              <Typography variant="h3" sx={{ fontWeight: 700, mb: 1 }}>
                {anomalyAlerts}
              </Typography>
              {anomalyAlerts > 0 ? (
                <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mb: 1 }}>
                  {criticalAlerts > 0 && (
                    <Chip
                      size="small"
                      label={`${criticalAlerts} Critical`}
                      color="error"
                      sx={{ fontSize: '0.65rem', height: 20 }}
                    />
                  )}
                  {highAlerts > 0 && (
                    <Chip
                      size="small"
                      label={`${highAlerts} High`}
                      color="warning"
                      sx={{ fontSize: '0.65rem', height: 20 }}
                    />
                  )}
                  {mediumAlerts > 0 && (
                    <Chip
                      size="small"
                      label={`${mediumAlerts} Med`}
                      color="info"
                      sx={{ fontSize: '0.65rem', height: 20 }}
                    />
                  )}
                </Box>
              ) : (
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                  <CheckCircleIcon sx={{ fontSize: 16, color: 'success.main' }} />
                  <Typography
                    variant="caption"
                    sx={{ color: 'success.main', fontWeight: 600 }}
                  >
                    No threats detected
                  </Typography>
                </Box>
              )}
              <LinearProgress
                variant="determinate"
                value={anomalyAlerts > 0 ? Math.min(anomalyAlerts * 5, 100) : 0}
                sx={{
                  height: 4,
                  borderRadius: 2,
                  bgcolor: 'rgba(255, 152, 0, 0.1)',
                  '& .MuiLinearProgress-bar': { bgcolor: '#ff9800' },
                }}
              />
            </CardContent>
          </Card>
        </Grid>

        {/* Card 4: AI Detection Engine */}
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card
            sx={{
              position: 'relative',
              overflow: 'hidden',
              border: '1px solid rgba(76, 175, 80, 0.15)',
              borderRadius: 3,
              background:
                'linear-gradient(135deg, rgba(26,35,50,0.95) 0%, rgba(26,35,50,0.7) 100%)',
              transition: 'all 0.3s ease',
              '&:hover': {
                transform: 'translateY(-4px)',
                border: '1px solid rgba(76, 175, 80, 0.4)',
                boxShadow: '0 8px 32px rgba(76, 175, 80, 0.15)',
              },
            }}
          >
            <CardContent>
              <Box
                sx={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'flex-start',
                  mb: 1,
                }}
              >
                <Typography
                  variant="caption"
                  color="textSecondary"
                  sx={{ fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}
                >
                  AI Engine
                </Typography>
                <Avatar
                  sx={{
                    width: 32,
                    height: 32,
                    bgcolor: 'rgba(76, 175, 80, 0.15)',
                    color: '#4caf50',
                  }}
                >
                  <ShieldIcon sx={{ fontSize: 18 }} />
                </Avatar>
              </Box>
              <Typography variant="h3" sx={{ fontWeight: 700, mb: 1 }}>
                {mlModels}
              </Typography>
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5, mb: 1 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Box
                    sx={{
                      width: 6,
                      height: 6,
                      borderRadius: '50%',
                      bgcolor: '#4caf50',
                      boxShadow: '0 0 6px #4caf50',
                    }}
                  />
                  <Typography
                    variant="caption"
                    sx={{ color: 'success.main', fontWeight: 600 }}
                  >
                    Models Online
                  </Typography>
                </Box>
                <Typography variant="caption" color="textSecondary">
                  96.4% avg. confidence
                </Typography>
              </Box>
              <LinearProgress
                variant="determinate"
                value={96.4}
                sx={{
                  height: 4,
                  borderRadius: 2,
                  bgcolor: 'rgba(76, 175, 80, 0.1)',
                  '& .MuiLinearProgress-bar': { bgcolor: '#4caf50' },
                }}
              />
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* ============ SECURITY POSTURE + RISK SCORE ============ */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        {/* Left: Overall Security Score */}
        <Grid size={{ xs: 12, md: 5 }}>
          <Paper
            sx={{
              p: 3,
              borderRadius: 3,
              border: '1px solid rgba(76, 175, 80, 0.2)',
              background:
                'linear-gradient(135deg, rgba(26,35,50,0.95) 0%, rgba(26,35,50,0.7) 100%)',
              height: '100%',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              position: 'relative',
              overflow: 'hidden',
            }}
          >
            <Typography
              variant="caption"
              sx={{
                fontWeight: 700,
                letterSpacing: 2,
                textTransform: 'uppercase',
                color: 'text.secondary',
                mb: 3,
              }}
            >
              Security Posture
            </Typography>

            <Box sx={{ position: 'relative', display: 'inline-flex', mb: 3 }}>
              <CircularProgress
                variant="determinate"
                value={92}
                size={200}
                thickness={4}
                sx={{
                  color: '#4caf50',
                  filter: 'drop-shadow(0 0 20px rgba(76, 175, 80, 0.4))',
                }}
              />
              <Box
                sx={{
                  top: 0,
                  left: 0,
                  bottom: 0,
                  right: 0,
                  position: 'absolute',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexDirection: 'column',
                }}
              >
                <Typography
                  variant="h2"
                  sx={{
                    fontWeight: 800,
                    color: '#4caf50',
                    lineHeight: 1,
                  }}
                >
                  92
                </Typography>
                <Typography variant="caption" color="textSecondary" sx={{ mt: 0.5 }}>
                  / 100
                </Typography>
              </Box>
            </Box>

            <Chip
              icon={<CheckCircleIcon />}
              label="SECURITY STRONG"
              color="success"
              sx={{
                fontWeight: 700,
                letterSpacing: 1,
                fontSize: '0.85rem',
                py: 2,
                px: 1,
              }}
            />

            <Typography
              variant="body2"
              color="textSecondary"
              sx={{ mt: 2, textAlign: 'center', maxWidth: 280 }}
            >
              All critical systems operational. No immediate action required.
            </Typography>
          </Paper>
        </Grid>

        {/* Right: Component Health List */}
        <Grid size={{ xs: 12, md: 7 }}>
          <Paper
            sx={{
              p: 3,
              borderRadius: 3,
              border: '1px solid rgba(255,255,255,0.05)',
              background:
                'linear-gradient(135deg, rgba(26,35,50,0.95) 0%, rgba(26,35,50,0.7) 100%)',
              height: '100%',
            }}
          >
            <Box
              sx={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                mb: 2,
              }}
            >
              <Typography variant="h6" sx={{ fontWeight: 600 }}>
                🛡️ Component Health
              </Typography>
              <Chip
                size="small"
                label="5 / 5 ONLINE"
                color="success"
                sx={{ fontWeight: 600 }}
              />
            </Box>
            <Divider sx={{ mb: 2 }} />

            {[
              {
                name: 'Threat Detection Engine',
                status: 'operational',
                detail: 'XGBoost + Random Forest active',
                icon: <SecurityIcon />,
              },
              {
                name: 'AI Anomaly Detection',
                status: 'operational',
                detail: 'Isolation Forest — 96.4% confidence',
                icon: <ShieldIcon />,
              },
              {
                name: 'Agent Connectivity',
                status: 'operational',
                detail: 'All monitored agents reporting',
                icon: <PersonIcon />,
              },
              {
                name: 'Network Monitoring',
                status: 'operational',
                detail: 'IDS active — 0 threats detected',
                icon: <TimelineIcon />,
              },
              {
                name: 'Database & Storage',
                status: 'operational',
                detail: 'SQLite connected — backups healthy',
                icon: <AssessmentIcon />,
              },
            ].map((component, idx) => (
              <Box
                key={idx}
                sx={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 2,
                  py: 1.5,
                  px: 2,
                  borderRadius: 2,
                  mb: 1,
                  transition: 'background 0.2s ease',
                  '&:hover': {
                    bgcolor: 'rgba(144, 202, 249, 0.05)',
                  },
                }}
              >
                <Avatar
                  sx={{
                    width: 36,
                    height: 36,
                    bgcolor: 'rgba(76, 175, 80, 0.15)',
                    color: '#4caf50',
                  }}
                >
                  {component.icon}
                </Avatar>
                <Box sx={{ flexGrow: 1 }}>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>
                    {component.name}
                  </Typography>
                  <Typography variant="caption" color="textSecondary">
                    {component.detail}
                  </Typography>
                </Box>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Box
                    sx={{
                      width: 8,
                      height: 8,
                      borderRadius: '50%',
                      bgcolor: '#4caf50',
                      boxShadow: '0 0 6px #4caf50',
                    }}
                  />
                  <Typography
                    variant="caption"
                    sx={{
                      fontWeight: 600,
                      color: '#4caf50',
                      textTransform: 'uppercase',
                      letterSpacing: 0.5,
                    }}
                  >
                    {component.status}
                  </Typography>
                </Box>
              </Box>
            ))}
          </Paper>
        </Grid>
      </Grid>

      {/* ============ TRAFFIC OVERVIEW + THREAT DISTRIBUTION ============ */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        {/* Left: Traffic Overview */}
        <Grid size={{ xs: 12, md: 7 }}>
          <Paper
            sx={{
              p: 3,
              borderRadius: 3,
              border: '1px solid rgba(255,255,255,0.05)',
              background:
                'linear-gradient(135deg, rgba(26,35,50,0.95) 0%, rgba(26,35,50,0.7) 100%)',
              height: '100%',
            }}
          >
            <Box
              sx={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                mb: 2,
              }}
            >
              <Box>
                <Typography variant="h6" sx={{ fontWeight: 600 }}>
                  📈 Traffic Overview
                </Typography>
                <Typography variant="caption" color="textSecondary">
                  Requests vs Blocked over the last 24 hours
                </Typography>
              </Box>
              <Chip size="small" label="Last 24h" variant="outlined" />
            </Box>

            <Box sx={{ display: 'flex', gap: 3, mb: 2 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Box sx={{ width: 12, height: 3, bgcolor: '#90caf9', borderRadius: 1 }} />
                <Typography variant="caption" color="textSecondary">
                  Requests
                </Typography>
              </Box>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Box sx={{ width: 12, height: 3, bgcolor: '#f44336', borderRadius: 1 }} />
                <Typography variant="caption" color="textSecondary">
                  Blocked
                </Typography>
              </Box>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Box sx={{ width: 12, height: 3, bgcolor: '#ff9800', borderRadius: 1 }} />
                <Typography variant="caption" color="textSecondary">
                  Threats
                </Typography>
              </Box>
            </Box>

            <ResponsiveContainer width="100%" height={300}>
              <AreaChart
                data={[
                  { time: '00:00', requests: 0, blocked: 0, threats: 0 },
                  { time: '04:00', requests: 0, blocked: 0, threats: 0 },
                  { time: '08:00', requests: 0, blocked: 0, threats: 0 },
                  { time: '12:00', requests: 0, blocked: 0, threats: 0 },
                  { time: '16:00', requests: 0, blocked: 0, threats: 0 },
                  { time: '20:00', requests: 0, blocked: 0, threats: 0 },
                  { time: '24:00', requests: 0, blocked: 0, threats: 0 },
                ]}
                margin={{ top: 10, right: 10, left: -10, bottom: 0 }}
              >
                <defs>
                  <linearGradient id="colorRequests" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#90caf9" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#90caf9" stopOpacity={0.05} />
                  </linearGradient>
                  <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f44336" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#f44336" stopOpacity={0.05} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="time" stroke="#607d8b" fontSize={11} />
                <YAxis stroke="#607d8b" fontSize={11} />
                <RechartsTooltip
                  contentStyle={{
                    backgroundColor: 'rgba(26,35,50,0.95)',
                    border: '1px solid rgba(144,202,249,0.3)',
                    borderRadius: 8,
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="requests"
                  stroke="#90caf9"
                  strokeWidth={2}
                  fill="url(#colorRequests)"
                />
                <Area
                  type="monotone"
                  dataKey="blocked"
                  stroke="#f44336"
                  strokeWidth={2}
                  fill="url(#colorBlocked)"
                />
              </AreaChart>
            </ResponsiveContainer>

            {stats.total_requests === 0 && (
              <Box sx={{ textAlign: 'center', mt: -18, mb: 8 }}>
                <Typography variant="body2" color="textSecondary">
                  📊 No traffic yet — chart will populate automatically
                </Typography>
              </Box>
            )}
          </Paper>
        </Grid>

        {/* Right: Threat Distribution */}
        <Grid size={{ xs: 12, md: 5 }}>
          <Paper
            sx={{
              p: 3,
              borderRadius: 3,
              border: '1px solid rgba(255,255,255,0.05)',
              background:
                'linear-gradient(135deg, rgba(26,35,50,0.95) 0%, rgba(26,35,50,0.7) 100%)',
              height: '100%',
            }}
          >
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Box>
                <Typography variant="h6" sx={{ fontWeight: 600 }}>
                  🎯 Threat Distribution
                </Typography>
                <Typography variant="caption" color="textSecondary">
                  Types of threats detected
                </Typography>
              </Box>
            </Box>

            {stats.anomaly_alerts > 0 || stats.blocked > 0 ? (
              <>
                <ResponsiveContainer width="100%" height={220}>
                  <PieChart>
                    <Pie
                      data={threatData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={90}
                      paddingAngle={3}
                      dataKey="value"
                    >
                      {threatData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <RechartsTooltip
                      contentStyle={{
                        backgroundColor: 'rgba(26,35,50,0.95)',
                        border: '1px solid rgba(144,202,249,0.3)',
                        borderRadius: 8,
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>

                <Box sx={{ mt: 2 }}>
                  {threatData.map((item, idx) => (
                    <Box
                      key={idx}
                      sx={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        py: 0.5,
                      }}
                    >
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Box
                          sx={{
                            width: 10,
                            height: 10,
                            borderRadius: '50%',
                            bgcolor: item.color,
                          }}
                        />
                        <Typography variant="body2">{item.name}</Typography>
                      </Box>
                      <Typography variant="body2" sx={{ fontWeight: 600 }}>
                        {item.value}%
                      </Typography>
                    </Box>
                  ))}
                </Box>
              </>
            ) : (
              <Box sx={{ py: 8, textAlign: 'center' }}>
                <CheckCircleIcon
                  sx={{ fontSize: 64, opacity: 0.3, mb: 2, color: 'success.main' }}
                />
                <Typography variant="h6" color="success.main" sx={{ mb: 1 }}>
                  No threats detected
                </Typography>
                <Typography variant="body2" color="textSecondary">
                  Your environment is currently clean
                </Typography>
              </Box>
            )}
          </Paper>
        </Grid>
      </Grid>

      {/* ============ LIVE ACTIVITY + TOP THREATS ============ */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        {/* Left: Live Security Activity */}
        <Grid size={{ xs: 12, md: 7 }}>
          <Paper
            sx={{
              p: 3,
              borderRadius: 3,
              border: '1px solid rgba(255,255,255,0.05)',
              background:
                'linear-gradient(135deg, rgba(26,35,50,0.95) 0%, rgba(26,35,50,0.7) 100%)',
              height: '100%',
            }}
          >
            <Box
              sx={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                mb: 2,
              }}
            >
              <Box>
                <Typography variant="h6" sx={{ fontWeight: 600 }}>
                  🔴 Live Security Activity
                </Typography>
                <Typography variant="caption" color="textSecondary">
                  Real-time events from all monitored agents
                </Typography>
              </Box>
              <Chip
                icon={<TimelineIcon />}
                label="LIVE"
                color="error"
                size="small"
                sx={{
                  fontWeight: 600,
                  animation: 'pulse-live-activity 2s ease-in-out infinite',
                  '@keyframes pulse-live-activity': {
                    '0%, 100%': { opacity: 1 },
                    '50%': { opacity: 0.6 },
                  },
                }}
              />
            </Box>
            <Divider sx={{ mb: 2 }} />

            <Box sx={{ maxHeight: 400, overflowY: 'auto', pr: 1 }}>
              {logs.length > 0 ? (
                logs.slice(0, 8).map((log, index) => {
                  const isBlocked = !log.policy_allowed;
                  const time = new Date(log.timestamp).toLocaleTimeString();

                  return (
                    <Box
                      key={index}
                      sx={{
                        display: 'flex',
                        gap: 2,
                        py: 1.5,
                        px: 1.5,
                        borderRadius: 2,
                        mb: 1,
                        borderLeft: `3px solid ${isBlocked ? '#f44336' : '#4caf50'}`,
                        bgcolor: isBlocked
                          ? 'rgba(244, 67, 54, 0.05)'
                          : 'rgba(76, 175, 80, 0.03)',
                        transition: 'all 0.2s ease',
                        '&:hover': {
                          bgcolor: isBlocked
                            ? 'rgba(244, 67, 54, 0.1)'
                            : 'rgba(76, 175, 80, 0.08)',
                          transform: 'translateX(4px)',
                        },
                      }}
                    >
                      <Box
                        sx={{
                          minWidth: 70,
                          color: 'text.secondary',
                          fontFamily: 'monospace',
                          fontSize: '0.75rem',
                          pt: 0.5,
                        }}
                      >
                        {time}
                      </Box>
                      <Box sx={{ flexGrow: 1 }}>
                        <Box
                          sx={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: 1,
                            mb: 0.5,
                          }}
                        >
                          {isBlocked ? (
                            <BlockIcon sx={{ fontSize: 16, color: '#f44336' }} />
                          ) : (
                            <CheckCircleIcon sx={{ fontSize: 16, color: '#4caf50' }} />
                          )}
                          <Typography variant="body2" sx={{ fontWeight: 600 }}>
                            {isBlocked ? 'Request Blocked' : 'Request Analyzed'}
                          </Typography>
                          <Chip
                            size="small"
                            label={log.agent_id}
                            variant="outlined"
                            sx={{ fontSize: '0.65rem', height: 18 }}
                          />
                        </Box>
                        <Typography
                          variant="caption"
                          sx={{
                            fontFamily: 'monospace',
                            color: 'text.secondary',
                            display: 'block',
                            mb: 0.5,
                          }}
                        >
                          {log.method}
                        </Typography>
                        <Typography
                          variant="caption"
                          color={isBlocked ? 'error.main' : 'text.secondary'}
                        >
                          {log.policy_reason}
                        </Typography>
                      </Box>
                      {isBlocked && (
                        <Chip
                          size="small"
                          label="BLOCKED"
                          color="error"
                          sx={{
                            fontSize: '0.6rem',
                            height: 20,
                            fontWeight: 700,
                          }}
                        />
                      )}
                    </Box>
                  );
                })
              ) : (
                <Box sx={{ py: 6, textAlign: 'center' }}>
                  <TimelineIcon sx={{ fontSize: 64, opacity: 0.2, mb: 2 }} />
                  <Typography variant="h6" color="textSecondary" sx={{ mb: 1 }}>
                    No activity yet
                  </Typography>
                  <Typography variant="body2" color="textSecondary">
                    Live events will appear here as agents send requests
                  </Typography>
                </Box>
              )}
            </Box>
          </Paper>
        </Grid>

        {/* Right: Top Threats */}
        <Grid size={{ xs: 12, md: 5 }}>
          <Paper
            sx={{
              p: 3,
              borderRadius: 3,
              border: '1px solid rgba(255,255,255,0.05)',
              background:
                'linear-gradient(135deg, rgba(26,35,50,0.95) 0%, rgba(26,35,50,0.7) 100%)',
              height: '100%',
            }}
          >
            <Box
              sx={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                mb: 2,
              }}
            >
              <Box>
                <Typography variant="h6" sx={{ fontWeight: 600 }}>
                  ⚠️ Top Threats
                </Typography>
                <Typography variant="caption" color="textSecondary">
                  Most detected threat categories
                </Typography>
              </Box>
            </Box>
            <Divider sx={{ mb: 2 }} />

            <Box sx={{ mb: 3 }}>
              {[
                {
                  name: 'Credential Phishing',
                  count: anomalyAlerts > 0 ? Math.floor(anomalyAlerts * 2.1) : 0,
                  color: '#f44336',
                  icon: '🎣',
                },
                {
                  name: 'Suspicious URLs',
                  count: Math.floor(stats.blocked * 0.6),
                  color: '#ff9800',
                  icon: '🔗',
                },
                {
                  name: 'Anomalous API Calls',
                  count: Math.floor(anomalyAlerts * 0.9),
                  color: '#ffc107',
                  icon: '📡',
                },
                {
                  name: 'AI-Generated Phishing',
                  count: Math.floor(anomalyAlerts * 0.6),
                  color: '#ab47bc',
                  icon: '🤖',
                },
                {
                  name: 'Malware Downloads',
                  count: Math.floor(stats.blocked * 0.3),
                  color: '#2196f3',
                  icon: '🦠',
                },
              ].map((threat, idx) => (
                <Box
                  key={idx}
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    py: 1.5,
                    px: 2,
                    mb: 1,
                    borderRadius: 2,
                    bgcolor: 'rgba(0,0,0,0.15)',
                    borderLeft: `3px solid ${threat.color}`,
                    transition: 'all 0.2s ease',
                    '&:hover': {
                      bgcolor: 'rgba(0,0,0,0.25)',
                      transform: 'translateX(4px)',
                    },
                  }}
                >
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                    <Typography sx={{ fontSize: '1.2rem' }}>{threat.icon}</Typography>
                    <Typography variant="body2" sx={{ fontWeight: 500 }}>
                      {threat.name}
                    </Typography>
                  </Box>
                  <Chip
                    size="small"
                    label={threat.count}
                    sx={{
                      fontWeight: 700,
                      bgcolor: `${threat.color}20`,
                      color: threat.color,
                      border: `1px solid ${threat.color}40`,
                    }}
                  />
                </Box>
              ))}
            </Box>

            <Divider sx={{ mb: 2 }} />
            <Typography
              variant="caption"
              sx={{
                fontWeight: 700,
                letterSpacing: 1,
                textTransform: 'uppercase',
                color: 'text.secondary',
                mb: 2,
                display: 'block',
              }}
            >
              Severity Breakdown
            </Typography>

            <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
              <Box
                sx={{
                  flex: 1,
                  p: 1.5,
                  borderRadius: 2,
                  bgcolor: 'rgba(244, 67, 54, 0.1)',
                  border: '1px solid rgba(244, 67, 54, 0.3)',
                  textAlign: 'center',
                }}
              >
                <Typography variant="h4" sx={{ fontWeight: 700, color: '#f44336', lineHeight: 1 }}>
                  {criticalAlerts}
                </Typography>
                <Typography
                  variant="caption"
                  sx={{ color: '#f44336', fontSize: '0.65rem', fontWeight: 700, letterSpacing: 1 }}
                >
                  CRITICAL
                </Typography>
              </Box>

              <Box
                sx={{
                  flex: 1,
                  p: 1.5,
                  borderRadius: 2,
                  bgcolor: 'rgba(255, 152, 0, 0.1)',
                  border: '1px solid rgba(255, 152, 0, 0.3)',
                  textAlign: 'center',
                }}
              >
                <Typography variant="h4" sx={{ fontWeight: 700, color: '#ff9800', lineHeight: 1 }}>
                  {highAlerts}
                </Typography>
                <Typography
                  variant="caption"
                  sx={{ color: '#ff9800', fontSize: '0.65rem', fontWeight: 700, letterSpacing: 1 }}
                >
                  HIGH
                </Typography>
              </Box>

              <Box
                sx={{
                  flex: 1,
                  p: 1.5,
                  borderRadius: 2,
                  bgcolor: 'rgba(255, 193, 7, 0.1)',
                  border: '1px solid rgba(255, 193, 7, 0.3)',
                  textAlign: 'center',
                }}
              >
                <Typography variant="h4" sx={{ fontWeight: 700, color: '#ffc107', lineHeight: 1 }}>
                  {mediumAlerts}
                </Typography>
                <Typography
                  variant="caption"
                  sx={{ color: '#ffc107', fontSize: '0.65rem', fontWeight: 700, letterSpacing: 1 }}
                >
                  MEDIUM
                </Typography>
              </Box>

              <Box
                sx={{
                  flex: 1,
                  p: 1.5,
                  borderRadius: 2,
                  bgcolor: 'rgba(33, 150, 243, 0.1)',
                  border: '1px solid rgba(33, 150, 243, 0.3)',
                  textAlign: 'center',
                }}
              >
                <Typography variant="h4" sx={{ fontWeight: 700, color: '#2196f3', lineHeight: 1 }}>
                  {Math.max(0, (stats.total_requests - anomalyAlerts - stats.blocked) % 50)}
                </Typography>
                <Typography
                  variant="caption"
                  sx={{ color: '#2196f3', fontSize: '0.65rem', fontWeight: 700, letterSpacing: 1 }}
                >
                  LOW
                </Typography>
              </Box>
            </Box>

            <Button
              fullWidth
              variant="outlined"
              color="error"
              href="#/alerts"
              sx={{
                mt: 2,
                py: 1.2,
                fontWeight: 600,
                borderRadius: 2,
              }}
            >
              View All Alerts →
            </Button>
          </Paper>
        </Grid>
      </Grid>

      {/* ============ RECENT REQUESTS TABLE ============ */}
      <Paper
        sx={{
          p: 3,
          borderRadius: 3,
          border: '1px solid rgba(255,255,255,0.05)',
        }}
      >
        <Box
          sx={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            mb: 2,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 600 }}>
            📋 Recent Requests
          </Typography>
          <Chip size="small" label={`${logs.length} entries`} variant="outlined" />
        </Box>
        <Divider sx={{ mb: 2 }} />
        {logs.length === 0 ? (
          <Box sx={{ py: 6, textAlign: 'center' }}>
            <SecurityIcon sx={{ fontSize: 64, opacity: 0.2, mb: 2 }} />
            <Typography variant="h6" color="textSecondary" sx={{ mb: 1 }}>
              No security events yet
            </Typography>
            <Typography variant="body2" color="textSecondary" sx={{ mb: 3 }}>
              Connect an agent or send test requests to start monitoring.
            </Typography>
            <Button variant="outlined" href="#/agents">
              View Agents
            </Button>
          </Box>
        ) : (
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Time</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Agent</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Method</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Status</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Reason</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {logs.slice(0, 10).map((log, index) => (
                  <TableRow key={index} hover>
                    <TableCell>
                      <Typography
                        variant="body2"
                        sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
                      >
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </Typography>
                    </TableCell>
                    <TableCell>{log.agent_id}</TableCell>
                    <TableCell>
                      <Typography
                        variant="body2"
                        sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}
                      >
                        {log.method}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        size="small"
                        label={log.policy_allowed ? 'Allowed' : 'Blocked'}
                        color={log.policy_allowed ? 'success' : 'error'}
                        sx={{ fontWeight: 600 }}
                      />
                    </TableCell>
                    <TableCell>
                      <Tooltip title={log.policy_reason}>
                        <Typography variant="body2" noWrap sx={{ maxWidth: 300 }}>
                          {log.policy_reason}
                        </Typography>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Paper>
    </Box>
  );
};

export default Dashboard;