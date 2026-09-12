import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Avatar, Box, Card, CardContent, Chip, Divider, Grid, IconButton, LinearProgress, Paper, Tooltip, Typography } from '@mui/material';
import { Block as BlockIcon, CheckCircle as CheckCircleIcon, ErrorOutlined as ErrorIcon, Hub as HubIcon, Refresh as RefreshIcon, Security as SecurityIcon, Timeline as TimelineIcon, Warning as WarningIcon } from '@mui/icons-material';
import { Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip as ChartTooltip, XAxis, YAxis } from 'recharts';
import { gatewayApi } from '../services/api';
import { Alert, LogEntry, StatsResponse } from '../types';
import useLiveTraffic from '../hooks/useLiveTraffic';
import ExtensionBanner from './ExtensionBanner';

const COLORS = ['#ff9800', '#ab47bc'];

const formatAge = (timestamp?: string) => {
  if (!timestamp) return 'No events received';
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(timestamp).getTime()) / 1000));
  return seconds < 60 ? `${seconds}s ago` : `${Math.floor(seconds / 60)}m ago`;
};

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { connected, events } = useLiveTraffic();

  const fetchData = useCallback(async () => {
    try {
      const [statsData, logsData, alertsData] = await Promise.all([
        gatewayApi.getStats(), gatewayApi.getLogs(200), gatewayApi.getAnomalies(200),
      ]);
      setStats(statsData);
      setLogs(logsData.logs);
      setAlerts(alertsData.alerts);
      setError(null);
    } catch {
      setError('Unable to reach the gateway on port 8001.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const poll = window.setInterval(fetchData, 10_000);
    return () => window.clearInterval(poll);
  }, [fetchData]);

  useEffect(() => {
    if (events.length) fetchData();
  }, [events.length, fetchData]);

  const traffic = useMemo(() => {
    const buckets = new Map<string, { time: string; events: number; blocked: number }>();
    logs.forEach((log) => {
      const date = new Date(log.timestamp);
      const key = `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}-${date.getHours()}`;
      const item = buckets.get(key) || { time: date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }), events: 0, blocked: 0 };
      item.events += 1;
      if (!log.policy_allowed || log.analysis_anomaly || log.ml_anomaly) item.blocked += 1;
      buckets.set(key, item);
    });
    return [...buckets.values()].slice(-24);
  }, [logs]);

  const detections = useMemo(() => [
    { name: 'Rule detections', value: alerts.filter((alert) => alert.type === 'rule_based').length },
    { name: 'Behavioral anomalies', value: alerts.filter((alert) => alert.type === 'ml_based').length },
  ].filter((item) => item.value > 0), [alerts]);

  if (loading) return <LinearProgress sx={{ mt: 4 }} />;
  if (error || !stats) return <Paper sx={{ p: 4, m: 3, textAlign: 'center' }}><ErrorIcon color="error" sx={{ fontSize: 44 }} /><Typography variant="h6" sx={{ mt: 1 }}>{error || 'Gateway data is unavailable.'}</Typography><IconButton aria-label="Retry" onClick={fetchData}><RefreshIcon /></IconButton></Paper>;

  const lastEvent = events[0]?.timestamp || logs[logs.length - 1]?.timestamp;
  const blockRate = Math.min(100, Math.max(0, stats.block_rate || 0));
  const metricCards = [
    { label: 'Events', value: stats.total_requests, hint: 'Current gateway process window', color: '#90caf9', icon: <TimelineIcon /> },
    { label: 'Blocked requests', value: stats.blocked || 0, hint: `${blockRate.toFixed(1)}% of observed events`, color: '#ef5350', icon: <BlockIcon /> },
    { label: 'Security detections', value: stats.anomaly_alerts || 0, hint: 'Rule and behavior signals only', color: '#ffb74d', icon: <WarningIcon /> },
    { label: 'Detection engines', value: stats.ml_models || 0, hint: 'Behavioral models currently trained', color: '#81c784', icon: <SecurityIcon /> },
  ];

  return <Box sx={{ p: 3 }}>
    <ExtensionBanner />
    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3, gap: 2, flexWrap: 'wrap' }}>
      <Box><Typography variant="h4" sx={{ fontWeight: 700 }}>Sentinel-MCP</Typography><Typography color="text.secondary">AI agent runtime security and MCP request protection</Typography></Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><Tooltip title="Refresh data"><IconButton onClick={fetchData}><RefreshIcon /></IconButton></Tooltip><Chip icon={<HubIcon />} label={connected ? `LIVE · last event ${formatAge(lastEvent)}` : 'RECONNECTING · telemetry unavailable'} color={connected ? 'success' : 'warning'} variant="outlined" /></Box>
    </Box>

    <Paper sx={{ p: 2, mb: 3, borderLeft: `4px solid ${connected ? '#4caf50' : '#ff9800'}` }}>
      <Typography variant="overline">Protection status</Typography><Typography variant="h6">{connected ? 'Telemetry connected' : 'Telemetry connection unavailable'}</Typography>
      <Typography variant="body2" color="text.secondary">{connected ? `WebSocket connected. Last event ${formatAge(lastEvent)}.` : 'REST data may still be available; live event updates will resume when the gateway reconnects.'}</Typography>
    </Paper>

    <Grid container spacing={2} sx={{ mb: 3 }}>{metricCards.map((card) => <Grid key={card.label} size={{ xs: 12, sm: 6, md: 3 }}><Card><CardContent><Box sx={{ display: 'flex', justifyContent: 'space-between' }}><Typography variant="overline">{card.label}</Typography><Avatar sx={{ bgcolor: `${card.color}22`, color: card.color }}>{card.icon}</Avatar></Box><Typography variant="h3" sx={{ fontWeight: 700 }}>{card.value.toLocaleString()}</Typography><Typography variant="caption" color="text.secondary">{card.hint}</Typography></CardContent></Card></Grid>)}</Grid>

    <Grid container spacing={3} sx={{ mb: 3 }}>
      <Grid size={{ xs: 12, md: 7 }}><Paper sx={{ p: 3, height: 360 }}><Typography variant="h6">Traffic observed by the gateway</Typography><Typography variant="caption" color="text.secondary">Actual request logs; only populated while the gateway is running.</Typography>{traffic.length ? <ResponsiveContainer width="100%" height={270}><AreaChart data={traffic}><defs><linearGradient id="events" x1="0" x2="0" y1="0" y2="1"><stop offset="5%" stopColor="#90caf9" stopOpacity={.45}/><stop offset="95%" stopColor="#90caf9" stopOpacity={0}/></linearGradient></defs><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="time" /><YAxis allowDecimals={false} /><ChartTooltip /><Area type="monotone" dataKey="events" stroke="#90caf9" fill="url(#events)" name="Events" /><Area type="monotone" dataKey="blocked" stroke="#ef5350" fill="none" name="Blocked" /></AreaChart></ResponsiveContainer> : <Box sx={{ height: 260, display: 'grid', placeItems: 'center' }}><Typography color="text.secondary">No traffic has been recorded yet.</Typography></Box>}</Paper></Grid>
      <Grid size={{ xs: 12, md: 5 }}><Paper sx={{ p: 3, height: 360 }}><Typography variant="h6">Detection sources</Typography><Typography variant="caption" color="text.secondary">Security signals only—protocol errors are excluded.</Typography>{detections.length ? <><ResponsiveContainer width="100%" height={220}><PieChart><Pie data={detections} dataKey="value" nameKey="name" innerRadius={55} outerRadius={85}>{detections.map((_, i) => <Cell key={i} fill={COLORS[i]} />)}</Pie><ChartTooltip /></PieChart></ResponsiveContainer>{detections.map((item, i) => <Box key={item.name} sx={{ display: 'flex', justifyContent: 'space-between', py: .5 }}><Typography><Box component="span" sx={{ color: COLORS[i] }}>● </Box>{item.name}</Typography><Typography sx={{ fontWeight: 700 }}>{item.value}</Typography></Box>)}</> : <Box sx={{ height: 260, display: 'grid', placeItems: 'center' }}><Typography color="text.secondary">No security detections recorded.</Typography></Box>}</Paper></Grid>
    </Grid>

    <Paper sx={{ p: 3 }}><Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}><Box><Typography variant="h6">Recent gateway events</Typography><Typography variant="caption" color="text.secondary">Security enforcement and protocol/system events are labeled separately.</Typography></Box><Chip size="small" label={connected ? 'LIVE' : 'OFFLINE'} color={connected ? 'success' : 'default'} /></Box><Divider />
      {logs.length ? logs.slice(-12).reverse().map((log, index) => { const blocked = !log.policy_allowed || log.analysis_anomaly || log.ml_anomaly; const system = log.event_category === 'system'; return <Box key={log.event_id || `${log.timestamp}-${index}`} sx={{ display: 'flex', alignItems: 'center', gap: 1.5, py: 1.25, borderBottom: '1px solid', borderColor: 'divider' }}>{blocked ? <BlockIcon color={system ? 'warning' : 'error'} /> : <CheckCircleIcon color="success" />}<Box sx={{ flex: 1, minWidth: 0 }}><Typography sx={{ fontWeight: 600 }}>{log.method} <Typography component="span" variant="caption" color="text.secondary">· {log.agent_id}</Typography></Typography><Typography variant="caption" color="text.secondary">{log.policy_reason}</Typography></Box><Chip size="small" label={system ? 'SYSTEM' : blocked ? 'BLOCKED' : 'ALLOWED'} color={system ? 'warning' : blocked ? 'error' : 'success'} /><Typography variant="caption" color="text.secondary">{new Date(log.timestamp).toLocaleTimeString()}</Typography></Box>; }) : <Box sx={{ py: 5, textAlign: 'center' }}><Typography color="text.secondary">Events will appear as agents send MCP requests.</Typography></Box>}
    </Paper>
  </Box>;
};

export default Dashboard;
