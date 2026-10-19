import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Avatar, Box, Button, Card, CardContent, Chip, Divider, FormControl, Grid, IconButton, InputLabel, LinearProgress, MenuItem, Paper, Select, Tooltip, Typography } from '@mui/material';
import { Block as BlockIcon, CheckCircle as CheckCircleIcon, ErrorOutlined as ErrorIcon, Hub as HubIcon, Refresh as RefreshIcon, Security as SecurityIcon, Timeline as TimelineIcon, Warning as WarningIcon } from '@mui/icons-material';
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip as ChartTooltip, XAxis, YAxis } from 'recharts';
import { gatewayApi, gatewayFetch } from '../services/api';
import { LogEntry, StatsResponse } from '../types';
import useLiveTraffic, { ObservableFeatureFamilies, TrafficEvent } from '../hooks/useLiveTraffic';
import ExtensionBanner from './ExtensionBanner';
import { API_BASE_URL as API_URL } from '../services/urls';

const DETECTION_CATEGORIES = [
  { name: 'SQL injection', color: '#ef5350' },
  { name: 'Path traversal', color: '#ff9800' },
  { name: 'Tool policy violations', color: '#ab47bc' },
  { name: 'ML payload detections', color: '#42a5f5' },
  { name: 'Protocol validation', color: '#26a69a' },
  { name: 'Behavioral anomalies', color: '#ec407a' },
  { name: 'Other gateway rules', color: '#78909c' },
];
const chartTooltipStyle = { backgroundColor: '#101822', border: '1px solid rgba(154,175,193,.2)', borderRadius: 10, color: '#F3F7FA' };

interface MCPOverview {
  agents: { total: number; active: number; inactive: number };
  traffic: { total_requests: number; blocked_requests: number; allowed_requests: number };
}

interface BehavioralMonitorStatus {
  agents_monitored: number;
  training_samples: number;
  learning_quarantined: number;
  learning_policy: string;
  online_scoring: string;
  federated_updates: { status: string; mode: string; reason: string };
  enforcement: string;
}

interface AttackSimulationReport {
  simulation_id: string;
  scenario: string;
  synthetic: boolean;
  upstream_calls: number;
  persisted_events: number;
  events_broadcast: number;
  static_policy_decision: string;
  static_policy_miss: boolean;
  static_policy_summary: string;
  ml_detected_events: number;
  cep_findings: { rule_id: string; summary: string }[];
  events: { event_id: string; policy_decision: string; policy_matched_rules: string[]; ml_detected: boolean; ml_explanation: { feature: string; observed_z_score: number }[]; cep_findings: string[] }[];
}

const formatAge = (timestamp?: string) => {
  if (!timestamp) return 'No events received';
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(timestamp).getTime()) / 1000));
  return seconds < 60 ? `${seconds}s ago` : `${Math.floor(seconds / 60)}m ago`;
};

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [mcpOverview, setMcpOverview] = useState<MCPOverview | null>(null);
  const [behavioralStatus, setBehavioralStatus] = useState<BehavioralMonitorStatus | null>(null);
  const [simulation, setSimulation] = useState<AttackSimulationReport | null>(null);
  const [simulationError, setSimulationError] = useState<string | null>(null);
  const [simulationRunning, setSimulationRunning] = useState(false);
  const [simulationScenario, setSimulationScenario] = useState<'novel_sensitive_tool' | 'cross_agent_payload_fanout'>('novel_sensitive_tool');
  const [liveClock, setLiveClock] = useState(Date.now());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { connected, events } = useLiveTraffic();

  const fetchData = useCallback(async () => {
    try {
      const token = localStorage.getItem('access_token');
      const overviewRequest = fetch(`${API_URL}/mcp/overview`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      })
        .then(async (response) => {
          if (!response.ok) {
            throw new Error(`MCP overview request failed (${response.status})`);
          }
          return await response.json() as MCPOverview;
        })
        .catch((requestError) => {
          console.error('Unable to load persisted MCP overview:', requestError);
          return null;
        });
      const behavioralRequest = fetch(`${API_URL}/api/ml/behavioral-monitor`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      }).then(async (response) => {
        if (!response.ok) throw new Error(`Behavioral monitor request failed (${response.status})`);
        return await response.json() as BehavioralMonitorStatus;
      }).catch((requestError) => {
        console.error('Unable to load behavioral model status:', requestError);
        return null;
      });
      const [statsData, logsData] = await Promise.all([
        gatewayApi.getStats(), gatewayApi.getLogs(200),
      ]);
      const [overviewData, behavioralData] = await Promise.all([overviewRequest, behavioralRequest]);
      setStats(statsData);
      setLogs(logsData.logs);
      setMcpOverview(overviewData);
      setBehavioralStatus(behavioralData);
      setError(null);
    } catch {
      setError('Unable to reach the gateway on port 8001.');
    } finally {
      setLoading(false);
    }
  }, []);

  const runAttackSimulation = useCallback(async () => {
    setSimulationRunning(true);
    setSimulationError(null);
    try {
      const response = await gatewayFetch('/api/demo/attack-simulation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: simulationScenario }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || `Simulation request failed (${response.status})`);
      setSimulation(result as AttackSimulationReport);
    } catch (error) {
      setSimulationError(error instanceof Error ? error.message : 'Unable to run the synthetic simulation.');
    } finally {
      setSimulationRunning(false);
    }
  }, [simulationScenario]);

  useEffect(() => {
    fetchData();
    const poll = window.setInterval(fetchData, 10_000);
    return () => window.clearInterval(poll);
  }, [fetchData]);

  useEffect(() => {
    if (events.length) fetchData();
  }, [events.length, fetchData]);

  useEffect(() => {
    const timer = window.setInterval(() => setLiveClock(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const traffic = useMemo(() => {
    return (stats?.traffic_by_hour || []).map((item) => ({
      ...item,
      time: new Date(item.hour).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    }));
  }, [stats]);

  const detections = useMemo(() => {
    return DETECTION_CATEGORIES.map((category) => ({
      ...category,
      value: stats?.detection_categories?.[category.name] || 0,
    }));
  }, [stats]);

  const methodDistribution = useMemo(() => Object.entries(stats?.methods || {})
    .map(([method, count]) => ({ method, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8), [stats]);

  const requestOutcomes = useMemo(() => [
    { name: 'Allowed', value: Math.max(0, (stats?.total_requests || 0) - (stats?.blocked || 0)), color: '#26a69a' },
    { name: 'Blocked', value: stats?.blocked || 0, color: '#ef5350' },
  ], [stats]);

  const liveWindow = useMemo(() => {
    const cutoff = liveClock - 60_000;
    const recent = events.filter((event) => {
      const timestamp = new Date(event.timestamp).getTime();
      return Number.isFinite(timestamp) && timestamp >= cutoff && timestamp <= liveClock;
    });
    const buckets = Array.from({ length: 6 }, (_, index) => {
      const start = liveClock - 60_000 + index * 10_000;
      const end = start + 10_000;
      const items = recent.filter((event) => {
        const timestamp = new Date(event.timestamp).getTime();
        return timestamp >= start && timestamp < end;
      });
      return {
        time: new Date(end).toLocaleTimeString([], { minute: '2-digit', second: '2-digit' }),
        requests: items.length,
        blocked: items.filter((event) => event.decision === 'block').length,
      };
    });
    const latencies = recent.map((event) => event.latency_ms).filter((value): value is number => typeof value === 'number' && Number.isFinite(value));
    return {
      recent,
      buckets,
      blocked: recent.filter((event) => event.decision === 'block').length,
      flagged: recent.filter((event) => event.decision === 'flag' || event.ml_anomaly).length,
      averageLatency: latencies.length ? Math.round(latencies.reduce((sum, value) => sum + value, 0) / latencies.length) : null,
    };
  }, [events, liveClock]);

  const hybridWindow = useMemo(() => {
    const cutoff = liveClock - 5 * 60_000;
    const recent = events.filter((event) => {
      const timestamp = new Date(event.timestamp).getTime();
      return Number.isFinite(timestamp) && timestamp >= cutoff && timestamp <= liveClock;
    });
    const correlations = recent.filter((event) => event.decision_source === 'cep' || event.method === 'security/correlation');
    return {
      policyBlocks: recent.filter((event) => event.decision === 'block' && event.decision_source !== 'cep').length,
      mlAnomalies: recent.filter((event) => event.ml_anomaly).length,
      cepCorrelations: correlations.length,
      correlations: correlations.slice(0, 4),
      featureEvents: recent.filter((event) => event.observable_features),
      ruleHits: recent.reduce((total, event) => total + event.matched_rule_ids.length, 0),
    };
  }, [events, liveClock]);

  const latestFeatures: ObservableFeatureFamilies | undefined = hybridWindow.featureEvents[0]?.observable_features;
  const featureFamilies: { key: string; label: string; requirement: string; signals: string[]; failureModes: string[]; values?: Record<string, string | number | boolean | null> }[] = [
    {
      key: 'identity', label: 'Identity',
      requirement: 'Who produced the event, and which environment does it belong to?',
      signals: ['Unknown or drifting principal', 'Environment mismatch'],
      failureModes: ['Agent impersonation', 'Stolen or misused credentials'],
      values: latestFeatures?.identity,
    },
    {
      key: 'topics', label: 'Topics and routing',
      requirement: 'Which channel, event type, method, and upstream carried it?',
      signals: ['Unexpected topic/type/method combination', 'Cross-agent route fan-out'],
      failureModes: ['Topic confusion or injection', 'Unauthorized cross-tenant delivery'],
      values: latestFeatures?.topics,
    },
    {
      key: 'timing', label: 'Timing and ordering',
      requirement: 'How quickly events arrive, and whether they arrive fresh and in sequence.',
      signals: ['Burst rate or unusual delay', 'Replay, duplicate, or ordering gap'],
      failureModes: ['Queue buildup or event replay', 'Denial of service or stale decisions'],
      values: latestFeatures?.timing,
    },
    {
      key: 'payload_summary', label: 'Payload summaries',
      requirement: 'Use size, shape, hashes, and finding counts without copying raw arguments.',
      signals: ['Schema, size, or nesting drift', 'Injection and policy-rule matches'],
      failureModes: ['Parser/resource exhaustion', 'Injection, truncation, or malformed events'],
      values: latestFeatures?.payload_summary,
    },
    {
      key: 'graph_structure', label: 'Graph structure',
      requirement: 'Track repeated agent-to-tool, agent-to-upstream, and agent-to-topic edges.',
      signals: ['Novel or unusually repeated edges', 'High fan-out or cross-agent overlap'],
      failureModes: ['Privilege pivot or lateral movement', 'Unexpected data-exfiltration paths'],
      values: latestFeatures?.graph_structure,
    },
    {
      key: 'broker_state', label: 'Broker and consumer state',
      requirement: 'Observe producer, consumer group, retries, cursor, and transport protection.',
      signals: ['Delivery retries or rising event age', 'Missing schema or transport protection'],
      failureModes: ['Tampering, duplicate, or dropped events', 'Consumer backlog or broker outage'],
      values: latestFeatures?.broker_state,
    },
  ];

  if (loading) return <LinearProgress sx={{ mt: 4 }} />;
  if (error || !stats) return <Paper sx={{ p: 4, m: 3, textAlign: 'center' }}><ErrorIcon color="error" sx={{ fontSize: 44 }} /><Typography variant="h6" sx={{ mt: 1 }}>{error || 'Gateway data is unavailable.'}</Typography><IconButton aria-label="Retry" onClick={fetchData}><RefreshIcon /></IconButton></Paper>;

  const lastEvent = events[0]?.timestamp || logs[logs.length - 1]?.timestamp;
  const totalRequests = stats.total_requests;
  const blockedRequests = stats.blocked;
  const blockRate = totalRequests > 0 ? Math.min(100, Math.max(0, (blockedRequests / totalRequests) * 100)) : 0;
  const metricCards = [
    { label: 'Agent requests', value: totalRequests, hint: 'Persisted requests across registered agents', color: '#D56B82', icon: <TimelineIcon /> },
    { label: 'Blocked requests', value: blockedRequests, hint: `${blockRate.toFixed(1)}% of observed agent requests`, color: '#ef5350', icon: <BlockIcon /> },
    { label: 'Security detections', value: stats.anomaly_alerts || 0, hint: 'Persisted blocked and flagged events · all time', color: '#ffb74d', icon: <WarningIcon /> },
    { label: 'Detection engines', value: stats.ml_models || 0, hint: 'Behavioral models currently trained', color: '#81c784', icon: <SecurityIcon /> },
    { label: 'SQLi blocks · 24h', value: stats.sqli_blocks_24h || 0, hint: 'Rule-based SQL injection blocks', color: '#ef5350', icon: <BlockIcon /> },
    { label: 'Registered agents', value: mcpOverview?.agents.total || 0, hint: `${mcpOverview?.agents.active || 0} active`, color: '#D56B82', icon: <SecurityIcon /> },
  ];

  return <Box sx={{ p: 3 }}>
    <ExtensionBanner />
    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3, gap: 2, flexWrap: 'wrap' }}>
      <Box><Typography variant="h4" sx={{ fontWeight: 700 }}>Sentinel-MCP</Typography><Typography color="text.secondary">AI agent runtime security and MCP request protection</Typography></Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}><Tooltip title="Refresh data"><IconButton onClick={fetchData}><RefreshIcon /></IconButton></Tooltip><Chip icon={<HubIcon />} label={connected ? `LIVE · last event ${formatAge(lastEvent)}` : 'RECONNECTING · telemetry unavailable'} color={connected ? 'success' : 'warning'} variant="outlined" /></Box>
    </Box>

    <Paper sx={{ p: { xs: 2, sm: 2.5 }, mb: 3, borderLeft: `4px solid ${connected ? '#4caf50' : '#ff9800'}`, background: 'linear-gradient(110deg, rgba(76,175,80,.08), rgba(16,24,34,.96) 34%)' }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 2, flexWrap: 'wrap' }}>
        <Box>
          <Typography variant="overline" color="text.secondary" sx={{ letterSpacing: 1.2 }}>Protection status</Typography>
          <Typography variant="h6" sx={{ fontWeight: 700, lineHeight: 1.3 }}>{connected ? 'Telemetry connected' : 'Telemetry connection unavailable'}</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: .4 }}>{connected ? `WebSocket connected · Last event ${formatAge(lastEvent)}` : 'REST data is available; live event updates will resume when the gateway reconnects.'}</Typography>
        </Box>
        <Chip icon={<HubIcon />} label={connected ? 'LIVE STREAM' : 'RECONNECTING'} color={connected ? 'success' : 'warning'} variant="outlined" />
      </Box>
    </Paper>

    <Paper sx={{ p: { xs: 2, sm: 3 }, mb: 3, overflow: 'hidden', background: 'linear-gradient(145deg, rgba(17,27,39,.98), rgba(13,21,31,.98))' }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 2, flexWrap: 'wrap', mb: 2 }}>
        <Box>
          <Typography variant="h6" sx={{ fontWeight: 700 }}>Online model governance</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: .5, maxWidth: 760 }}>Each agent is scored against its own learned baseline, with the strongest feature deviations shown for review.</Typography>
        </Box>
        <Chip size="small" label={behavioralStatus?.online_scoring === 'active' ? 'ONLINE SCORING' : 'MODEL WARMING UP'} color={behavioralStatus?.online_scoring === 'active' ? 'success' : 'default'} variant="outlined" sx={{ fontWeight: 700, letterSpacing: .4 }} />
      </Box>
      <Grid container spacing={1.5}>
        {[
          { label: 'Trained agents', value: behavioralStatus?.agents_monitored ?? 0, hint: 'Individual behavior baselines' },
          { label: 'Clean baseline samples', value: behavioralStatus?.training_samples ?? 0, hint: 'Accepted for model learning' },
          { label: 'Anomalies quarantined', value: behavioralStatus?.learning_quarantined ?? 0, hint: 'Excluded from training data' },
        ].map((metric) => <Grid key={metric.label} size={{ xs: 12, sm: 4 }}>
          <Box sx={{ height: '100%', p: 1.75, borderRadius: 2.5, bgcolor: 'rgba(5,12,20,.42)', border: '1px solid rgba(154,175,193,.1)' }}>
            <Typography variant="overline" color="text.secondary" sx={{ letterSpacing: .8 }}>{metric.label}</Typography>
            <Typography variant="h4" sx={{ fontWeight: 750, lineHeight: 1.25, mt: .25 }}>{metric.value.toLocaleString()}</Typography>
            <Typography variant="caption" color="text.secondary">{metric.hint}</Typography>
          </Box>
        </Grid>)}
      </Grid>
      <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1, flexWrap: 'wrap', mt: 2 }}>
        <Chip size="small" color="primary" variant="outlined" label={behavioralStatus?.enforcement || 'Deterministic policy and CEP remain authoritative'} />
        <Chip size="small" variant="outlined" label={`Learning gate · ${behavioralStatus?.learning_policy || 'allow-only; anomalies excluded'}`} sx={{ maxWidth: '100%', '& .MuiChip-label': { whiteSpace: 'normal', py: .5 } }} />
      </Box>
      <Box sx={{ mt: 1.5, p: 1.5, borderRadius: 2, bgcolor: 'rgba(255,255,255,.025)', border: '1px solid rgba(154,175,193,.08)' }}>
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', fontWeight: 700, mb: .35 }}>Federated updates · {behavioralStatus?.federated_updates.status || 'status unavailable'}</Typography>
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', overflowWrap: 'anywhere' }}>{behavioralStatus?.federated_updates.reason || 'Signed aggregator not configured.'}</Typography>
      </Box>
    </Paper>

    <Paper sx={{ p: { xs: 2, sm: 3 }, mb: 3, borderLeft: '4px solid #ab47bc', background: 'linear-gradient(115deg, rgba(171,71,188,.09), rgba(16,24,34,.97) 45%)' }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 2, flexWrap: 'wrap', mb: 2 }}>
        <Box>
          <Typography variant="h6" sx={{ fontWeight: 700 }}>Synthetic event-stream attack lab</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: .5, maxWidth: 800 }}>Explore how generated events move through policy checks, anomaly scoring, correlation, and the live stream.</Typography>
        </Box>
        <Chip size="small" color="secondary" variant="outlined" label="SAFE · SYNTHETIC DATA" sx={{ fontWeight: 700, letterSpacing: .35 }} />
      </Box>
      <Box sx={{ display: 'flex', gap: 1.25, flexWrap: 'wrap', alignItems: 'center' }}>
        <FormControl size="small" sx={{ minWidth: { xs: '100%', sm: 290 }, maxWidth: '100%' }}>
          <InputLabel id="attack-scenario-label">Synthetic scenario</InputLabel>
          <Select labelId="attack-scenario-label" label="Synthetic scenario" value={simulationScenario} onChange={(event) => {
            setSimulationScenario(event.target.value as typeof simulationScenario);
            setSimulation(null);
          }}>
            <MenuItem value="novel_sensitive_tool">Novel behavior on filesystem/write</MenuItem>
            <MenuItem value="cross_agent_payload_fanout">Cross-agent payload fan-out</MenuItem>
          </Select>
        </FormControl>
        <Button variant="contained" color="secondary" onClick={runAttackSimulation} disabled={simulationRunning} sx={{ minHeight: 40, px: 2.5, width: { xs: '100%', sm: 'auto' } }}>
          {simulationRunning ? 'Running simulation…' : 'Run synthetic replay'}
        </Button>
      </Box>
      <Box sx={{ mt: 1.75, p: 1.5, borderRadius: 2, bgcolor: 'rgba(5,12,20,.4)', border: '1px solid rgba(154,175,193,.09)' }}>
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', lineHeight: 1.7 }}>
          Replays three requests through policy, ML, and CEP. No upstream calls or database writes. Requires <strong>gateway:write</strong>.
        </Typography>
      </Box>
      {simulationRunning && <LinearProgress sx={{ mt: 1.5 }} />}
      {simulationError && <Typography color="error.main" variant="body2" sx={{ mt: 1.5 }}>{simulationError}</Typography>}
      {simulation && <Box sx={{ mt: 2 }}>
        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 1 }}>
          <Chip size="small" color={simulation.static_policy_decision === 'allow' ? 'success' : 'error'} variant="outlined" label={`Static policy: ${simulation.static_policy_decision}`} />
          <Chip size="small" color={simulation.ml_detected_events ? 'warning' : 'default'} variant="outlined" label={`Online ML: ${simulation.ml_detected_events}/${simulation.events_broadcast}`} />
          <Chip size="small" color={simulation.cep_findings.length ? 'error' : 'default'} variant="outlined" label={`CEP: ${simulation.cep_findings.length} findings`} />
          <Chip size="small" color={simulation.static_policy_miss ? 'warning' : 'success'} variant="outlined" label={simulation.static_policy_miss ? 'Static-rule miss demonstrated' : 'No static-rule miss'} />
          <Chip size="small" color="secondary" label="SYNTHETIC" />
        </Box>
        <Typography variant="body2" color="text.secondary">{simulation.static_policy_summary}</Typography>
        {simulation.events.map((event) => <Box key={event.event_id} sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap', py: .75, borderTop: '1px solid', borderColor: 'divider' }}>
          <Chip size="small" label={event.event_id.slice(-1)} />
          <Typography variant="body2" sx={{ minWidth: 100 }}>Policy {event.policy_decision} · ML {event.ml_detected ? 'anomaly' : 'normal'}</Typography>
          <Typography variant="caption" color="text.secondary">Rules: {event.policy_matched_rules.length ? event.policy_matched_rules.join(', ') : 'none matched'}</Typography>
          <Typography variant="caption" color="text.secondary" sx={{ flex: 1 }}>{event.ml_explanation.map((item) => `${item.feature} ${item.observed_z_score > 0 ? '+' : ''}${item.observed_z_score}σ`).join(' · ') || 'No feature deviations returned'}</Typography>
          {event.cep_findings.map((rule) => <Chip key={`${event.event_id}-${rule}`} size="small" color="warning" variant="outlined" label={rule} />)}
          <Chip size="small" color="secondary" variant="outlined" label="DEMO EVENT" />
        </Box>)}
      </Box>}
    </Paper>

    <Grid container spacing={2} sx={{ mb: 3 }}>{metricCards.map((card) => <Grid key={card.label} size={{ xs: 12, sm: 6, md: 3 }}><Card><CardContent><Box sx={{ display: 'flex', justifyContent: 'space-between' }}><Typography variant="overline">{card.label}</Typography><Avatar sx={{ bgcolor: `${card.color}22`, color: card.color }}>{card.icon}</Avatar></Box><Typography variant="h3" sx={{ fontWeight: 700 }}>{card.value.toLocaleString()}</Typography><Typography variant="caption" color="text.secondary">{card.hint}</Typography></CardContent></Card></Grid>)}</Grid>

    <Paper sx={{ p: 2.5, mb: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 2, flexWrap: 'wrap', mb: 1 }}>
        <Box><Typography variant="h6">Live traffic pulse</Typography><Typography variant="caption" color="text.secondary">Rolling 60-second window from incoming gateway events · refreshes in real time</Typography></Box>
        <Chip size="small" icon={<HubIcon />} label={connected ? 'STREAM CONNECTED' : 'WAITING FOR STREAM'} color={connected ? 'success' : 'warning'} variant="outlined" />
      </Box>
      <Grid container spacing={2}>
        <Grid size={{ xs: 6, sm: 3 }}><Typography variant="overline" color="text.secondary">Requests / 60s</Typography><Typography variant="h4" sx={{ fontWeight: 700 }}>{liveWindow.recent.length}</Typography></Grid>
        <Grid size={{ xs: 6, sm: 3 }}><Typography variant="overline" color="text.secondary">Blocked</Typography><Typography variant="h4" sx={{ fontWeight: 700, color: '#ef5350' }}>{liveWindow.blocked}</Typography></Grid>
        <Grid size={{ xs: 6, sm: 3 }}><Typography variant="overline" color="text.secondary">Flagged</Typography><Typography variant="h4" sx={{ fontWeight: 700, color: '#ffb74d' }}>{liveWindow.flagged}</Typography></Grid>
        <Grid size={{ xs: 6, sm: 3 }}><Typography variant="overline" color="text.secondary">Avg. latency</Typography><Typography variant="h4" sx={{ fontWeight: 700 }}>{liveWindow.averageLatency === null ? '—' : `${liveWindow.averageLatency} ms`}</Typography></Grid>
      </Grid>
      <ResponsiveContainer width="100%" height={170}>
        <AreaChart data={liveWindow.buckets}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="time" tick={{ fill: '#9BAAB7', fontSize: 12 }} />
          <YAxis allowDecimals={false} tick={{ fill: '#9BAAB7', fontSize: 12 }} />
          <ChartTooltip contentStyle={chartTooltipStyle} />
          <Legend />
          <Area type="monotone" dataKey="requests" stroke="#42a5f5" fill="#42a5f522" name="Requests" />
          <Area type="monotone" dataKey="blocked" stroke="#ef5350" fill="#ef535022" name="Blocked" />
        </AreaChart>
      </ResponsiveContainer>
      {!liveWindow.recent.length && <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', mt: -1 }}>Waiting for gateway events. New MCP requests will appear here as they arrive.</Typography>}
    </Paper>

    <Paper sx={{ p: 2.5, mb: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 2, flexWrap: 'wrap', mb: 2 }}>
        <Box>
          <Typography variant="h6">Hybrid security layer</Typography>
          <Typography variant="caption" color="text.secondary">ML and behavioral analysis detect drift; synchronous policy rules block known unsafe calls; CEP correlates event sequences.</Typography>
        </Box>
        <Chip size="small" label={connected ? 'LIVE · LAST 5 MIN' : 'STREAM RECONNECTING'} color={connected ? 'success' : 'warning'} variant="outlined" />
      </Box>
      <Grid container spacing={2}>
        <Grid size={{ xs: 12, md: 4 }}>
          <Card variant="outlined" sx={{ height: '100%' }}><CardContent>
            <Typography variant="overline" color="text.secondary">Deterministic enforcement</Typography>
            <Typography variant="h4" sx={{ fontWeight: 700, color: '#ef5350' }}>{hybridWindow.policyBlocks}</Typography>
            <Typography variant="body2" color="text.secondary">Blocked by gateway policies in the live window</Typography>
            <Typography variant="caption" color="text.secondary">{hybridWindow.ruleHits} matched policy / CEP rules</Typography>
          </CardContent></Card>
        </Grid>
        <Grid size={{ xs: 12, md: 4 }}>
          <Card variant="outlined" sx={{ height: '100%' }}><CardContent>
            <Typography variant="overline" color="text.secondary">Behavioral model</Typography>
            <Typography variant="h4" sx={{ fontWeight: 700, color: '#42a5f5' }}>{hybridWindow.mlAnomalies}</Typography>
            <Typography variant="body2" color="text.secondary">Events outside learned agent behavior</Typography>
            <Typography variant="caption" color="text.secondary">{stats.ml_models || 0} trained model{stats.ml_models === 1 ? '' : 's'} active</Typography>
          </CardContent></Card>
        </Grid>
        <Grid size={{ xs: 12, md: 4 }}>
          <Card variant="outlined" sx={{ height: '100%' }}><CardContent>
            <Typography variant="overline" color="text.secondary">CEP correlations</Typography>
            <Typography variant="h4" sx={{ fontWeight: 700, color: '#ffb74d' }}>{hybridWindow.cepCorrelations}</Typography>
            <Typography variant="body2" color="text.secondary">Cross-event patterns detected in the last 5 minutes</Typography>
            <Typography variant="caption" color="text.secondary">Burst, rule-campaign, fan-out, and behavior-drift rules</Typography>
          </CardContent></Card>
        </Grid>
      </Grid>
      {hybridWindow.correlations.length > 0 ? <Box sx={{ mt: 2 }}>
        <Typography variant="subtitle2" sx={{ mb: .5 }}>Latest CEP findings</Typography>
        {hybridWindow.correlations.map((event) => <Box key={event.event_id} sx={{ display: 'flex', alignItems: 'center', gap: 1, py: .75, borderTop: '1px solid', borderColor: 'divider', flexWrap: 'wrap' }}>
          <Chip size="small" color="warning" label={event.matched_rule_ids[0] || 'CEP'} />
          <Typography variant="body2" sx={{ flex: 1, minWidth: 200 }}>{event.decision_reason}</Typography>
          {event.correlation_window_seconds ? <Typography variant="caption" color="text.secondary">{event.correlation_window_seconds}s window</Typography> : null}
          <Typography variant="caption" color="text.secondary">{new Date(event.timestamp).toLocaleTimeString()}</Typography>
        </Box>)}
      </Box> : <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>No CEP threshold has fired in the last 5 minutes. Policy blocks and model flags continue to appear as events arrive.</Typography>}
    </Paper>

    <Paper sx={{ p: { xs: 2, sm: 3 }, mb: 3, background: 'linear-gradient(145deg, rgba(17,27,39,.98), rgba(13,21,31,.98))' }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 2, flexWrap: 'wrap', mb: 2.5 }}>
        <Box>
          <Typography variant="h6" sx={{ fontWeight: 700 }}>Event security feature map</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: .35 }}>Six views of each consumed broker event help surface identity, routing, timing, payload, graph, and broker risks.</Typography>
        </Box>
        <Chip size="small" label={`${hybridWindow.featureEvents.length} live events · 5 min`} color={hybridWindow.featureEvents.length ? 'info' : 'default'} variant="outlined" sx={{ fontWeight: 700 }} />
      </Box>
      <Grid container spacing={2}>
        {featureFamilies.map((family, index) => {
          const accentColors = ['#56E0C3', '#42A5F5', '#A99BFF', '#FFB74D', '#F06292', '#80CBC4'];
          const accent = accentColors[index % accentColors.length];
          const values = family.values ? Object.entries(family.values).filter(([, value]) => value !== null) : [];
          return (
          <Grid key={family.key} size={{ xs: 12, sm: 6, lg: 4 }}>
            <Card variant="outlined" sx={{
              height: '100%',
              borderRadius: 3,
              borderColor: 'rgba(154,175,193,.14)',
              borderTop: `2px solid ${accent}`,
              background: 'linear-gradient(155deg, rgba(20,32,45,.88), rgba(12,20,29,.8))',
              transition: 'transform .18s ease, border-color .18s ease, box-shadow .18s ease',
              '&:hover': { transform: 'translateY(-2px)', borderColor: `${accent}88`, boxShadow: `0 12px 28px ${accent}12` },
            }}>
              <CardContent sx={{ p: 2.25, '&:last-child': { pb: 2.25 } }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.1, mb: .75 }}>
                  <Box sx={{ width: 30, height: 30, display: 'grid', placeItems: 'center', borderRadius: 2, bgcolor: `${accent}1A`, color: accent, fontSize: 12, fontWeight: 800 }}>{String(index + 1).padStart(2, '0')}</Box>
                  <Typography variant="subtitle1" sx={{ fontWeight: 750 }}>{family.label}</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ minHeight: 42, lineHeight: 1.55 }}>{family.requirement}</Typography>

                <Box sx={{ mt: 1.5, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1 }}>
                  <Box sx={{ p: 1.15, borderRadius: 2, bgcolor: 'rgba(86,224,195,.055)', border: '1px solid rgba(86,224,195,.11)' }}>
                    <Typography variant="overline" sx={{ color: 'primary.light', fontSize: 9, lineHeight: 1.4, letterSpacing: 1 }}>Signals</Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: .25, lineHeight: 1.55 }}>{family.signals.join(' · ')}</Typography>
                  </Box>
                  <Box sx={{ p: 1.15, borderRadius: 2, bgcolor: 'rgba(255,183,77,.045)', border: '1px solid rgba(255,183,77,.10)' }}>
                    <Typography variant="overline" sx={{ color: '#FFCC80', fontSize: 9, lineHeight: 1.4, letterSpacing: 1 }}>Risks</Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: .25, lineHeight: 1.55 }}>{family.failureModes.join(' · ')}</Typography>
                  </Box>
                </Box>

                <Divider sx={{ my: 1.5, borderColor: 'rgba(154,175,193,.1)' }} />
                {values.length ? (
                  <Grid container spacing={.75}>
                    {values.map(([name, value]) => (
                      <Grid key={name} size={{ xs: 6 }}>
                        <Box sx={{ minWidth: 0, height: '100%', px: 1, py: .75, borderRadius: 1.5, bgcolor: 'rgba(5,12,20,.45)' }}>
                          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', textTransform: 'capitalize', fontSize: 10, lineHeight: 1.35 }}>{name.replace(/_/g, ' ')}</Typography>
                          <Typography variant="body2" sx={{ mt: .2, color: 'text.primary', fontWeight: 650, fontSize: 12, overflowWrap: 'anywhere', lineHeight: 1.4 }}>{String(value)}</Typography>
                        </Box>
                      </Grid>
                    ))}
                  </Grid>
                ) : (
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'block', py: .5 }}>Live values will appear when the stream consumes an event.</Typography>
                )}
              </CardContent>
            </Card>
          </Grid>
          );
        })}
      </Grid>
      <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 2 }}>
        Payload features contain shape and detection summaries only; raw arguments are not duplicated into the feature map.
      </Typography>
    </Paper>

    <Paper sx={{ p: 2, mb: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', gap: 2, flexWrap: 'wrap' }}>
        <Box><Typography variant="h6">SQL injection blocks</Typography><Typography variant="caption" color="text.secondary">Persisted rule blocks over the last 24 hours</Typography></Box>
        <Typography variant="h4" sx={{ fontWeight: 700 }}>{(stats.sqli_blocks_24h || 0).toLocaleString()}</Typography>
      </Box>
      {stats.sqli_blocks_by_hour?.length ? <ResponsiveContainer width="100%" height={150}><AreaChart data={stats.sqli_blocks_by_hour.map((item) => ({ ...item, time: new Date(item.hour).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) }))}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="time" /><YAxis allowDecimals={false} /><ChartTooltip /><Area type="stepAfter" dataKey="blocks" stroke="#ef5350" fill="#ef535022" name="SQLi blocks" /></AreaChart></ResponsiveContainer> : <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>No SQLi blocks recorded in the last 24 hours.</Typography>}
    </Paper>

    <Grid container spacing={3} sx={{ mb: 3 }}>
      <Grid size={{ xs: 12, md: 7 }}><Paper sx={{ p: 3, height: 440 }}><Typography variant="h6">Traffic observed by the gateway</Typography><Typography variant="caption" color="text.secondary">Persisted request events · last 24 hours</Typography>{traffic.length ? <ResponsiveContainer width="100%" height={350}><AreaChart data={traffic}><defs><linearGradient id="events" x1="0" x2="0" y1="0" y2="1"><stop offset="5%" stopColor="#D56B82" stopOpacity={.45}/><stop offset="95%" stopColor="#D56B82" stopOpacity={0}/></linearGradient></defs><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="time" /><YAxis allowDecimals={false} /><ChartTooltip contentStyle={chartTooltipStyle} /><Legend /><Area type="monotone" dataKey="events" stroke="#D56B82" fill="url(#events)" name="Events" /><Area type="monotone" dataKey="blocked" stroke="#ef5350" fill="none" name="Blocked" /></AreaChart></ResponsiveContainer> : <Box sx={{ height: 350, display: 'grid', placeItems: 'center' }}><Typography color="text.secondary">No traffic has been recorded yet.</Typography></Box>}</Paper></Grid>
      <Grid size={{ xs: 12, md: 5 }}><Paper sx={{ p: 3, minHeight: 440 }}><Typography variant="h6">Detection categories</Typography><Typography variant="caption" color="text.secondary">All retained blocked and flagged events. Category counts can overlap; zero-count categories remain visible.</Typography><ResponsiveContainer width="100%" height={200}><PieChart><Pie data={detections.filter((item) => item.value > 0)} dataKey="value" nameKey="name" innerRadius={58} outerRadius={78}>{detections.filter((item) => item.value > 0).map((item) => <Cell key={item.name} fill={item.color} />)}</Pie><ChartTooltip contentStyle={chartTooltipStyle} /></PieChart></ResponsiveContainer>{detections.map((item) => <Box key={item.name} sx={{ display: 'flex', justifyContent: 'space-between', py: .25 }}><Typography variant="body2"><Box component="span" sx={{ color: item.color }}>● </Box>{item.name}</Typography><Typography variant="body2" sx={{ fontWeight: 700 }}>{item.value}</Typography></Box>)}</Paper></Grid>
    </Grid>

    <Grid container spacing={3} sx={{ mb: 3 }}>
      <Grid size={{ xs: 12, md: 5 }}>
        <Paper sx={{ p: 3, height: 360 }}>
          <Typography variant="h6">Request outcomes</Typography>
          <Typography variant="caption" color="text.secondary">Allowed and blocked requests across registered agents</Typography>
          <ResponsiveContainer width="100%" height={245}>
            <PieChart>
              <Pie data={requestOutcomes} dataKey="value" nameKey="name" innerRadius={62} outerRadius={96} paddingAngle={3}>
                {requestOutcomes.map((item) => <Cell key={item.name} fill={item.color} />)}
              </Pie>
              <ChartTooltip contentStyle={chartTooltipStyle} formatter={(value) => [Number(value ?? 0).toLocaleString(), 'Requests']} />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </Paper>
      </Grid>
      <Grid size={{ xs: 12, md: 7 }}>
        <Paper sx={{ p: 3, height: 360 }}>
          <Typography variant="h6">Most used request methods</Typography>
          <Typography variant="caption" color="text.secondary">Method distribution from gateway telemetry</Typography>
          {methodDistribution.length ? <ResponsiveContainer width="100%" height={275}>
            <BarChart data={methodDistribution} layout="vertical" margin={{ left: 16, right: 20, top: 8, bottom: 4 }}>
              <CartesianGrid strokeDasharray="3 3" horizontal={false} />
              <XAxis type="number" allowDecimals={false} tick={{ fill: '#9BAAB7' }} />
              <YAxis type="category" dataKey="method" width={120} tick={{ fill: '#CBD5DE', fontSize: 12 }} />
              <ChartTooltip contentStyle={chartTooltipStyle} />
              <Bar dataKey="count" name="Requests" fill="#42a5f5" radius={[0, 6, 6, 0]} />
            </BarChart>
          </ResponsiveContainer> : <Box sx={{ height: 275, display: 'grid', placeItems: 'center' }}><Typography color="text.secondary">Method data will appear as requests arrive.</Typography></Box>}
        </Paper>
      </Grid>
    </Grid>

    <Paper sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
        <Box>
          <Typography variant="h6">Recent MCP agent events</Typography>
          <Typography variant="caption" color="text.secondary">Persisted history with live updates for requests passing through the gateway.</Typography>
        </Box>
        <Chip size="small" label={connected ? 'LIVE' : 'OFFLINE'} color={connected ? 'success' : 'default'} />
      </Box>
      <Divider />
      {events.length ? events.slice(0, 25).map((event: TrafficEvent) => (
        <Box key={event.event_id} sx={{ display: 'flex', alignItems: 'center', gap: 1.5, py: 1.25, borderBottom: '1px solid', borderColor: 'divider', flexWrap: 'wrap' }}>
          {event.decision === 'block' ? <BlockIcon color="error" /> : <CheckCircleIcon color="success" />}
          <Box sx={{ flex: 1, minWidth: 180 }}>
            <Typography sx={{ fontWeight: 600 }}>
              {event.agent_name}
              <Typography component="span" variant="caption" color="text.secondary"> · {event.tool_name || event.method}</Typography>
              {event.synthetic_demo && <Chip size="small" color="secondary" label="DEMO" sx={{ ml: 1, height: 20 }} />}
            </Typography>
            <Typography variant="caption" color="text.secondary">{event.decision_reason || 'No policy reason reported'}</Typography>
            {event.ml_anomaly && <Typography variant="caption" color="warning.main" sx={{ display: 'block' }}>
              Behavioral deviation: {event.behavioral_explanation?.length
                ? event.behavioral_explanation.map((item) => `${item.feature} (${item.observed_z_score > 0 ? '+' : ''}${item.observed_z_score}σ)`).join(' · ')
                : 'outside learned baseline'} · held out from training
            </Typography>}
          </Box>
          <Typography variant="caption" color="text.secondary" sx={{ minWidth: 150 }}>
            ML {event.ml_score === null ? 'n/a' : `${(event.ml_score * 100).toFixed(1)}%`} · Rule {event.rule_risk_score === null ? 'n/a' : `${(event.rule_risk_score * 100).toFixed(1)}%`}
          </Typography>
          <Chip size="small" label={event.decision.toUpperCase()} color={event.decision === 'block' ? 'error' : event.decision === 'flag' ? 'warning' : 'success'} />
          <Typography variant="caption" color="text.secondary">{new Date(event.timestamp).toLocaleTimeString()}</Typography>
        </Box>
      )) : logs.length ? logs.slice(-12).reverse().map((log, index) => {
        const blocked = !log.policy_allowed || log.analysis_anomaly || log.ml_anomaly;
        const system = log.event_category === 'system';
        return (
          <Box key={log.event_id || `${log.timestamp}-${index}`} sx={{ display: 'flex', alignItems: 'center', gap: 1.5, py: 1.25, borderBottom: '1px solid', borderColor: 'divider' }}>
            {blocked ? <BlockIcon color={system ? 'warning' : 'error'} /> : <CheckCircleIcon color="success" />}
            <Box sx={{ flex: 1, minWidth: 0 }}>
              <Typography sx={{ fontWeight: 600 }}>{log.method}<Typography component="span" variant="caption" color="text.secondary"> · {log.agent_id}</Typography></Typography>
              <Typography variant="caption" color="text.secondary">{log.policy_reason}</Typography>
            </Box>
            <Chip size="small" label={system ? 'SYSTEM' : blocked ? 'BLOCKED' : 'ALLOWED'} color={system ? 'warning' : blocked ? 'error' : 'success'} />
            <Typography variant="caption" color="text.secondary">{new Date(log.timestamp).toLocaleTimeString()}</Typography>
          </Box>
        );
      }) : <Box sx={{ py: 5, textAlign: 'center' }}><Typography color="text.secondary">No MCP agent traffic yet. Send requests through /mcp/proxy to populate this dashboard.</Typography></Box>}
    </Paper>
  </Box>;
};

export default Dashboard;
