import React, { useEffect, useMemo, useState } from 'react';
import { Box, Button, Card, CardContent, Chip, Dialog, DialogActions, DialogContent, DialogTitle, Divider, Grid, IconButton, LinearProgress, Paper, Stack, TextField, Tooltip, Typography } from '@mui/material';
import { CheckCircle as CheckIcon, Refresh as RefreshIcon, Security as SecurityIcon, Warning as WarningIcon } from '@mui/icons-material';
import { AgentSecuritySummary, gatewayApi } from '../services/api';
import { LogEntry } from '../types';

const age = (value: string | null) => !value ? 'No activity yet' : `${Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000))}s ago`;
const trustColor = (trust: AgentSecuritySummary['trust_level']) => trust === 'TRUSTED' ? 'success' : trust === 'MONITORED' ? 'info' : trust === 'RESTRICTED' ? 'warning' : 'error';

const summarizeLogs = (logs: LogEntry[]): AgentSecuritySummary[] => {
  const summaries = new Map<string, AgentSecuritySummary>();
  logs.forEach((log) => {
    const item = summaries.get(log.agent_id) || {
      agent_id: log.agent_id, requests: 0, blocked: 0, anomalies: 0, tools: {},
      last_seen: null, risk_score: 0, trust_level: 'TRUSTED' as const,
      behavior_status: 'NORMAL' as const, recent_events: [],
    };
    const blocked = !log.policy_allowed || log.analysis_anomaly || log.ml_anomaly;
    item.requests += 1;
    item.blocked += Number(blocked);
    item.anomalies += Number(log.analysis_anomaly || log.ml_anomaly);
    item.tools[log.method] = (item.tools[log.method] || 0) + 1;
    item.last_seen = log.timestamp;
    item.recent_events = [...item.recent_events, log].slice(-10);
    summaries.set(log.agent_id, item);
  });
  return [...summaries.values()].map((item) => {
    const risk = Math.min(100, Math.round(item.anomalies * 25 + (item.requests ? item.blocked / item.requests : 0) * 45 + Math.min(Object.keys(item.tools).length, 10) * 2));
    return { ...item, risk_score: risk, trust_level: risk >= 80 ? 'QUARANTINED' : risk >= 60 ? 'RESTRICTED' : risk >= 30 ? 'MONITORED' : 'TRUSTED', behavior_status: item.anomalies ? 'ANOMALOUS' : 'NORMAL' };
  });
};

const AgentDetailsPage: React.FC = () => {
  const [agents, setAgents] = useState<AgentSecuritySummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<AgentSecuritySummary | null>(null);
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const fetchAgents = async () => {
    try {
      setAgents((await gatewayApi.getAgentsSummary()).agents);
      setConnectionError(null);
    } catch (error: any) {
      // The summary endpoint requires a gateway restart after an upgrade.
      // Fall back to the long-standing logs endpoint for a safe live view.
      if (error.response?.status === 404) {
        try {
          setAgents(summarizeLogs((await gatewayApi.getLogs(200)).logs));
          setConnectionError('Gateway upgrade pending: showing a compatibility view from request logs. Restart the gateway to enable server-side agent summaries.');
        } catch {
          setConnectionError('Unable to reach the gateway. Start it on port 8001 and retry.');
        }
      } else {
        setConnectionError('Unable to reach the gateway. Start it on port 8001 and retry.');
      }
    } finally { setLoading(false); }
  };
  useEffect(() => { fetchAgents(); const timer = window.setInterval(fetchAgents, 10_000); return () => window.clearInterval(timer); }, []);
  const filtered = useMemo(() => agents.filter((agent) => agent.agent_id.toLowerCase().includes(search.toLowerCase())), [agents, search]);
  if (loading) return <LinearProgress sx={{ mt: 4 }} />;
  const totalRequests = agents.reduce((sum, agent) => sum + agent.requests, 0);
  const cards = [['Agents', agents.length, 'Observed in gateway telemetry'], ['Monitored', agents.filter((agent) => agent.trust_level !== 'TRUSTED').length, 'Need ongoing oversight'], ['Risky', agents.filter((agent) => agent.risk_score >= 60).length, 'Restricted or quarantined'], ['Requests', totalRequests, 'Consistent gateway total']];
  return <Box sx={{ p: 3 }}>
    <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 3 }}><Box><Typography variant="h4" sx={{ fontWeight: 700 }}>Agent Security</Typography><Typography color="text.secondary">Behavioral intelligence, tool exposure, and security controls for MCP agents</Typography></Box><Tooltip title="Refresh"><IconButton onClick={fetchAgents}><RefreshIcon /></IconButton></Tooltip></Box>
    {connectionError && <Paper sx={{ p: 2, mb: 3, borderLeft: '4px solid', borderColor: connectionError.startsWith('Gateway upgrade') ? 'warning.main' : 'error.main' }}><Typography variant="body2">{connectionError}</Typography></Paper>}
    <Grid container spacing={2} sx={{ mb: 3 }}>{cards.map(([label, value, hint]) => <Grid key={label as string} size={{ xs: 12, sm: 6, md: 3 }}><Card><CardContent><Typography variant="overline">{label}</Typography><Typography variant="h3" sx={{ fontWeight: 700 }}>{value}</Typography><Typography variant="caption" color="text.secondary">{hint}</Typography></CardContent></Card></Grid>)}</Grid>
    <Paper sx={{ p: 2, mb: 3 }}><TextField size="small" fullWidth placeholder="Search agents" value={search} onChange={(event) => setSearch(event.target.value)} /></Paper>
    {filtered.length ? <Grid container spacing={3}>{filtered.map((agent) => { const allowed = agent.requests - agent.blocked; return <Grid key={agent.agent_id} size={{ xs: 12, md: 6 }}><Card sx={{ height: '100%', borderLeft: '4px solid', borderColor: `${trustColor(agent.trust_level)}.main` }}><CardContent><Box sx={{ display: 'flex', justifyContent: 'space-between', gap: 2 }}><Box><Typography variant="h6">{agent.agent_id}</Typography><Typography variant="caption" color="text.secondary">Last activity: {age(agent.last_seen)}</Typography></Box><Chip label={agent.trust_level} color={trustColor(agent.trust_level)} /></Box><Grid container spacing={2} sx={{ my: 1 }}><Grid size={{ xs: 4 }}><Typography variant="overline">Risk</Typography><Typography variant="h4" color={agent.risk_score >= 60 ? 'error.main' : 'success.main'}>{agent.risk_score}<Typography component="span" variant="caption">/100</Typography></Typography></Grid><Grid size={{ xs: 4 }}><Typography variant="overline">Requests</Typography><Typography variant="h4">{agent.requests}</Typography></Grid><Grid size={{ xs: 4 }}><Typography variant="overline">Blocked</Typography><Typography variant="h4">{agent.blocked}</Typography></Grid></Grid><Typography variant="body2"><CheckIcon color={agent.behavior_status === 'NORMAL' ? 'success' : 'warning'} fontSize="small" /> Behavior: {agent.behavior_status} · {Object.keys(agent.tools).length} tools observed</Typography><Stack direction="row" spacing={.5} sx={{ my: 1, flexWrap: 'wrap' }}>{Object.entries(agent.tools).slice(0, 4).map(([tool, calls]) => <Chip key={tool} size="small" label={`${tool} · ${calls}`} variant="outlined" />)}</Stack><Button variant="outlined" onClick={() => setSelected(agent)}>View agent</Button></CardContent></Card></Grid>; })}</Grid> : <Paper sx={{ p: 6, textAlign: 'center' }}><SecurityIcon sx={{ fontSize: 48, opacity: .4 }} /><Typography>No agents match your search.</Typography></Paper>}
    <Dialog open={!!selected} onClose={() => setSelected(null)} maxWidth="sm" fullWidth>{selected && <><DialogTitle>{selected.agent_id}</DialogTitle><DialogContent dividers><Stack direction="row" spacing={1} sx={{ mb: 2 }}><Chip label={selected.trust_level} color={trustColor(selected.trust_level)} /><Chip label={`Risk ${selected.risk_score}/100`} /></Stack><Typography variant="overline">Security explanation</Typography><Typography>{selected.anomalies ? `${selected.anomalies} behavioral anomaly signals and ${selected.blocked} blocked requests contribute to the current risk score.` : 'No behavioral anomalies have been recorded. Risk reflects observed tool exposure and enforcement activity.'}</Typography><Divider sx={{ my: 2 }} /><Typography variant="overline">Observed tools</Typography>{Object.entries(selected.tools).map(([tool, calls]) => <Box key={tool} sx={{ display: 'flex', justifyContent: 'space-between', py: .5 }}><Typography>{tool}</Typography><Typography>{calls} calls</Typography></Box>)}<Divider sx={{ my: 2 }} /><Typography variant="overline">Recommended action</Typography><Typography>{selected.risk_score >= 60 ? 'Review recent requests and restrict permissions until the cause is understood.' : 'Continue monitoring this agent; review permissions before enabling additional tools.'}</Typography></DialogContent><DialogActions><Button onClick={() => setSelected(null)}>Close</Button></DialogActions></>}</Dialog>
  </Box>;
};

export default AgentDetailsPage;
