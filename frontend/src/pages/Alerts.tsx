import React, { useEffect, useMemo, useState } from 'react';
import {
  Box, Button, Card, CardContent, Chip, Dialog, DialogActions, DialogContent,
  DialogTitle, Divider, Grid, IconButton, LinearProgress, MenuItem, Paper,
  Select, Stack, TextField, Tooltip, Typography,
} from '@mui/material';
import { CheckCircle as CheckCircleIcon, Refresh as RefreshIcon, Search as SearchIcon, Warning as WarningIcon } from '@mui/icons-material';
import { gatewayApi } from '../services/api';
import { Alert } from '../types';

const statuses: Alert['status'][] = ['NEW', 'ACKNOWLEDGED', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'];
const age = (date: string) => {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(date).getTime()) / 1000));
  return seconds < 60 ? `${seconds}s ago` : seconds < 3600 ? `${Math.floor(seconds / 60)}m ago` : `${Math.floor(seconds / 3600)}h ago`;
};
const severityColor = (severity: string) => severity === 'HIGH' ? 'error' : severity === 'MEDIUM' ? 'warning' : 'info';

const AlertsPage: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('ALL');
  const [status, setStatus] = useState('ACTIVE');
  const [selected, setSelected] = useState<Alert | null>(null);

  const fetchAlerts = async () => {
    try { const data = await gatewayApi.getAnomalies(200); setAlerts(data.alerts); }
    finally { setLoading(false); }
  };
  useEffect(() => { fetchAlerts(); const timer = window.setInterval(fetchAlerts, 10_000); return () => window.clearInterval(timer); }, []);

  const filtered = useMemo(() => alerts.filter((alert) => {
    const query = search.toLowerCase();
    const matchesSearch = !query || [alert.title, alert.reason, alert.agent_id, alert.category, alert.evidence.method].join(' ').toLowerCase().includes(query);
    const matchesSeverity = severity === 'ALL' || alert.severity === severity;
    const matchesStatus = status === 'ALL' || (status === 'ACTIVE' ? !['RESOLVED', 'FALSE_POSITIVE'].includes(alert.status) : alert.status === status);
    return matchesSearch && matchesSeverity && matchesStatus;
  }), [alerts, search, severity, status]);
  const active = alerts.filter((item) => !['RESOLVED', 'FALSE_POSITIVE'].includes(item.status));
  const critical = alerts.filter((item) => item.risk.score >= 90 && !['RESOLVED', 'FALSE_POSITIVE'].includes(item.status));
  const unacknowledged = alerts.filter((item) => item.status === 'NEW');
  const blocked = alerts.filter((item) => item.decision === 'BLOCK');

  const updateStatus = async (next: Alert['status']) => {
    if (!selected) return;
    const updated = await gatewayApi.updateAlertStatus(selected.id, next);
    setAlerts((previous) => previous.map((item) => item.id === updated.id ? updated : item));
    setSelected(updated);
  };

  if (loading) return <LinearProgress sx={{ mt: 4 }} />;
  const cards = [
    ['Active alerts', active.length, 'Open analyst work items', '#ff9800'],
    ['Critical', critical.length, 'Risk score 90 or higher', '#ef5350'],
    ['Unacknowledged', unacknowledged.length, 'Awaiting first review', '#ab47bc'],
    ['Blocked', blocked.length, 'Enforcement decisions', '#90caf9'],
  ];

  return <Box sx={{ p: 3 }}>
    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}><Box><Typography variant="h4" sx={{ fontWeight: 700 }}>Security Alerts</Typography><Typography color="text.secondary">Correlated, explainable decisions for analyst investigation</Typography></Box><Tooltip title="Refresh alerts"><IconButton onClick={fetchAlerts}><RefreshIcon /></IconButton></Tooltip></Box>
    <Grid container spacing={2} sx={{ mb: 3 }}>{cards.map(([label, value, hint, color]) => <Grid key={label as string} size={{ xs: 12, sm: 6, md: 3 }}><Card sx={{ borderTop: `3px solid ${color}` }}><CardContent><Typography variant="overline">{label}</Typography><Typography variant="h3" sx={{ fontWeight: 700 }}>{value}</Typography><Typography variant="caption" color="text.secondary">{hint}</Typography></CardContent></Card></Grid>)}</Grid>
    <Paper sx={{ p: 2, mb: 3 }}><Typography variant="overline">Filter alerts</Typography><Stack direction={{ xs: 'column', md: 'row' }} spacing={1} sx={{ mt: 1 }}><TextField size="small" placeholder="Search agent, tool, reason, or threat" value={search} onChange={(event) => setSearch(event.target.value)} fullWidth /><Select size="small" value={severity} onChange={(event) => setSeverity(event.target.value)}><MenuItem value="ALL">All severities</MenuItem><MenuItem value="HIGH">High</MenuItem><MenuItem value="MEDIUM">Medium</MenuItem><MenuItem value="LOW">Low</MenuItem></Select><Select size="small" value={status} onChange={(event) => setStatus(event.target.value)}><MenuItem value="ACTIVE">Active</MenuItem><MenuItem value="ALL">All statuses</MenuItem>{statuses.map((item) => <MenuItem key={item} value={item}>{item}</MenuItem>)}</Select><Button onClick={() => { setSearch(''); setSeverity('ALL'); setStatus('ACTIVE'); }}>Clear</Button></Stack></Paper>
    <Paper sx={{ overflow: 'hidden' }}><Box sx={{ p: 2 }}><Typography variant="h6">Alert queue</Typography><Typography variant="caption" color="text.secondary">{filtered.length} correlated alerts · raw events remain retained by the gateway</Typography></Box><Divider />
      {filtered.length ? filtered.sort((a, b) => new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime()).map((alert) => <Box key={alert.id} sx={{ p: 2, borderBottom: '1px solid', borderColor: 'divider', display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}><Chip label={alert.severity} color={severityColor(alert.severity)} /><Box sx={{ flex: 1, minWidth: 240 }}><Typography sx={{ fontWeight: 700 }}>{alert.title}</Typography><Typography variant="body2" color="text.secondary">{alert.agent_id} · {alert.evidence.method} · {alert.rule_id} · {alert.occurrence_count} occurrence{alert.occurrence_count === 1 ? '' : 's'}</Typography><Typography variant="caption" color="text.secondary">Last seen {age(alert.last_seen)} · {alert.reason}</Typography></Box><Typography sx={{ fontWeight: 700 }}>Risk {alert.risk.score}/100</Typography><Chip size="small" label={alert.status} variant="outlined" /><Chip size="small" label={alert.decision} color={alert.decision === 'BLOCK' ? 'error' : 'default'} /><Button variant="outlined" onClick={() => setSelected(alert)}>Investigate</Button></Box>) : <Box sx={{ textAlign: 'center', py: 8 }}><CheckCircleIcon color="success" sx={{ fontSize: 48 }} /><Typography>No alerts match the selected filters.</Typography></Box>}
    </Paper>
    <Dialog open={!!selected} onClose={() => setSelected(null)} maxWidth="md" fullWidth>{selected && <><DialogTitle>{selected.id} · {selected.title}</DialogTitle><DialogContent dividers><Stack direction="row" spacing={1} sx={{ mb: 2 }}><Chip label={selected.severity} color={severityColor(selected.severity)} /><Chip label={`Risk ${selected.risk.score}/100`} /><Chip label={selected.decision} color="error" /><Chip label={selected.status} variant="outlined" /></Stack><Grid container spacing={2}><Grid size={{ xs: 12, md: 6 }}><Typography variant="overline">Why Sentinel detected this</Typography><Typography>{selected.evidence.explanation}</Typography><Typography variant="body2" sx={{ mt: 1 }}>Rule: {selected.rule_id} · Source: {selected.type === 'rule_based' ? 'Rule engine' : 'Behavioral model'}</Typography></Grid><Grid size={{ xs: 12, md: 6 }}><Typography variant="overline">Evidence and context</Typography><Typography>Agent: {selected.agent_id}</Typography><Typography>Tool: {selected.evidence.method}</Typography><Typography>First seen: {new Date(selected.first_seen).toLocaleString()}</Typography><Typography>Last seen: {new Date(selected.last_seen).toLocaleString()}</Typography><Typography>Correlated events: {selected.occurrence_count}</Typography></Grid><Grid size={{ xs: 12 }}><Divider sx={{ my: 1 }} /><Typography variant="overline">Recommended actions</Typography><Typography>Review preceding tool activity, verify the agent’s assigned permissions, and retain {selected.rule_id} until the behavior is understood.</Typography></Grid></Grid></DialogContent><DialogActions><Select size="small" value={selected.status} onChange={(event) => updateStatus(event.target.value as Alert['status'])}>{statuses.map((item) => <MenuItem key={item} value={item}>{item}</MenuItem>)}</Select><Button onClick={() => setSelected(null)}>Close</Button></DialogActions></>}</Dialog>
  </Box>;
};

export default AlertsPage;
