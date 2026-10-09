import React, { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  FormControl,
  InputLabel,
  LinearProgress,
  MenuItem,
  Paper,
  Select,
  Snackbar,
  Switch,
  TextField,
  Typography,
} from '@mui/material';
import api from '../services/api';

type Severity = 'low' | 'medium' | 'high';
type SQLMode = 'none' | 'query_tool' | 'readonly';

interface Indicator {
  id: string;
  name: string;
  description: string;
  recommendation: string;
  category: string;
  severity: Severity;
  enabled: boolean;
}

const severityColor = (severity: Severity): 'info' | 'warning' | 'error' =>
  severity === 'high' ? 'error' : severity === 'medium' ? 'warning' : 'info';

const SQLiPolicies: React.FC = () => {
  const [indicators, setIndicators] = useState<Indicator[]>([]);
  const [toolModes, setToolModes] = useState<Record<string, SQLMode>>({});
  const [toolName, setToolName] = useState('');
  const [toolMode, setToolMode] = useState<SQLMode>('query_tool');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const fetchPolicies = useCallback(async () => {
    setLoading(true);
    try {
      const response = await api.get<{ indicators: Indicator[]; tool_modes: Record<string, SQLMode> }>(
        '/api/policies/sqli/indicators',
      );
      setIndicators(response.data.indicators);
      setToolModes(response.data.tool_modes);
      setError('');
    } catch (requestError: any) {
      setError(requestError.response?.data?.detail || 'Could not load SQL injection policies.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchPolicies(); }, [fetchPolicies]);

  const updateIndicator = async (indicator: Indicator, changes: Partial<Pick<Indicator, 'enabled' | 'severity'>>) => {
    setSaving(true);
    try {
      const response = await api.put(`/api/policies/sqli/indicators/${indicator.id}`, changes);
      setIndicators(current => current.map(item => item.id === indicator.id ? { ...item, ...response.data } : item));
      setNotice(`${indicator.id} updated`);
    } catch (requestError: any) {
      setError(requestError.response?.data?.detail || `Could not update ${indicator.id}.`);
    } finally {
      setSaving(false);
    }
  };

  const saveToolMode = async () => {
    if (!toolName.trim()) {
      setError('Enter a tool name first.');
      return;
    }
    setSaving(true);
    try {
      await api.put(
        `/api/policies/sqli/tools/${encodeURIComponent(toolName.trim())}/mode`,
        null,
        { params: { sql_mode: toolMode } },
      );
      setToolModes(current => ({ ...current, [toolName.trim()]: toolMode }));
      setNotice(`${toolName.trim()} mode set to ${toolMode}`);
    } catch (requestError: any) {
      setError(requestError.response?.data?.detail || 'Could not save this tool mode.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Box sx={{ p: 3, maxWidth: 1100, mx: 'auto' }}>
      <Box sx={{ mb: 3 }}>
        <Typography variant="h4" sx={{ fontWeight: 700 }}>SQL Injection Policy</Typography>
        <Typography color="text.secondary">Tune SQLi indicators and SQL expectations for registered tools.</Typography>
      </Box>

      {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>{error}</Alert>}
      <Paper sx={{ p: 2, mb: 3 }}>
        <Typography variant="h6">Tool SQL modes</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          `none` treats SQL-like input as suspicious; `query_tool` checks restricted operations; `readonly` permits SELECT-only behavior.
        </Typography>
        <Box sx={{ display: 'flex', flexDirection: { xs: 'column', sm: 'row' }, alignItems: { sm: 'center' }, gap: 1.5 }}>
          <TextField size="small" label="Tool name" value={toolName} onChange={event => setToolName(event.target.value)} />
          <FormControl size="small" sx={{ minWidth: 170 }}>
            <InputLabel id="sql-mode-label">SQL mode</InputLabel>
            <Select labelId="sql-mode-label" label="SQL mode" value={toolMode} onChange={event => setToolMode(event.target.value as SQLMode)}>
              <MenuItem value="none">none</MenuItem>
              <MenuItem value="query_tool">query_tool</MenuItem>
              <MenuItem value="readonly">readonly</MenuItem>
            </Select>
          </FormControl>
          <Button variant="contained" onClick={saveToolMode} disabled={saving || !toolName.trim()}>
            {saving ? <CircularProgress size={18} color="inherit" /> : 'Save mode'}
          </Button>
        </Box>
        {Object.entries(toolModes).length > 0 && (
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 2 }}>
            {Object.entries(toolModes).map(([name, mode]) => <Chip key={name} label={`${name} · ${mode}`} variant="outlined" onClick={() => { setToolName(name); setToolMode(mode); }} />)}
          </Box>
        )}
      </Paper>

      <Box sx={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', mb: 1 }}>
        <Typography variant="h6">Indicators</Typography>
        <Typography variant="caption" color="text.secondary">{indicators.filter(item => item.enabled).length} enabled</Typography>
      </Box>
      {loading ? <LinearProgress /> : indicators.map(indicator => (
        <Paper key={indicator.id} variant="outlined" sx={{ p: 2, mb: 1.25 }}>
          <Box sx={{ display: 'flex', flexDirection: { xs: 'column', sm: 'row' }, alignItems: { sm: 'center' }, gap: 2 }}>
            <Box sx={{ flex: 1, minWidth: 220 }}>
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, alignItems: 'center', mb: .5 }}>
                <Chip size="small" label={indicator.id} />
                <Typography sx={{ fontWeight: 600 }}>{indicator.name}</Typography>
                <Chip size="small" label={indicator.severity} color={severityColor(indicator.severity)} />
              </Box>
              <Typography variant="body2" color="text.secondary">{indicator.description}</Typography>
            </Box>
            <Typography variant="caption" color="text.secondary" sx={{ maxWidth: 280 }}>{indicator.recommendation}</Typography>
            <FormControl size="small" sx={{ minWidth: 120 }}>
              <InputLabel id={`${indicator.id}-severity`}>Severity</InputLabel>
              <Select
                labelId={`${indicator.id}-severity`}
                label="Severity"
                value={indicator.severity}
                onChange={event => updateIndicator(indicator, { severity: event.target.value as Severity })}
                disabled={saving}
              >
                <MenuItem value="low">Low</MenuItem>
                <MenuItem value="medium">Medium</MenuItem>
                <MenuItem value="high">High</MenuItem>
              </Select>
            </FormControl>
            <Box sx={{ display: 'flex', gap: .5, alignItems: 'center' }}>
              <Switch checked={indicator.enabled} onChange={(_, checked) => updateIndicator(indicator, { enabled: checked })} disabled={saving} slotProps={{ input: { 'aria-label': `Enable ${indicator.id}` } }} />
              <Typography variant="caption">{indicator.enabled ? 'On' : 'Off'}</Typography>
            </Box>
          </Box>
        </Paper>
      ))}
      <Snackbar open={!!notice} autoHideDuration={2500} onClose={() => setNotice('')} message={notice} />
    </Box>
  );
};

export default SQLiPolicies;