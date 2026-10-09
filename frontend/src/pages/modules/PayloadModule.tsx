import React, { useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  LinearProgress,
  Paper,
  TextField,
  Typography,
} from '@mui/material';
import api from '../../services/api';

interface PayloadResult {
  score: number;
  label: number;
  top_signals: string[];
  decision: 'ALLOW' | 'WARN' | 'BLOCK';
  fallback: boolean;
  model_version: string;
}

interface ModelInfo {
  loaded: boolean;
  fallback: boolean;
  model_version: string;
  thresholds: { warn: number; block: number };
}

const PayloadModule: React.FC = () => {
  const [payload, setPayload] = useState('');
  const [result, setResult] = useState<PayloadResult | null>(null);
  const [modelInfo, setModelInfo] = useState<ModelInfo | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    api.get<ModelInfo>('/api/ml/model-info')
      .then(response => setModelInfo(response.data))
      .catch(() => setModelInfo(null));
  }, []);

  const analyzePayload = async () => {
    if (!payload.trim()) {
      setError('Enter a payload to analyze.');
      return;
    }
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const response = await api.post<PayloadResult>('/api/ml/score', { payload });
      setResult(response.data);
    } catch (requestError: any) {
      setError(requestError.response?.data?.detail || 'Payload analysis failed.');
    } finally {
      setLoading(false);
    }
  };

  const decisionColor = result?.decision === 'BLOCK' ? 'error' : result?.decision === 'WARN' ? 'warning' : 'success';

  return (
    <Box sx={{ p: 3, maxWidth: 1000, mx: 'auto' }}>
      <Paper sx={{ p: 3, mb: 2, bgcolor: 'rgba(26,35,50,0.8)' }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
          <Box>
            <Typography variant="h4" sx={{ fontWeight: 600 }}>Payload Analyzer</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              Score text arguments for suspicious command, SQL, and path patterns.
            </Typography>
          </Box>
          <Chip
            label={modelInfo?.loaded ? `Ready · ${modelInfo.model_version}` : 'Model unavailable'}
            color={modelInfo?.loaded ? 'success' : 'warning'}
            variant="outlined"
          />
        </Box>
      </Paper>

      <Paper sx={{ p: 3, mb: 2 }}>
        <TextField
          fullWidth
          multiline
          minRows={5}
          maxRows={14}
          label="Payload text"
          placeholder="Paste a tool argument, command, URL, or query"
          value={payload}
          onChange={event => setPayload(event.target.value)}
          disabled={loading}
        />
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mt: 2 }}>
          <Button variant="contained" onClick={analyzePayload} disabled={loading || !payload.trim()}>
            {loading ? <CircularProgress size={20} color="inherit" /> : 'Analyze payload'}
          </Button>
          {modelInfo && (
            <Typography variant="caption" color="text.secondary">
              Warn at {(modelInfo.thresholds.warn * 100).toFixed(0)}% · block at {(modelInfo.thresholds.block * 100).toFixed(0)}%
            </Typography>
          )}
        </Box>
        {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      </Paper>

      {result && (
        <Paper sx={{ p: 3 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
            <Box>
              <Typography variant="overline" color="text.secondary">Classifier decision</Typography>
              <Typography variant="h4">{result.decision}</Typography>
            </Box>
            <Chip label={`${(result.score * 100).toFixed(1)}% risk`} color={decisionColor} />
          </Box>
          <LinearProgress
            variant="determinate"
            value={Math.min(100, Math.max(0, result.score * 100))}
            color={decisionColor}
            sx={{ mt: 2, height: 8, borderRadius: 1 }}
          />
          <Typography variant="subtitle2" sx={{ mt: 2 }}>Signals</Typography>
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mt: 1 }}>
            {result.top_signals.map(signal => <Chip key={signal} label={signal} size="small" variant="outlined" />)}
          </Box>
          {result.fallback && <Alert severity="warning" sx={{ mt: 2 }}>No model score was produced; do not treat this result as a safe verdict.</Alert>}
          <Alert severity="info" sx={{ mt: 2 }}>
            Advisory analysis only. Gateway policy rules remain authoritative for live MCP requests.
          </Alert>
        </Paper>
      )}
    </Box>
  );
};

export default PayloadModule;