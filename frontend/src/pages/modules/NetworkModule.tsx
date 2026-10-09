// pages/modules/NetworkModule.tsx
import React, { useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Paper,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tabs,
  Typography,
} from '@mui/material';
import UploadFileIcon from '@mui/icons-material/UploadFile';
import ModuleBase from './ModuleBase';
import api from '../../services/api';

interface FlowResult {
  row: number;
  prediction: 'attack' | 'benign';
  attack_probability: number;
}

interface FlowModelInfo {
  loaded: boolean;
  error?: string;
  metrics?: {
    accuracy?: number;
    recall?: number;
    roc_auc?: number;
  };
}

const NetworkModule: React.FC = () => {
  const [tab, setTab] = useState(0);
  const [file, setFile] = useState<File | null>(null);
  const [modelInfo, setModelInfo] = useState<FlowModelInfo | null>(null);
  const [results, setResults] = useState<FlowResult[]>([]);
  const [attacksFlagged, setAttacksFlagged] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    api.get<FlowModelInfo>('/api/ml/network-flow/model-info')
      .then(response => setModelInfo(response.data))
      .catch(() => setModelInfo({ loaded: false, error: 'Model status is unavailable' }));
  }, []);

  const handleAnalyze = async (input: string) => {
    let networkData;
    try {
      networkData = JSON.parse(input);
    } catch {
      const parts = input.split(' ');
      networkData = {
        src_ip: parts[0] || '',
        dst_ip: parts[1] || '',
        dst_port: parseInt(parts[2], 10) || 0,
        protocol: parts[3] || 'TCP',
        payload: parts.slice(4).join(' ') || '',
      };
    }

    const response = await api.post('/cybereye/analyze', {
      type: 'network',
      data: networkData,
    });
    return response.data;
  };

  const scoreFlows = async () => {
    if (!file) {
      setError('Choose a CSV file first.');
      return;
    }
    setLoading(true);
    setError('');
    setResults([]);
    try {
      const csv = await file.text();
      const response = await api.post('/api/ml/network-flow/score', csv, {
        headers: { 'Content-Type': 'text/csv' },
        timeout: 60000,
        transformRequest: [(body) => body],
      });
      setResults(response.data.results);
      setAttacksFlagged(response.data.attacks_flagged);
    } catch (requestError: any) {
      setError(requestError.response?.data?.detail || 'Could not score this CSV. Check its columns and try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box sx={{ p: 3, maxWidth: 1200, mx: 'auto' }}>
      <Paper sx={{ p: 3, mb: 2, bgcolor: 'rgba(26,35,50,0.8)' }}>
        <Typography variant="h4" sx={{ fontWeight: 600 }}>Network Security</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
          Analyze flow records with the UNSW-NB15 classifier or run a quick heuristic check.
        </Typography>
      </Paper>
      <Tabs value={tab} onChange={(_, value) => setTab(value)} aria-label="Network analysis mode">
        <Tab label="Flow classifier" />
        <Tab label="Quick network check" />
      </Tabs>

      {tab === 0 ? (
        <Box sx={{ pt: 2 }}>
          <Paper sx={{ p: 3, mb: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
              <Box>
                <Typography variant="h6">UNSW-NB15 flow model</Typography>
                <Typography variant="body2" color="text.secondary">
                  Scores each flow as benign or attack. Upload a CSV with the UNSW-NB15 feature columns; label, attack_cat, and id are ignored.
                </Typography>
              </Box>
              <Chip
                label={modelInfo?.loaded ? 'Model ready' : 'Model unavailable'}
                color={modelInfo?.loaded ? 'success' : 'warning'}
                variant="outlined"
              />
            </Box>
            {modelInfo?.loaded && modelInfo.metrics && (
              <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                Held-out test: {(Number(modelInfo.metrics.roc_auc || 0) * 100).toFixed(1)}% ROC-AUC · {(Number(modelInfo.metrics.recall || 0) * 100).toFixed(1)}% attack recall
              </Typography>
            )}
          </Paper>

          <Paper sx={{ p: 3, mb: 2 }}>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              CSV limit: 250 rows and 2 MB. The upload is analyzed in memory and is not stored.
            </Typography>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
              <Button component="label" variant="outlined" startIcon={<UploadFileIcon />}>
                Choose CSV
                <input
                  hidden
                  type="file"
                  accept=".csv,text/csv"
                  onChange={event => {
                    setFile(event.target.files?.[0] || null);
                    setResults([]);
                    setError('');
                  }}
                />
              </Button>
              <Typography variant="body2" color="text.secondary">
                {file?.name || 'No file selected'}
              </Typography>
              <Button variant="contained" onClick={scoreFlows} disabled={loading || !file || !modelInfo?.loaded}>
                {loading ? <CircularProgress size={20} color="inherit" /> : 'Analyze flows'}
              </Button>
            </Box>
            {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
            {modelInfo?.error && <Alert severity="warning" sx={{ mt: 2 }}>{modelInfo.error}</Alert>}
          </Paper>

          {results.length > 0 && (
            <Paper sx={{ p: 3 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                <Typography variant="h6">Analysis results</Typography>
                <Chip label={`${results.length} flows`} size="small" />
                <Chip label={`${attacksFlagged} flagged`} color={attacksFlagged ? 'error' : 'success'} size="small" />
              </Box>
              <TableContainer sx={{ maxHeight: 480 }}>
                <Table stickyHeader size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Row</TableCell>
                      <TableCell>Classification</TableCell>
                      <TableCell align="right">Attack probability</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {results.map(result => (
                      <TableRow key={result.row}>
                        <TableCell>{result.row}</TableCell>
                        <TableCell>
                          <Chip label={result.prediction} color={result.prediction === 'attack' ? 'error' : 'success'} size="small" />
                        </TableCell>
                        <TableCell align="right">{(result.attack_probability * 100).toFixed(1)}%</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
              <Alert severity="info" sx={{ mt: 2 }}>
                Model estimates are triage signals, not proof of compromise. Review flagged flows and false-positive risk.
              </Alert>
            </Paper>
          )}
        </Box>
      ) : (
        <Box sx={{ pt: 2 }}>
          <ModuleBase
            title="Quick Network Check"
            icon="🌐"
            description="Check a single network event for suspicious ports, payload signatures, and traffic patterns."
            inputLabel="Enter a network event"
            inputPlaceholder="JSON or: 192.168.1.100 203.0.113.1 22 TCP failed login attempt"
            inputType="network"
            onAnalyze={handleAnalyze}
          />
        </Box>
      )}
    </Box>
  );
};

export default NetworkModule;