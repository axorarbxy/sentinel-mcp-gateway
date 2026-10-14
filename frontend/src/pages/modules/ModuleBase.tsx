// pages/modules/ModuleBase.tsx
import React, { useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Grid,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Alert,
  Divider,
} from '@mui/material';
import {
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
} from '@mui/icons-material';


interface ModuleBaseProps {
  title: string;
  icon: React.ReactNode;
  description: string;
  inputLabel: string;
  inputPlaceholder: string;
  inputType: 'url' | 'file' | 'network' | 'user' | 'android' | 'password' | 'qr';
  onAnalyze: (input: string) => Promise<any>;
}

const ModuleBase: React.FC<ModuleBaseProps> = ({
  title,
  icon,
  description,
  inputLabel,
  inputPlaceholder,
  inputType,
  onAnalyze,
}) => {
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAnalyze = async () => {
    if (!input.trim()) {
      setError('Please enter something to analyze');
      return;
    }

    setLoading(true);
    setError(null);
    setResults(null);

    try {
      const response = await onAnalyze(input);
      setResults(response);
    } catch (err: any) {
      setError(err.message || 'Analysis failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'error';
      case 'HIGH':
        return 'error';
      case 'MEDIUM':
        return 'warning';
      case 'LOW':
        return 'info';
      default:
        return 'default';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return <ErrorIcon />;
      case 'HIGH':
        return <WarningIcon />;
      case 'MEDIUM':
        return <WarningIcon />;
      case 'LOW':
        return <InfoIcon />;
      default:
        return <InfoIcon />;
    }
  };
  const passwordAnalysis = inputType === 'password' ? results?.analysis : null;
  const issueCount = passwordAnalysis?.issues?.length ?? results?.results?.length ?? 0;
  const highestSeverity = passwordAnalysis?.severity || results?.results?.reduce((max: any, r: any) => {
    const severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    const current = severities.indexOf(r.severity);
    const maxSev = severities.indexOf(max?.severity || 'LOW');
    return current > maxSev ? r : max;
  }, { severity: 'LOW' })?.severity || 'N/A';

  return (
    <Box sx={{ p: 3, maxWidth: 1200, mx: 'auto' }}>
      {/* Header */}
      <Paper sx={{ p: 3, mb: 3, bgcolor: 'rgba(23, 18, 20,0.8)' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <Box sx={{ fontSize: 40 }}>{icon}</Box>
          <Box>
            <Typography variant="h4" sx={{ fontWeight: 600 }}>
              {title}
            </Typography>
            <Typography variant="body2" color="textSecondary">
              {description}
            </Typography>
          </Box>
        </Box>
      </Paper>

      {/* Input Section */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          {inputLabel}
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
          <TextField
            fullWidth
            multiline
            rows={inputType === 'file' ? 3 : 2}
            placeholder={inputPlaceholder}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            variant="outlined"
            sx={{ flex: 1 }}
            disabled={loading}
          />
          <Button
            variant="contained"
            onClick={handleAnalyze}
            disabled={loading || !input.trim()}
            sx={{
              minWidth: 120,
              py: 1.5,
              borderRadius: 2,
              background: 'linear-gradient(135deg, #6D001A, #8A1733)',
              '&:hover': {
                background: 'linear-gradient(135deg, #8A1733, #4A0012)',
              },
            }}
          >
            {loading ? <CircularProgress size={24} color="inherit" /> : 'Analyze'}
          </Button>
        </Box>
        {error && (
          <Alert severity="error" sx={{ mt: 2 }}>
            {error}
          </Alert>
        )}
      </Paper>

      {/* Results Section */}
      {results && (
        <>
          {/* Risk Score Card */}
          <Paper sx={{ p: 3, mb: 3 }}>
            <Grid container spacing={3}>
              <Grid size={{ xs: 12, md: 4 }}>
                <Card sx={{ textAlign: 'center', bgcolor: 'rgba(0,0,0,0.2)' }}>
                  <CardContent>
                    <Typography color="textSecondary" gutterBottom>
                      Risk Score
                    </Typography>
                    <Typography variant="h2" sx={{ fontWeight: 700 }}>
                      {((results.risk_score ?? 0) * 100).toFixed(0)}%
                    </Typography>
                    <Chip
                      label={results.risk_score > 0.7 ? 'HIGH' : results.risk_score > 0.4 ? 'MEDIUM' : 'LOW'}
                      color={results.risk_score > 0.7 ? 'error' : results.risk_score > 0.4 ? 'warning' : 'success'}
                      sx={{ mt: 1 }}
                    />
                  </CardContent>
                </Card>
              </Grid>
              <Grid size={{ xs: 12, md: 4 }}>
                <Card sx={{ textAlign: 'center', bgcolor: 'rgba(0,0,0,0.2)' }}>
                  <CardContent>
                    <Typography color="textSecondary" gutterBottom>
                      {passwordAnalysis ? 'Password findings' : 'Total Events'}
                    </Typography>
                    <Typography variant="h2" sx={{ fontWeight: 700 }}>
                      {issueCount}
                    </Typography>
                    <Chip
                      label={passwordAnalysis
                        ? issueCount > 0 ? 'Recommendations' : 'No Issues'
                        : results.results?.length > 0 ? 'Alerts Found' : 'No Issues'}
                      color={issueCount > 0 ? 'warning' : 'success'}
                      sx={{ mt: 1 }}
                    />
                  </CardContent>
                </Card>
              </Grid>
              <Grid size={{ xs: 12, md: 4 }}>
                <Card sx={{ textAlign: 'center', bgcolor: 'rgba(0,0,0,0.2)' }}>
                  <CardContent>
                    <Typography color="textSecondary" gutterBottom>
                      Highest Severity
                    </Typography>
                    <Typography variant="h2" sx={{ fontWeight: 700 }}>
                      {highestSeverity}
                    </Typography>
                    <Chip
                      label={passwordAnalysis ? `${passwordAnalysis.strength} password` : 'Highest Alert'}
                      color={passwordAnalysis
                        ? passwordAnalysis.severity === 'HIGH' ? 'error' : passwordAnalysis.severity === 'MEDIUM' ? 'warning' : 'success'
                        : 'warning'}
                      sx={{ mt: 1 }}
                    />
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </Paper>

          {/* Detailed Results */}
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Detailed Results
            </Typography>
            <Divider sx={{ mb: 2 }} />

            {passwordAnalysis && (
              <Box sx={{ mb: 3 }}>
                <Typography variant="body1">
                  Strength: <strong>{passwordAnalysis.strength}</strong>
                  {' · '}
                  Strength score: <strong>{(passwordAnalysis.strength_score * 100).toFixed(0)}%</strong>
                  {' · '}
                  Estimated entropy: <strong>{passwordAnalysis.entropy.toFixed(1)} bits</strong>
                </Typography>
                {passwordAnalysis.issues.length > 0 && (
                  <Box component="ul" sx={{ mt: 1 }}>
                    {passwordAnalysis.issues.map((issue: string) => (
                      <li key={issue}><Typography variant="body2">{issue}</Typography></li>
                    ))}
                  </Box>
                )}
              </Box>
            )}

            {results.results && results.results.length === 0 && issueCount === 0 ? (
              <Box sx={{ textAlign: 'center', py: 4 }}>
                <CheckCircleIcon sx={{ fontSize: 48, color: 'success.main' }} />
                <Typography variant="h6" color="success.main" sx={{ mt: 2 }}>
                  No threats detected!
                </Typography>
                <Typography variant="body2" color="textSecondary">
                  All checks passed successfully.
                </Typography>
              </Box>
            ) : (
              results.results?.map((result: any, index: number) => (
                <Card
                  key={index}
                  sx={{
                    mb: 2,
                    bgcolor: 'rgba(0,0,0,0.2)',
                    borderLeft: `4px solid ${
                      result.severity === 'CRITICAL' ? '#f44336' :
                      result.severity === 'HIGH' ? '#ff9800' :
                      result.severity === 'MEDIUM' ? '#ffc107' :
                      '#4caf50'
                    }`,
                  }}
                >
                  <CardContent>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                      <Box>
                        <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                          {result.module}
                        </Typography>
                        <Typography variant="body2" color="textSecondary">
                          {result.description}
                        </Typography>
                      </Box>
                      <Chip
                        label={result.severity}
                        color={getSeverityColor(result.severity)}
                        size="small"
                        icon={getSeverityIcon(result.severity)}
                      />
                    </Box>
                    {result.confidence && (
                      <Box sx={{ mt: 1 }}>
                        <Typography variant="caption" color="textSecondary">
                          Confidence: {(result.confidence * 100).toFixed(0)}%
                        </Typography>
                      </Box>
                    )}
                    {result.data && Object.keys(result.data).length > 0 && (
                      <Box sx={{ mt: 1 }}>
                        <Typography variant="caption" color="textSecondary">
                          Details:
                        </Typography>
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>
                          {Object.entries(result.data).map(([key, value]) => (
                            <Chip
                              key={key}
                              size="small"
                              label={`${key}: ${JSON.stringify(value)}`}
                              variant="outlined"
                            />
                          ))}
                        </Box>
                      </Box>
                    )}
                  </CardContent>
                </Card>
              ))
            )}
          </Paper>
        </>
      )}
    </Box>
  );
};

export default ModuleBase;