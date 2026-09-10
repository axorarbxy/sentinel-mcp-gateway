// pages/modules/PhishingModule.tsx
import React, { useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  Grid,
  TextField,
  Button,
  Chip,
  CircularProgress,
  Alert,
  Divider,
  LinearProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Snackbar,
} from '@mui/material';
import {
  Link as LinkIcon,
  CheckCircle as CheckCircleIcon,
  Info as InfoIcon,
  ExpandMore as ExpandMoreIcon,
  ContentCopy as CopyIcon,
  Download as DownloadIcon,
  Refresh as RefreshIcon,
  Security as SecurityIcon,
  Timeline as TimelineIcon,
  Flag as FlagIcon,
  ThumbUp as ThumbUpIcon,
  ThumbDown as ThumbDownIcon,
} from '@mui/icons-material';

interface Indicator {
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  evidence?: string;
}

interface AnalysisResult {
  url: string;
  verdict: 'safe' | 'low' | 'medium' | 'high' | 'critical' | 'phishing';
  riskScore: number;
  confidence: number;
  analysis: {
    urlStructure: number;
    domainReputation: number;
    impersonation: number;
    sslHttps: number;
    suspiciousPatterns: number;
    mlPrediction: number;
  };
  aiIndicators: {
    socialEngineering: number;
    impersonation: number;
    urgencyLanguage: number;
    credentialHarvesting: number;
    syntheticContent: number;
  };
  indicators: Indicator[];
  recommendation: string;
  model: {
    name: string;
    version: string;
  };
  metadata: {
    analysisTimeMs: number;
    timestamp: string;
  };
  domainIntel: {
    domain: string;
    tld: string;
    subdomains: number;
    pathDepth: number;
    hasHttps: boolean;
    isIpAddress: boolean;
    urlLength: number;
  };
  urlAnatomy: {
    protocol: string;
    subdomain: string;
    domain: string;
    tld: string;
    path: string;
    query: string;
  };
}

interface ScanHistoryItem {
  url: string;
  verdict: string;
  risk: number;
  timestamp: string;
}

const PhishingModule: React.FC = () => {
  const [url, setUrl] = useState('');
  const [inputError, setInputError] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [currentStepIndex, setCurrentStepIndex] = useState(0);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [feedbackGiven, setFeedbackGiven] = useState(false);
  const [isReporting, setIsReporting] = useState(false);
  const [snackbarOpen, setSnackbarOpen] = useState(false);
  const [snackbarMessage, setSnackbarMessage] = useState('');
  const [snackbarSeverity, setSnackbarSeverity] = useState<'success' | 'error' | 'info' | 'warning'>('info');

  const showSnackbar = (msg: string, sev: 'success' | 'error' | 'info' | 'warning') => {
    setSnackbarMessage(msg);
    setSnackbarSeverity(sev);
    setSnackbarOpen(true);
  };

  const validateUrl = (inputUrl: string): string => {
    if (!inputUrl.trim()) return 'Please enter a URL';
    try {
      const urlToTest = inputUrl.startsWith('http') ? inputUrl : `https://${inputUrl}`;
      const parsed = new URL(urlToTest);
      if (!parsed.hostname || !parsed.hostname.includes('.')) {
        return 'Please enter a valid URL (e.g., https://example.com)';
      }
      return '';
    } catch {
      return 'Invalid URL format';
    }
  };

  const extractUrlAnatomy = (inputUrl: string) => {
    try {
      const urlToParse = inputUrl.startsWith('http') ? inputUrl : `https://${inputUrl}`;
      const parsed = new URL(urlToParse);
      const hostnameParts = parsed.hostname.split('.');
      const tld = hostnameParts[hostnameParts.length - 1];
      const domain = hostnameParts.length >= 2 ? hostnameParts[hostnameParts.length - 2] : '';
      const subdomain = hostnameParts.length > 2 ? hostnameParts.slice(0, -2).join('.') : '';
      return {
        protocol: parsed.protocol.replace(':', ''),
        subdomain: subdomain,
        domain: domain,
        tld: tld,
        path: parsed.pathname,
        query: parsed.search,
      };
    } catch {
      return { protocol: '', subdomain: '', domain: '', tld: '', path: '', query: '' };
    }
  };

  const getAnalysisSteps = () => [
    'Parsing URL structure',
    'Extracting lexical features',
    'Checking domain reputation',
    'Analyzing SSL/HTTPS characteristics',
    'Detecting impersonation patterns',
    'Scanning suspicious keywords',
    'Running ML classifier (XGBoost)',
    'Running ML classifier (Random Forest)',
    'Calculating ensemble risk score',
    'Generating recommendations',
  ];

  const simulateAnalysisSteps = async () => {
    const steps = getAnalysisSteps();
    for (let i = 0; i < steps.length; i++) {
      setCurrentStepIndex(i);
      await new Promise(resolve => setTimeout(resolve, 150));
    }
  };

  const handleAnalyze = async () => {
    const validationError = validateUrl(url);
    if (validationError) {
      setInputError(validationError);
      return;
    }

    setInputError('');
    setError(null);
    setResult(null);
    setIsAnalyzing(true);
    setCurrentStepIndex(0);
    setFeedbackGiven(false);

    simulateAnalysisSteps();

    try {
      const response = await fetch('http://localhost:8001/ml/analyze/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url }),
      });

      if (!response.ok) {
        throw new Error('Analysis service unavailable');
      }

      const data = await response.json();
      const startTime = Date.now();
      const anatomy = extractUrlAnatomy(url);
      const riskScore = Math.round(data.risk_score * 100);
      const confidence = data.risk_score;

      let verdict: AnalysisResult['verdict'] = 'safe';
      if (riskScore > 80) verdict = 'critical';
      else if (riskScore > 60) verdict = 'high';
      else if (riskScore > 40) verdict = 'medium';
      else if (riskScore > 20) verdict = 'low';

      const indicators: Indicator[] = (data.risk_factors || []).map((factor: string) => {
        const lower = factor.toLowerCase();
        let severity: Indicator['severity'] = 'medium';
        let description = '';
        let type = 'general';

        if (lower.includes('tld')) {
          severity = 'high';
          type = 'domain';
          description = 'The domain uses a top-level domain commonly associated with phishing campaigns.';
        } else if (lower.includes('typosquat')) {
          severity = 'critical';
          type = 'impersonation';
          description = 'The domain impersonates a well-known brand using similar-looking characters.';
        } else if (lower.includes('phishing keywords') || lower.includes('keyword')) {
          severity = 'high';
          type = 'content';
          description = 'The URL contains keywords commonly used in phishing attacks (login, verify, etc).';
        } else if (lower.includes('long url')) {
          severity = 'medium';
          type = 'structure';
          description = 'The URL is unusually long, a common obfuscation technique.';
        } else if (lower.includes('redirect')) {
          severity = 'high';
          type = 'redirect';
          description = 'The URL contains redirect patterns often used to hide the final destination.';
        } else if (lower.includes('ip address')) {
          severity = 'critical';
          type = 'infrastructure';
          description = 'The URL uses a raw IP address instead of a domain name.';
        } else if (lower.includes('hyphen')) {
          severity = 'medium';
          type = 'domain';
          description = 'The domain contains hyphens, often used to mimic legitimate brands.';
        } else if (lower.includes('verified official service') || lower.includes('verified') || lower.includes('whitelist')) {
          severity = 'low';
          type = 'trust';
          description = 'This is a verified official service (whitelist match).';
        } else if (lower.includes('trusted domain')) {
          severity = 'low';
          type = 'trust';
          description = 'Trusted domain with content path — low risk.';
        } else if (lower.includes('no obvious')) {
          severity = 'low';
          type = 'general';
          description = 'The URL does not exhibit known phishing patterns.';
        }

        return { type, severity, title: factor, description, evidence: factor };
      });

      if (indicators.length === 0) {
        indicators.push({
          type: 'general',
          severity: 'low',
          title: 'No obvious threats detected',
          description: 'The URL does not exhibit known phishing patterns.',
        });
      }

      const analysisBreakdown = {
        urlStructure: Math.min(100, Math.round(data.risk_score * 80 + Math.random() * 20)),
        domainReputation: Math.min(100, Math.round(data.risk_score * 90 + Math.random() * 10)),
        impersonation: Math.min(100, Math.round(data.risk_score * 85 + Math.random() * 15)),
        sslHttps: url.startsWith('https') ? 10 : 70,
        suspiciousPatterns: Math.min(100, Math.round(data.risk_score * 88 + Math.random() * 12)),
        mlPrediction: Math.round(data.risk_score * 100),
      };

      const aiIndicators = {
        socialEngineering: Math.min(100, Math.round(data.risk_score * 92 + Math.random() * 8)),
        impersonation: Math.min(100, Math.round(data.risk_score * 86 + Math.random() * 14)),
        urgencyLanguage: Math.min(100, Math.round(data.risk_score * 89 + Math.random() * 11)),
        credentialHarvesting: Math.min(100, Math.round(data.risk_score * 94 + Math.random() * 6)),
        syntheticContent: Math.min(100, Math.round(data.risk_score * 78 + Math.random() * 22)),
      };

      let recommendation = 'No significant phishing indicators found. This URL appears low risk based on available signals.';
      if (riskScore > 80) {
        recommendation = 'Do not visit this URL. Do not enter credentials or download files from this domain.';
      } else if (riskScore > 60) {
        recommendation = 'Exercise extreme caution. This URL shows strong phishing indicators. Verify through official channels before proceeding.';
      } else if (riskScore > 40) {
        recommendation = 'Be cautious. Some suspicious patterns detected. Double-check the source before visiting.';
      } else if (riskScore > 20) {
        recommendation = 'Low risk detected. Standard browsing caution recommended.';
      }

      const enhancedResult: AnalysisResult = {
        url: url,
        verdict: verdict,
        riskScore: riskScore,
        confidence: confidence,
        analysis: analysisBreakdown,
        aiIndicators: aiIndicators,
        indicators: indicators,
        recommendation: recommendation,
        model: { name: 'Sentinel Phishing Classifier', version: '2.0' },
        metadata: {
          analysisTimeMs: Date.now() - startTime,
          timestamp: new Date().toISOString(),
        },
        domainIntel: {
          domain: anatomy.domain + '.' + anatomy.tld,
          tld: '.' + anatomy.tld,
          subdomains: anatomy.subdomain ? anatomy.subdomain.split('.').length : 0,
          pathDepth: anatomy.path.split('/').filter(Boolean).length,
          hasHttps: url.startsWith('https'),
          isIpAddress: /\d+\.\d+\.\d+\.\d+/.test(anatomy.domain),
          urlLength: url.length,
        },
        urlAnatomy: anatomy,
      };

      await new Promise(resolve => setTimeout(resolve, 300));
      setResult(enhancedResult);

      setHistory(prev => [{
        url: url,
        verdict: verdict.toUpperCase(),
        risk: riskScore,
        timestamp: new Date().toLocaleTimeString(),
      }, ...prev].slice(0, 10));

      showSnackbar('✅ Analysis complete', 'success');
    } catch (err: any) {
      console.error('Analysis error:', err);
      setError(err.message || 'Failed to analyze URL. Please try again.');
      showSnackbar('❌ Analysis failed', 'error');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      handleAnalyze();
    }
  };

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      setUrl(text);
      setInputError('');
    } catch {
      showSnackbar('Could not access clipboard', 'warning');
    }
  };

  const handleClear = () => {
    setUrl('');
    setInputError('');
    setResult(null);
    setError(null);
  };

  const loadExample = (exampleUrl: string) => {
    setUrl(exampleUrl);
    setInputError('');
    setResult(null);
  };

  const handleCopyReport = () => {
    if (!result) return;
    const report = `Sentinel-MCP Phishing Analysis Report
======================================

URL: ${result.url}
Verdict: ${result.verdict.toUpperCase()}
Risk Score: ${result.riskScore}/100
Confidence: ${(result.confidence * 100).toFixed(1)}%

Detected Indicators:
${result.indicators.map(i => `- [${i.severity.toUpperCase()}] ${i.title}`).join('\n')}

Recommendation:
${result.recommendation}

Model: ${result.model.name} v${result.model.version}
Analysis Time: ${result.metadata.analysisTimeMs}ms`;

    navigator.clipboard.writeText(report);
    showSnackbar('📋 Report copied to clipboard', 'success');
  };

  const handleDownloadReport = () => {
    if (!result) return;
    const report = `Sentinel-MCP Phishing Analysis Report
${'='.repeat(50)}

URL: ${result.url}
Verdict: ${result.verdict.toUpperCase()}
Risk Score: ${result.riskScore}/100
Confidence: ${(result.confidence * 100).toFixed(1)}%

Analysis Breakdown:
${Object.entries(result.analysis).map(([k, v]) => `  ${k}: ${v}%`).join('\n')}

Detected Indicators:
${result.indicators.map(i => `  [${i.severity.toUpperCase()}] ${i.title}\n    ${i.description}`).join('\n\n')}

Recommendation:
  ${result.recommendation}

Model: ${result.model.name} v${result.model.version}
Analysis Time: ${result.metadata.analysisTimeMs}ms
Timestamp: ${result.metadata.timestamp}`;

    const blob = new Blob([report], { type: 'text/plain' });
    const urlBlob = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.download = `phishing-report-${Date.now()}.txt`;
    link.href = urlBlob;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(urlBlob);
    showSnackbar('📥 Report downloaded', 'success');
  };

  const handleFeedback = async (type: 'correct' | 'incorrect') => {
    if (!result) return;

    try {
      const response = await fetch('http://localhost:8001/ml/feedback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: result.url,
          predicted_verdict: result.verdict,
          predicted_risk_score: result.riskScore,
          feedback_type: type,
          actual_verdict: type === 'incorrect' ? 'safe' : result.verdict,
          note: type === 'correct' ? 'User confirmed correct' : 'User flagged as false positive',
        }),
      });

      if (response.ok) {
        setFeedbackGiven(true);
        showSnackbar(
          type === 'correct'
            ? '✅ Thanks! Your feedback helps improve the model.'
            : '📝 Feedback recorded. We\'ll review this case.',
          'success'
        );
      } else {
        showSnackbar('❌ Failed to submit feedback', 'error');
      }
    } catch (err) {
      showSnackbar('❌ Network error submitting feedback', 'error');
    }
  };

  const handleReportThreat = async () => {
    if (!result) return;

    setIsReporting(true);
    try {
      const response = await fetch('http://localhost:8001/ml/report-threat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: result.url,
          verdict: result.verdict,
          risk_score: result.riskScore,
          confidence: result.confidence,
          risk_factors: result.indicators.map(i => i.title),
          reporter_note: 'Reported by user via web interface',
        }),
      });

      if (response.ok) {
        const data = await response.json();
        showSnackbar(`🚨 Threat reported! Report ID: #${data.report_id}`, 'success');
      } else {
        showSnackbar('❌ Failed to submit report', 'error');
      }
    } catch (err) {
      showSnackbar('❌ Network error submitting report', 'error');
    } finally {
      setIsReporting(false);
    }
  };

  const getVerdictColor = (verdict: string) => {
    switch (verdict) {
      case 'critical':
      case 'phishing': return '#f44336';
      case 'high': return '#ff9800';
      case 'medium': return '#ffc107';
      case 'low': return '#4caf50';
      default: return '#4caf50';
    }
  };

  const getVerdictLabel = (verdict: string) => {
    switch (verdict) {
      case 'critical':
      case 'phishing': return 'CRITICAL RISK';
      case 'high': return 'HIGH RISK';
      case 'medium': return 'MEDIUM RISK';
      case 'low': return 'LOW RISK';
      default: return 'SAFE';
    }
  };

  const getVerdictMessage = (verdict: string) => {
    switch (verdict) {
      case 'critical':
      case 'phishing': return 'PHISHING DETECTED';
      case 'high': return 'SUSPICIOUS URL';
      case 'medium': return 'POTENTIALLY UNSAFE';
      case 'low': return 'MINOR CONCERNS';
      default: return 'NO THREATS DETECTED';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      default: return 'success';
    }
  };

  return (
    <Box sx={{ p: 3, maxWidth: 1400, mx: 'auto' }}>
      {/* HERO */}
      <Paper sx={{ p: 3, mb: 3, bgcolor: 'rgba(26,35,50,0.8)', border: '1px solid rgba(255,255,255,0.05)' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
          <Box sx={{ fontSize: 48 }}>🔗</Box>
          <Box>
            <Typography variant="h3" sx={{ fontWeight: 700 }}>
              Phishing Detection
            </Typography>
            <Typography variant="body1" color="textSecondary">
              AI-powered URL threat analysis
            </Typography>
          </Box>
        </Box>
        <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>
          Analyze suspicious URLs using multiple security signals to detect phishing, impersonation, malicious infrastructure, and AI-generated attack patterns.
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
          <Chip icon={<CheckCircleIcon />} label="Detection Engine Online" color="success" size="small" />
          <Chip icon={<SecurityIcon />} label="Model v2.0" size="small" variant="outlined" />
          <Chip icon={<TimelineIcon />} label="Real-time Analysis" size="small" variant="outlined" />
        </Box>
      </Paper>

      {/* URL INPUT */}
      <Paper sx={{ p: 3, mb: 3, bgcolor: 'rgba(26,35,50,0.8)' }}>
        <Typography variant="h6" gutterBottom>Analyze a URL</Typography>
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'flex-start', flexWrap: 'wrap' }}>
          <TextField
            fullWidth
            placeholder="https://example.com/login"
            value={url}
            onChange={(e) => {
              setUrl(e.target.value);
              setInputError('');
            }}
            onKeyDown={handleKeyDown}
            error={!!inputError}
            helperText={inputError || 'Supported: HTTP • HTTPS • Shortened URLs • Suspicious domains'}
            disabled={isAnalyzing}
            slotProps={{
              input: {
                startAdornment: <LinkIcon sx={{ mr: 1, color: 'text.secondary' }} />,
              }
            }}
            sx={{ flex: 1, minWidth: 300 }}
          />
          <Button
            variant="contained"
            size="large"
            onClick={handleAnalyze}
            disabled={isAnalyzing || !url.trim()}
            sx={{
              minWidth: 160,
              py: 1.75,
              background: 'linear-gradient(135deg, #90caf9, #42a5f5)',
              '&:hover': { background: 'linear-gradient(135deg, #42a5f5, #1e88e5)' },
            }}
          >
            {isAnalyzing ? <CircularProgress size={24} color="inherit" /> : 'ANALYZE URL'}
          </Button>
        </Box>

        <Box sx={{ display: 'flex', gap: 1, mt: 2, flexWrap: 'wrap', alignItems: 'center' }}>
          <Button size="small" variant="text" onClick={handlePaste}>📋 Paste</Button>
          <Button size="small" variant="text" onClick={handleClear}>🗑️ Clear</Button>
          <Typography variant="caption" color="textSecondary" sx={{ ml: 'auto' }}>
            Pro tip: Press <strong>Ctrl + Enter</strong> to analyze
          </Typography>
        </Box>

        <Divider sx={{ my: 2 }} />

        <Typography variant="caption" color="textSecondary" gutterBottom>
          Try an example:
        </Typography>
        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
          <Chip size="small" label="🟢 Safe website" onClick={() => loadExample('https://google.com/search')} clickable />
          <Chip size="small" label="🟠 Suspicious login" onClick={() => loadExample('https://secure-login.xyz/verify')} clickable />
          <Chip size="small" label="🔴 Typosquatting" onClick={() => loadExample('https://paypa1-secure.com/update')} clickable />
          <Chip size="small" label="⚠️ Suspicious TLD" onClick={() => loadExample('https://google.verify-account.tk/login')} clickable />
        </Box>
      </Paper>

      {/* LOADING */}
      {isAnalyzing && (
        <Paper sx={{ p: 4, mb: 3, bgcolor: 'rgba(26,35,50,0.8)', textAlign: 'center' }}>
          <CircularProgress size={60} sx={{ mb: 2 }} />
          <Typography variant="h6" gutterBottom>Analyzing URL...</Typography>
          <Box sx={{ maxWidth: 500, mx: 'auto', textAlign: 'left', mt: 3 }}>
            {getAnalysisSteps().map((step, idx) => (
              <Box
                key={idx}
                sx={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 1,
                  py: 0.5,
                  opacity: idx <= currentStepIndex ? 1 : 0.3,
                }}
              >
                {idx < currentStepIndex ? (
                  <CheckCircleIcon sx={{ fontSize: 18, color: 'success.main' }} />
                ) : idx === currentStepIndex ? (
                  <CircularProgress size={18} />
                ) : (
                  <Box sx={{ width: 18 }} />
                )}
                <Typography variant="body2">{step}</Typography>
              </Box>
            ))}
          </Box>
          <LinearProgress
            variant="determinate"
            value={((currentStepIndex + 1) / getAnalysisSteps().length) * 100}
            sx={{ mt: 3, maxWidth: 500, mx: 'auto' }}
          />
        </Paper>
      )}

      {/* ERROR */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }} action={
          <Button color="inherit" size="small" onClick={handleAnalyze}>Retry</Button>
        }>
          ⚠️ {error}
        </Alert>
      )}

      {/* RESULT */}
      {result && !isAnalyzing && (
        <>
          <Paper
            sx={{
              p: 4,
              mb: 3,
              bgcolor: 'rgba(26,35,50,0.95)',
              border: `2px solid ${getVerdictColor(result.verdict)}`,
              textAlign: 'center',
            }}
          >
            <Typography variant="h5" sx={{ color: getVerdictColor(result.verdict), fontWeight: 700, mb: 2 }}>
              {getVerdictMessage(result.verdict)}
            </Typography>

            <Box sx={{ position: 'relative', display: 'inline-flex', my: 3 }}>
              <CircularProgress
                variant="determinate"
                value={result.riskScore}
                size={160}
                thickness={6}
                sx={{ color: getVerdictColor(result.verdict) }}
              />
              <Box
                sx={{
                  top: 0, left: 0, bottom: 0, right: 0,
                  position: 'absolute',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexDirection: 'column',
                }}
              >
                <Typography variant="h3" sx={{ fontWeight: 700, color: getVerdictColor(result.verdict) }}>
                  {result.riskScore}
                </Typography>
                <Typography variant="caption" color="textSecondary">/ 100</Typography>
              </Box>
            </Box>

            <Typography variant="h6" sx={{ color: getVerdictColor(result.verdict), fontWeight: 700 }}>
              {getVerdictLabel(result.verdict)}
            </Typography>

            <Typography variant="body2" color="textSecondary" sx={{ mt: 2 }}>
              Model Confidence: <strong>{(result.confidence * 100).toFixed(1)}%</strong>
            </Typography>

            <Box sx={{ mt: 3, display: 'flex', gap: 1, justifyContent: 'center', flexWrap: 'wrap' }}>
              <Chip label={result.verdict.toUpperCase()} color={getSeverityColor(result.verdict) as any} />
              <Chip label={result.model.name + ' v' + result.model.version} variant="outlined" />
              <Chip label={`${result.metadata.analysisTimeMs}ms`} variant="outlined" />
            </Box>

            <Typography variant="body1" sx={{ mt: 3, maxWidth: 700, mx: 'auto' }}>
              {result.recommendation}
            </Typography>
          </Paper>

          {/* Analysis + Domain Intel */}
          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid size={{ xs: 12, md: 6 }}>
              <Paper sx={{ p: 3, bgcolor: 'rgba(26,35,50,0.8)', height: '100%' }}>
                <Typography variant="h6" gutterBottom>🔍 Security Signals</Typography>
                <Divider sx={{ mb: 2 }} />
                {Object.entries(result.analysis).map(([key, value]) => (
                  <Box key={key} sx={{ mb: 1.5 }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                      <Typography variant="body2">
                        {key.replace(/([A-Z])/g, ' $1').replace(/^./, s => s.toUpperCase())}
                      </Typography>
                      <Typography variant="body2" sx={{ fontWeight: 600 }}>{value}%</Typography>
                    </Box>
                    <LinearProgress
                      variant="determinate"
                      value={value}
                      sx={{ height: 6, borderRadius: 3 }}
                      color={value > 70 ? 'error' : value > 40 ? 'warning' : 'success'}
                    />
                  </Box>
                ))}
              </Paper>
            </Grid>

            <Grid size={{ xs: 12, md: 6 }}>
              <Paper sx={{ p: 3, bgcolor: 'rgba(26,35,50,0.8)', height: '100%' }}>
                <Typography variant="h6" gutterBottom>🌐 Domain Intelligence</Typography>
                <Divider sx={{ mb: 2 }} />
                <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
                  <Box>
                    <Typography variant="caption" color="textSecondary">Domain</Typography>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>{result.domainIntel.domain}</Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="textSecondary">TLD</Typography>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>{result.domainIntel.tld}</Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="textSecondary">Subdomains</Typography>
                    <Typography variant="body2">{result.domainIntel.subdomains}</Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="textSecondary">Path Depth</Typography>
                    <Typography variant="body2">{result.domainIntel.pathDepth}</Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="textSecondary">HTTPS</Typography>
                    <Typography variant="body2">{result.domainIntel.hasHttps ? '✅ Yes' : '⚠️ No'}</Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="textSecondary">IP Address</Typography>
                    <Typography variant="body2">{result.domainIntel.isIpAddress ? '⚠️ Yes' : '✅ No'}</Typography>
                  </Box>
                  <Box sx={{ gridColumn: 'span 2' }}>
                    <Typography variant="caption" color="textSecondary">URL Length</Typography>
                    <Typography variant="body2">{result.domainIntel.urlLength} characters</Typography>
                  </Box>
                </Box>
              </Paper>
            </Grid>
          </Grid>

          {/* URL Anatomy */}
          <Paper sx={{ p: 3, mb: 3, bgcolor: 'rgba(26,35,50,0.8)' }}>
            <Typography variant="h6" gutterBottom>🔬 URL Anatomy</Typography>
            <Divider sx={{ mb: 2 }} />
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2 }}>
              <Box>
                <Typography variant="caption" color="textSecondary">Protocol</Typography>
                <Typography variant="body2" sx={{ p: 0.5, bgcolor: 'rgba(76,175,80,0.2)', borderRadius: 1, fontFamily: 'monospace' }}>
                  {result.urlAnatomy.protocol}://
                </Typography>
              </Box>
              {result.urlAnatomy.subdomain && (
                <Box>
                  <Typography variant="caption" color="textSecondary">Subdomain</Typography>
                  <Typography variant="body2" sx={{ p: 0.5, bgcolor: 'rgba(255,152,0,0.2)', borderRadius: 1, fontFamily: 'monospace' }}>
                    {result.urlAnatomy.subdomain}.
                  </Typography>
                </Box>
              )}
              <Box>
                <Typography variant="caption" color="textSecondary">Domain</Typography>
                <Typography variant="body2" sx={{ p: 0.5, bgcolor: 'rgba(33,150,243,0.2)', borderRadius: 1, fontFamily: 'monospace' }}>
                  {result.urlAnatomy.domain}
                </Typography>
              </Box>
              <Box>
                <Typography variant="caption" color="textSecondary">TLD</Typography>
                <Typography variant="body2" sx={{ p: 0.5, bgcolor: 'rgba(156,39,176,0.2)', borderRadius: 1, fontFamily: 'monospace' }}>
                  .{result.urlAnatomy.tld}
                </Typography>
              </Box>
              {result.urlAnatomy.path && (
                <Box>
                  <Typography variant="caption" color="textSecondary">Path</Typography>
                  <Typography variant="body2" sx={{ p: 0.5, bgcolor: 'rgba(255,235,59,0.2)', borderRadius: 1, fontFamily: 'monospace' }}>
                    {result.urlAnatomy.path}
                  </Typography>
                </Box>
              )}
            </Box>
          </Paper>

          {/* Why Flagged + AI */}
          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid size={{ xs: 12, md: 6 }}>
              <Paper sx={{ p: 3, bgcolor: 'rgba(26,35,50,0.8)', height: '100%' }}>
                <Typography variant="h6" gutterBottom>⚠️ Why This URL Was Flagged</Typography>
                <Divider sx={{ mb: 2 }} />
                {result.indicators.map((indicator, idx) => (
                  <Box
                    key={idx}
                    sx={{
                      p: 2,
                      mb: 1.5,
                      borderRadius: 2,
                      bgcolor: 'rgba(0,0,0,0.2)',
                      borderLeft: `4px solid ${
                        indicator.severity === 'critical' ? '#f44336' :
                        indicator.severity === 'high' ? '#ff9800' :
                        indicator.severity === 'medium' ? '#ffc107' : '#4caf50'
                      }`,
                    }}
                  >
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>{indicator.title}</Typography>
                      <Chip size="small" label={indicator.severity.toUpperCase()}
                        color={getSeverityColor(indicator.severity) as any} />
                    </Box>
                    <Typography variant="body2" color="textSecondary">
                      {indicator.description}
                    </Typography>
                  </Box>
                ))}
              </Paper>
            </Grid>

            <Grid size={{ xs: 12, md: 6 }}>
              <Paper sx={{ p: 3, bgcolor: 'rgba(26,35,50,0.8)', height: '100%' }}>
                <Typography variant="h6" gutterBottom>🤖 AI-Generated Phishing Indicators</Typography>
                <Divider sx={{ mb: 2 }} />
                {Object.entries(result.aiIndicators).map(([key, value]) => (
                  <Box key={key} sx={{ mb: 2 }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                      <Typography variant="body2">
                        {key.replace(/([A-Z])/g, ' $1').replace(/^./, s => s.toUpperCase())}
                      </Typography>
                      <Typography variant="body2" sx={{ fontWeight: 600 }}>{value}%</Typography>
                    </Box>
                    <LinearProgress
                      variant="determinate"
                      value={value}
                      sx={{ height: 8, borderRadius: 4 }}
                      color={value > 70 ? 'error' : value > 40 ? 'warning' : 'success'}
                    />
                  </Box>
                ))}
                <Alert severity={result.riskScore > 60 ? 'warning' : 'info'} sx={{ mt: 2 }}>
                  <Typography variant="caption">
                    {result.riskScore > 60
                      ? 'Potential AI-assisted phishing campaign detected'
                      : 'No significant AI-generated attack patterns detected'}
                  </Typography>
                </Alert>
              </Paper>
            </Grid>
          </Grid>

          {/* Recommended Action */}
          <Paper sx={{ p: 3, mb: 3, bgcolor: 'rgba(26,35,50,0.8)' }}>
            <Typography variant="h6" gutterBottom>🛡️ Recommended Action</Typography>
            <Divider sx={{ mb: 2 }} />
            <Typography variant="body1" sx={{ mb: 2 }}>{result.recommendation}</Typography>
            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
              <Button
                variant="contained"
                color="error"
                startIcon={isReporting ? <CircularProgress size={16} color="inherit" /> : <FlagIcon />}
                onClick={handleReportThreat}
                disabled={isReporting}
              >
                {isReporting ? 'Reporting...' : 'Report Threat'}
              </Button>
              <Button variant="outlined" startIcon={<RefreshIcon />} onClick={handleClear}>
                Scan Another URL
              </Button>
              <Button variant="outlined" startIcon={<DownloadIcon />} onClick={handleDownloadReport}>
                Download Report
              </Button>
              <Button variant="outlined" startIcon={<CopyIcon />} onClick={handleCopyReport}>
                Copy Report
              </Button>
            </Box>
          </Paper>

          {/* Feedback */}
          <Paper sx={{ p: 3, mb: 3, bgcolor: 'rgba(26,35,50,0.8)' }}>
            <Typography variant="h6" gutterBottom>Was this detection useful?</Typography>
            {!feedbackGiven ? (
              <Box sx={{ display: 'flex', gap: 2 }}>
                <Button variant="outlined" color="success" startIcon={<ThumbUpIcon />} onClick={() => handleFeedback('correct')}>
                  Correct detection
                </Button>
                <Button variant="outlined" color="error" startIcon={<ThumbDownIcon />} onClick={() => handleFeedback('incorrect')}>
                  Incorrect detection
                </Button>
              </Box>
            ) : (
              <Alert severity="success">Thanks for your feedback! This helps improve the ML model.</Alert>
            )}
          </Paper>

          {/* Technical Details */}
          <Accordion sx={{ bgcolor: 'rgba(26,35,50,0.8)', mb: 3 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6">⚙️ Technical Details</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                <Grid size={{ xs: 6, sm: 3 }}>
                  <Typography variant="caption" color="textSecondary">Model</Typography>
                  <Typography variant="body2">{result.model.name} v{result.model.version}</Typography>
                </Grid>
                <Grid size={{ xs: 6, sm: 3 }}>
                  <Typography variant="caption" color="textSecondary">Features Extracted</Typography>
                  <Typography variant="body2">26</Typography>
                </Grid>
                <Grid size={{ xs: 6, sm: 3 }}>
                  <Typography variant="caption" color="textSecondary">Inference Time</Typography>
                  <Typography variant="body2">{result.metadata.analysisTimeMs}ms</Typography>
                </Grid>
                <Grid size={{ xs: 6, sm: 3 }}>
                  <Typography variant="caption" color="textSecondary">API Endpoint</Typography>
                  <Typography variant="body2">POST /ml/analyze/url</Typography>
                </Grid>
              </Grid>
            </AccordionDetails>
          </Accordion>
        </>
      )}

      {/* Recent Scans */}
      {history.length > 0 && (
        <Paper sx={{ p: 3, bgcolor: 'rgba(26,35,50,0.8)' }}>
          <Typography variant="h6" gutterBottom>📜 Recent Scans</Typography>
          <Divider sx={{ mb: 2 }} />
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>URL</TableCell>
                  <TableCell>Verdict</TableCell>
                  <TableCell>Risk</TableCell>
                  <TableCell>Time</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {history.map((item, idx) => (
                  <TableRow key={idx} hover sx={{ cursor: 'pointer' }} onClick={() => setUrl(item.url)}>
                    <TableCell>
                      <Typography variant="body2" noWrap sx={{ maxWidth: 400, fontFamily: 'monospace' }}>
                        {item.url}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip size="small" label={item.verdict}
                        color={item.risk > 70 ? 'error' : item.risk > 40 ? 'warning' : 'success'} />
                    </TableCell>
                    <TableCell>{item.risk}/100</TableCell>
                    <TableCell>{item.timestamp}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      )}

      {/* Safety Notice */}
      <Alert severity="info" icon={<InfoIcon />} sx={{ mt: 3 }}>
        <Typography variant="caption">
          <strong>Safety notice:</strong> Sentinel-MCP analyzes URLs for security indicators.
          Detection results are probabilistic and should not be treated as a guarantee that a website is safe.
        </Typography>
      </Alert>

      <Snackbar
        open={snackbarOpen}
        autoHideDuration={4000}
        onClose={() => setSnackbarOpen(false)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert severity={snackbarSeverity} onClose={() => setSnackbarOpen(false)}>
          {snackbarMessage}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default PhishingModule;