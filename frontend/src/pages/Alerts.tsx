// pages/Alerts.tsx
import React, { useEffect, useState } from 'react';
import {
  Box,
  Typography,
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
  LinearProgress,
  Card,
  CardContent,
  Grid,
  Button,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  CheckCircle as CheckCircleIcon,
  Download as DownloadIcon,
  Timeline as TimelineIcon,
} from '@mui/icons-material';
import { gatewayApi } from '../services/api';
import { Alert } from '../types';

const AlertsPage: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [totalAlerts, setTotalAlerts] = useState(0);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchAlerts = async () => {
    try {
      const data = await gatewayApi.getAnomalies(100);
      setAlerts(data.alerts);
      setTotalAlerts(data.total);
    } catch (error) {
      console.error('Error fetching alerts:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
    let interval: NodeJS.Timeout;
    if (autoRefresh) {
      interval = setInterval(fetchAlerts, 5000);
    }
    return () => clearInterval(interval);
  }, [autoRefresh]);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
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
      case 'HIGH':
        return <ErrorIcon />;
      case 'MEDIUM':
        return <WarningIcon />;
      case 'LOW':
        return <InfoIcon />;
      default:
        return <InfoIcon />;
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'rule_based':
        return <WarningIcon color="warning" />;
      case 'ml_based':
        return <TimelineIcon color="primary" />;
      default:
        return <InfoIcon />;
    }
  };

  const highSeverity = alerts.filter(a => a.severity === 'HIGH').length;
  const mediumSeverity = alerts.filter(a => a.severity === 'MEDIUM').length;
  const lowSeverity = alerts.filter(a => a.severity === 'LOW').length;
  const ruleBased = alerts.filter(a => a.type === 'rule_based').length;
  const mlBased = alerts.filter(a => a.type === 'ml_based').length;

  if (loading) {
    return (
      <Box sx={{ width: '100%', mt: 4 }}>
        <LinearProgress />
        <Typography align="center" sx={{ mt: 2 }}>
          Loading alerts...
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ flexGrow: 1, p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1">
          🚨 Security Alerts
        </Typography>
        <Box>
          <Tooltip title="Export Alerts">
            <IconButton>
              <DownloadIcon />
            </IconButton>
          </Tooltip>
          <Tooltip title="Refresh">
            <IconButton onClick={fetchAlerts}>
              <RefreshIcon />
            </IconButton>
          </Tooltip>
          <Tooltip title={autoRefresh ? 'Auto-refresh on' : 'Auto-refresh off'}>
            <IconButton onClick={() => setAutoRefresh(!autoRefresh)} color={autoRefresh ? 'primary' : 'default'}>
              <TimelineIcon />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>

      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Total Alerts
              </Typography>
              <Typography variant="h4">{totalAlerts}</Typography>
              <Chip
                size="small"
                icon={<WarningIcon />}
                label={`${alerts.length} active`}
                color="warning"
              />
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                High Severity
              </Typography>
              <Typography variant="h4" color="error">
                {highSeverity}
              </Typography>
              <Chip
                size="small"
                icon={<ErrorIcon />}
                label={`${((highSeverity / alerts.length) * 100 || 0).toFixed(0)}%`}
                color="error"
              />
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Rule-Based
              </Typography>
              <Typography variant="h4">{ruleBased}</Typography>
              <Chip
                size="small"
                icon={<WarningIcon />}
                label="Policy violations"
                color="warning"
              />
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                ML-Based
              </Typography>
              <Typography variant="h4">{mlBased}</Typography>
              <Chip
                size="small"
                icon={<TimelineIcon />}
                label="Behavioral anomalies"
                color="primary"
              />
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Paper sx={{ p: 2 }}>
        <Typography variant="h6" gutterBottom>
          Alert Details
        </Typography>
        <TableContainer>
          <Table size="medium">
            <TableHead>
              <TableRow>
                <TableCell>Time</TableCell>
                <TableCell>Type</TableCell>
                <TableCell>Severity</TableCell>
                <TableCell>Agent</TableCell>
                <TableCell>Method</TableCell>
                <TableCell>Reason</TableCell>
                <TableCell>Action</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {alerts.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} align="center">
                    <Typography variant="body1" sx={{ py: 4 }}>
                      <CheckCircleIcon sx={{ fontSize: 48, color: 'success.main' }} />
                      <br />
                      No alerts detected. All systems secure!
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                alerts.slice().reverse().map((alert, index) => (
                  <TableRow key={index} hover>
                    <TableCell>
                      {new Date(alert.timestamp).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      <Chip
                        size="small"
                        icon={getTypeIcon(alert.type)}
                        label={alert.type === 'rule_based' ? 'Rule' : 'ML'}
                        color={alert.type === 'rule_based' ? 'warning' : 'primary'}
                      />
                    </TableCell>
                    <TableCell>
                      <Chip
                        size="small"
                        icon={getSeverityIcon(alert.severity)}
                        label={alert.severity}
                        color={getSeverityColor(alert.severity)}
                      />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                        {alert.agent_id}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {alert.request?.method || 'Unknown'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Tooltip title={alert.reason}>
                        <Typography variant="body2" noWrap sx={{ maxWidth: 300 }}>
                          {alert.reason}
                        </Typography>
                      </Tooltip>
                    </TableCell>
                    <TableCell>
                      <Button
                        size="small"
                        variant="outlined"
                        color="primary"
                        onClick={() => {
                          console.log('Investigating alert:', alert);
                        }}
                      >
                        Investigate
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>
    </Box>
  );
};

export default AlertsPage;