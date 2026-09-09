import React, { useEffect, useState } from 'react';
import {
  Box,
  Typography,
  Paper,
  CircularProgress,
  Alert,
} from '@mui/material';
import { gatewayApi } from '../services/api';

const Dashboard: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState<any>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const statsData = await gatewayApi.getStats();
        setStats(statsData);
        setError(null);
      } catch (err: any) {
        console.error('Error:', err);
        setError('Failed to connect to gateway. Make sure it\'s running on port 8001');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '80vh' }}>
        <CircularProgress />
        <Typography sx={{ ml: 2 }}>Loading dashboard...</Typography>
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">
          {error}
        </Alert>
        <Typography sx={{ mt: 2 }}>
          Make sure the backend is running: <code>venv\Scripts\python.exe src\gateway.py</code>
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Paper sx={{ p: 3, bgcolor: 'rgba(26,35,50,0.8)' }}>
        <Typography variant="h4" sx={{ fontWeight: 600 }}>
          🛡️ Sentinel-MCP Dashboard
        </Typography>
        <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
          Total Requests: {stats?.total_requests || 0}
        </Typography>
        <Typography variant="body2" color="textSecondary">
          Blocked Requests: {stats?.blocked || 0}
        </Typography>
        <Typography variant="body2" color="textSecondary">
          Block Rate: {stats?.block_rate || 0}%
        </Typography>
        <Typography variant="body2" color="textSecondary">
          ML Models: {stats?.ml_models || 0}
        </Typography>
      </Paper>
    </Box>
  );
};

export default Dashboard;