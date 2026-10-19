// pages/ModuleDashboard.tsx
import React, { useEffect, useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
  Chip,
  LinearProgress,
} from '@mui/material';
import { useNavigate } from 'react-router-dom';
import { gatewayFetch } from '../services/api';

interface ModuleStats {
  name: string;
  icon: string;
  path: string;
  description: string;
  status: string;
  statsKey: string;
  activityLabel: 'events' | 'analyses';
  events: number;
}

const modules: ModuleStats[] = [
  { name: 'Phishing Detection', icon: '🔗', path: '/modules/phishing', description: 'URL phishing detection', status: 'active', statsKey: 'PhishingDetector', activityLabel: 'events', events: 0 },
  { name: 'Malware Detection', icon: '🦠', path: '/modules/malware', description: 'File/APK malware analysis', status: 'active', statsKey: 'MalwareDetector', activityLabel: 'events', events: 0 },
  { name: 'Network IDS', icon: '🌐', path: '/modules/network', description: 'Network intrusion detection', status: 'active', statsKey: 'NetworkIDS', activityLabel: 'events', events: 0 },
  { name: 'Payload Analyzer', icon: '⌘', path: '/modules/payload', description: 'Score MCP and command payloads', status: 'active', statsKey: 'Payload Analyzer', activityLabel: 'analyses', events: 0 },
  { name: 'Insider Threat', icon: '👤', path: '/modules/insider', description: 'User behavior analysis', status: 'active', statsKey: 'InsiderThreatDetector', activityLabel: 'events', events: 0 },
  { name: 'Android Security', icon: '📱', path: '/modules/android', description: 'App permission auditing', status: 'active', statsKey: 'AndroidSecurityAnalyzer', activityLabel: 'events', events: 0 },
  { name: 'Password Analyzer', icon: '🔑', path: '/modules/password', description: 'Password strength check', status: 'active', statsKey: 'PasswordAnalyzer', activityLabel: 'events', events: 0 },
  { name: 'QR Scanner', icon: '📷', path: '/modules/qr', description: 'QR code safety check', status: 'active', statsKey: 'QRSafetyChecker', activityLabel: 'events', events: 0 },
];

const ModuleDashboard: React.FC = () => {
  const navigate = useNavigate();
  const [moduleStats, setModuleStats] = useState<ModuleStats[]>(modules);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let isCurrent = true;
    const fetchStats = async () => {
      try {
        const response = await gatewayFetch('/cybereye/stats');
        if (response.ok) {
          const data = await response.json();
          if (isCurrent) {
            setModuleStats(prev => prev.map(module => {
              const moduleData = data.modules?.[module.statsKey];
              const count = module.activityLabel === 'analyses'
                ? moduleData?.total_analyses
                : moduleData?.total_events;
              return { ...module, events: typeof count === 'number' ? count : 0 };
            }));
          }
        }
      } catch (error) {
        console.error('Failed to fetch module stats:', error);
      } finally {
        if (isCurrent) setLoading(false);
      }
    };

    fetchStats();
    const refreshTimer = window.setInterval(fetchStats, 10_000);
    return () => {
      isCurrent = false;
      window.clearInterval(refreshTimer);
    };
  }, []);

  const handleModuleClick = (path: string) => {
    navigate(path);
  };

  if (loading) {
    return (
      <Box sx={{ p: 3 }}>
        <LinearProgress />
        <Typography align="center" sx={{ mt: 2 }}>
          Loading modules...
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3, maxWidth: 1200, mx: 'auto' }}>
      <Paper sx={{ p: 3, mb: 3, bgcolor: 'rgba(23, 18, 20,0.8)' }}>
        <Typography variant="h4" sx={{ fontWeight: 600 }}>
          🛡️ CyberEye Module Dashboard
        </Typography>
        <Typography variant="body2" color="textSecondary">
          Select a security module to analyze your data
        </Typography>
      </Paper>

      <Grid container spacing={3}>
        {moduleStats.map((module) => (
          <Grid size={{ xs: 12, sm: 6, md: 4 }} key={module.name}>
            <Card
              sx={{
                height: '100%',
                bgcolor: 'rgba(23, 18, 20,0.8)',
                border: '1px solid rgba(255,255,255,0.05)',
                transition: 'transform 0.2s, box-shadow 0.2s',
                cursor: 'pointer',
                '&:hover': {
                  transform: 'translateY(-4px)',
                  boxShadow: '0 8px 40px rgba(0,0,0,0.4)',
                  borderColor: 'primary.main',
                },
              }}
              onClick={() => handleModuleClick(module.path)}
            >
              <CardContent>
                <Box sx={{ fontSize: 48, mb: 2 }}>{module.icon}</Box>
                <Typography variant="h6" sx={{ fontWeight: 600 }}>
                  {module.name}
                </Typography>
                <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>
                  {module.description}
                </Typography>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <Chip
                    label={module.status}
                    size="small"
                    color={module.status === 'active' ? 'success' : 'default'}
                  />
                  <Typography variant="caption" color="textSecondary">
                    {module.events.toLocaleString()} {module.activityLabel}
                  </Typography>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>
    </Box>
  );
};

export default ModuleDashboard;
