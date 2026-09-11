// App.tsx
import React, { useState, useEffect } from 'react';
import { HashRouter, Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom';
import { ThemeProvider, createTheme, CssBaseline, AppBar, Toolbar, Typography, Tabs, Tab, Box } from '@mui/material';
import {
  Dashboard as DashboardIcon,
  Warning as WarningIcon,
  Person as PersonIcon,
  Security as SecurityIcon,
  Storage as StorageIcon,
} from '@mui/icons-material';
import Dashboard from './components/Dashboard';
import AlertsPage from './pages/Alerts';
import AgentDetailsPage from './pages/AgentDetails';
import Login from './pages/Login';
import Register from './pages/Register';
import Landing from './pages/Landing';
import ModuleDashboard from './pages/ModuleDashboard';
import MCPDashboard from './pages/MCPDashboard';
import MCPAgentDetail from './pages/MCPAgentDetail';
import MCPPolicyDetail from './pages/MCPPolicyDetail';
import MCPServerDetail from './pages/MCPServerDetail';

// Module Pages
import PhishingModule from './pages/modules/PhishingModule';
import PasswordModule from './pages/modules/PasswordModule';
import QRModule from './pages/modules/QRModule';
import MalwareModule from './pages/modules/MalwareModule';
import NetworkModule from './pages/modules/NetworkModule';
import InsiderModule from './pages/modules/InsiderModule';
import AndroidModule from './pages/modules/AndroidModule';

const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: { main: '#90caf9' },
    secondary: { main: '#f48fb1' },
    background: { default: '#0a1929', paper: '#1a2332' },
  },
});

// Protected Route Component
const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const token = localStorage.getItem('access_token');
  if (!token) {
    return <Navigate to="/login" />;
  }
  return <>{children}</>;
};

// Navigation wrapper
const AppLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const [tabValue, setTabValue] = useState(0);
  const [systemStatus, setSystemStatus] = useState<'active' | 'degraded' | 'critical'>('active');

  // Sync tab value with current route
  useEffect(() => {
    const path = location.pathname;
    if (path.includes('/mcp')) setTabValue(4);
    else if (path.includes('/alerts')) setTabValue(1);
    else if (path.includes('/agents')) setTabValue(2);
    else if (path.includes('/modules')) setTabValue(3);
    else setTabValue(0);
  }, [location.pathname]);

  // Poll system health
  useEffect(() => {
    const checkHealth = async () => {
      try {
        const response = await fetch('http://localhost:8001/health');
        if (response.ok) {
          setSystemStatus('active');
        } else {
          setSystemStatus('degraded');
        }
      } catch {
        setSystemStatus('critical');
      }
    };

    checkHealth();
    const interval = setInterval(checkHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
    switch (newValue) {
      case 0:
        navigate('/dashboard', { replace: true });
        break;
      case 1:
        navigate('/alerts', { replace: true });
        break;
      case 2:
        navigate('/agents', { replace: true });
        break;
      case 3:
        navigate('/modules', { replace: true });
        break;
      case 4:
        navigate('/mcp', { replace: true });
        break;
      default:
        navigate('/dashboard', { replace: true });
    }
  };

  const getStatusConfig = () => {
    switch (systemStatus) {
      case 'active':
        return {
          color: '#4caf50',
          bg: 'rgba(76, 175, 80, 0.1)',
          border: 'rgba(76, 175, 80, 0.3)',
          label: 'PROTECTION ACTIVE',
        };
      case 'degraded':
        return {
          color: '#ff9800',
          bg: 'rgba(255, 152, 0, 0.1)',
          border: 'rgba(255, 152, 0, 0.3)',
          label: 'DEGRADED',
        };
      case 'critical':
        return {
          color: '#f44336',
          bg: 'rgba(244, 67, 54, 0.1)',
          border: 'rgba(244, 67, 54, 0.3)',
          label: 'OFFLINE',
        };
    }
  };

  const statusConfig = getStatusConfig();

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      <AppBar
        position="static"
        elevation={0}
        sx={{
          bgcolor: 'background.paper',
          borderBottom: '1px solid rgba(255,255,255,0.05)',
        }}
      >
        <Toolbar>
          <Typography
            variant="h6"
            sx={{
              flexGrow: 0,
              mr: 4,
              cursor: 'pointer',
              fontWeight: 700,
              display: 'flex',
              alignItems: 'center',
              gap: 1,
              '&:hover': { color: 'primary.main' },
            }}
            onClick={() => navigate('/dashboard', { replace: true })}
          >
            🛡️ Sentinel-MCP
          </Typography>

          <Tabs value={tabValue} onChange={handleTabChange} textColor="primary" indicatorColor="primary">
            <Tab icon={<DashboardIcon />} label="Dashboard" />
            <Tab icon={<WarningIcon />} label="Alerts" />
            <Tab icon={<PersonIcon />} label="Agents" />
            <Tab icon={<SecurityIcon />} label="Modules" />
            <Tab icon={<StorageIcon />} label="MCP" />
          </Tabs>

          {/* System Status Indicator */}
          <Box sx={{ ml: 'auto', display: 'flex', alignItems: 'center', gap: 2 }}>
            <Box
              sx={{
                display: 'flex',
                alignItems: 'center',
                gap: 1,
                px: 2,
                py: 0.5,
                borderRadius: 4,
                bgcolor: statusConfig.bg,
                border: `1px solid ${statusConfig.border}`,
              }}
            >
              <Box
                sx={{
                  width: 8,
                  height: 8,
                  borderRadius: '50%',
                  bgcolor: statusConfig.color,
                  boxShadow: `0 0 8px ${statusConfig.color}`,
                  animation: 'pulse-dot 2s ease-in-out infinite',
                  '@keyframes pulse-dot': {
                    '0%, 100%': { opacity: 1 },
                    '50%': { opacity: 0.4 },
                  },
                }}
              />
              <Typography
                variant="caption"
                sx={{
                  fontWeight: 600,
                  color: statusConfig.color,
                  letterSpacing: 0.5,
                }}
              >
                {statusConfig.label}
              </Typography>
            </Box>
            <Typography variant="caption" color="textSecondary" sx={{ fontWeight: 600 }}>
              v2.0
            </Typography>
          </Box>
        </Toolbar>
      </AppBar>

      <Box sx={{ flexGrow: 1, bgcolor: 'background.default' }}>
        {children}
      </Box>
    </Box>
  );
};

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem('access_token');
    setIsAuthenticated(!!token);
  }, []);

  // If not authenticated
  if (!isAuthenticated) {
    return (
      <ThemeProvider theme={darkTheme}>
        <CssBaseline />
        <HashRouter>
          <Routes>
            <Route path="/" element={<Landing />} />
            <Route path="/login" element={<Login onLogin={() => setIsAuthenticated(true)} />} />
            <Route path="/register" element={<Register />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </HashRouter>
      </ThemeProvider>
    );
  }

  // Authenticated routes
  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      <HashRouter>
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <AppLayout>
                  <Dashboard />
                </AppLayout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/alerts"
            element={
              <ProtectedRoute>
                <AppLayout>
                  <AlertsPage />
                </AppLayout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/agents"
            element={
              <ProtectedRoute>
                <AppLayout>
                  <AgentDetailsPage />
                </AppLayout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/modules"
            element={
              <ProtectedRoute>
                <AppLayout>
                  <ModuleDashboard />
                </AppLayout>
              </ProtectedRoute>
            }
          />

          {/* ============ MCP ROUTES ============ */}
          <Route
            path="/mcp"
            element={
              <ProtectedRoute>
                <AppLayout>
                  <MCPDashboard />
                </AppLayout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/mcp/agents/:id"
            element={
              <ProtectedRoute>
                <AppLayout>
                  <MCPAgentDetail />
                </AppLayout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/mcp/policies/:id"
            element={
              <ProtectedRoute>
                <AppLayout>
                  <MCPPolicyDetail />
                </AppLayout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/mcp/servers/:id"
            element={
              <ProtectedRoute>
                <AppLayout>
                  <MCPServerDetail />
                </AppLayout>
              </ProtectedRoute>
            }
          />

          {/* ============ MODULE ROUTES ============ */}
          <Route
            path="/modules/phishing"
            element={
              <ProtectedRoute>
                <AppLayout>
                  <PhishingModule />
                </AppLayout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/modules/password"
            element={
              <ProtectedRoute>
                <AppLayout>
                  <PasswordModule />
                </AppLayout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/modules/qr"
            element={
              <ProtectedRoute>
                <AppLayout>
                  <QRModule />
                </AppLayout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/modules/malware"
            element={
              <ProtectedRoute>
                <AppLayout>
                  <MalwareModule />
                </AppLayout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/modules/network"
            element={
              <ProtectedRoute>
                <AppLayout>
                  <NetworkModule />
                </AppLayout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/modules/insider"
            element={
              <ProtectedRoute>
                <AppLayout>
                  <InsiderModule />
                </AppLayout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/modules/android"
            element={
              <ProtectedRoute>
                <AppLayout>
                  <AndroidModule />
                </AppLayout>
              </ProtectedRoute>
            }
          />

          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </HashRouter>
    </ThemeProvider>
  );
}

export default App;