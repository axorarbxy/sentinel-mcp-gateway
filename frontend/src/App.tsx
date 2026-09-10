import React, { useState, useEffect } from 'react';
import { HashRouter, Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom';
import { ThemeProvider, createTheme, CssBaseline, AppBar, Toolbar, Typography, Tabs, Tab, Box } from '@mui/material';
import {
  Dashboard as DashboardIcon,
  Warning as WarningIcon,
  Person as PersonIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';
import Dashboard from './components/Dashboard';
import AlertsPage from './pages/Alerts';
import AgentDetailsPage from './pages/AgentDetails';
import Login from './pages/Login';
import Register from './pages/Register';
import Landing from './pages/Landing';
import ModuleDashboard from './pages/ModuleDashboard';

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

  // Sync tab value with current route
  useEffect(() => {
    const path = location.pathname;
    if (path.includes('/alerts')) setTabValue(1);
    else if (path.includes('/agents')) setTabValue(2);
    else if (path.includes('/modules')) setTabValue(3);
    else setTabValue(0);
  }, [location.pathname]);

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
      default:
        navigate('/dashboard', { replace: true });
    }
  };

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      <AppBar position="static" elevation={0} sx={{ bgcolor: 'background.paper' }}>
        <Toolbar>
          <Typography
            variant="h6"
            sx={{
              flexGrow: 0,
              mr: 4,
              cursor: 'pointer',
              '&:hover': { color: 'primary.main' }
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
          </Tabs>
          <Typography variant="body2" color="textSecondary" sx={{ ml: 'auto' }}>
            v2.0
          </Typography>
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