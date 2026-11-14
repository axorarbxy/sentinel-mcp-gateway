// App.tsx
import React, { useState, useEffect } from 'react';
import './index.css';
import { HashRouter, Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom';
import { ThemeProvider, createTheme, CssBaseline, AppBar, Toolbar, Typography, Box, Button, Drawer, List, ListItemButton, ListItemIcon, ListItemText, Divider, IconButton, useMediaQuery } from '@mui/material';
import {
  Dashboard as DashboardIcon,
  Warning as WarningIcon,
  Person as PersonIcon,
  Security as SecurityIcon,
  Rule as PolicyIcon,
  Logout as LogoutIcon,
  Menu as MenuIcon,
  Hub as HubIcon,
  Insights as InsightsIcon,
} from '@mui/icons-material';
import { logout } from './services/api';
import { API_BASE_URL } from './services/urls';
import Dashboard from './components/Dashboard';
import AlertsPage from './pages/Alerts';
import AgentDetailsPage from './pages/AgentDetails';
import Login from './pages/Login';
import Register from './pages/Register';
import LegalPage from './pages/LegalPage';
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
import PayloadModule from './pages/modules/PayloadModule';
import InsiderModule from './pages/modules/InsiderModule';
import AndroidModule from './pages/modules/AndroidModule';
import SQLiPolicies from './pages/SQLiPolicies';

const darkTheme = createTheme({
  typography: { fontFamily: "'Open Sauce One', 'Segoe UI', sans-serif" },
  palette: {
    mode: 'dark',
    primary: { main: '#28A9E0', light: '#91DFFF', dark: '#087EAE', contrastText: '#F4FBFF' },
    secondary: { main: '#FF3B78', contrastText: '#FFFFFF' },
    background: { default: '#030407', paper: '#0B1018' },
    text: { primary: '#EDF3FB', secondary: '#929EAE' },
  },
  components: {
    MuiLink: {
      styleOverrides: {
        root: { color: '#28A9E0' },
      },
    },
    MuiTab: {
      styleOverrides: {
        root: {
          '&.Mui-selected': { color: '#28A9E0' },
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: { borderRadius: 7, textTransform: 'none', fontWeight: 600 },
        outlined: { color: '#28A9E0', borderColor: 'rgba(40, 169, 224, 0.48)' },
      },
    },
    MuiSvgIcon: {
      styleOverrides: {
        colorPrimary: { color: '#28A9E0' },
      },
    },
    MuiPaper: { styleOverrides: { root: { backgroundImage: 'none', border: '1px solid rgba(65, 147, 192, 0.22)', borderRadius: 10 } } },
    MuiCard: { styleOverrides: { root: { backgroundImage: 'none', border: '1px solid rgba(65, 147, 192, 0.22)', borderRadius: 10 } } },
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
  const [systemStatus, setSystemStatus] = useState<'active' | 'degraded' | 'critical'>('active');
  const [mobileOpen, setMobileOpen] = useState(false);
  const desktop = useMediaQuery('(min-width: 900px)');

  // Poll system health
  useEffect(() => {
    const checkHealth = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/health`);
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

  const navGroups = [
    { label: 'OVERVIEW', items: [
      { label: 'Command center', path: '/dashboard', icon: <DashboardIcon /> },
      { label: 'Threat alerts', path: '/alerts', icon: <WarningIcon /> },
      { label: 'AI agents', path: '/agents', icon: <PersonIcon /> },
    ] },
    { label: 'PROTECTION', items: [
      { label: 'Security modules', path: '/modules', icon: <SecurityIcon /> },
      { label: 'MCP gateway', path: '/mcp', icon: <HubIcon /> },
      { label: 'Policies', path: '/policies/sqli', icon: <PolicyIcon /> },
    ] },
  ];

  const getStatusConfig = () => {
    switch (systemStatus) {
      case 'active':
        return {
          color: '#28A9E0',
          bg: 'rgba(40, 169, 224, 0.1)',
          border: 'rgba(40, 169, 224, 0.38)',
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
          color: '#FF3B78',
          bg: 'rgba(255, 59, 120, 0.1)',
          border: 'rgba(255, 59, 120, 0.38)',
          label: 'OFFLINE',
        };
    }
  };

  const statusConfig = getStatusConfig();

  const handleLogout = () => {
    logout();
    navigate('/login', { replace: true });
  };

  const pageTitle = navGroups.flatMap((group) => group.items).find((item) =>
    item.path === location.pathname || (item.path !== '/dashboard' && location.pathname.startsWith(item.path)),
  )?.label || 'Security workspace';

  const drawer = (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column', px: 1.5, py: 2 }}>
      <Box onClick={() => navigate('/dashboard')} sx={{ display: 'flex', alignItems: 'center', gap: 1.2, px: 1, mb: 3, cursor: 'pointer' }}>
        <Box sx={{ width: 34, height: 34, display: 'grid', placeItems: 'center', borderRadius: 1.5, color: '#07130F', bgcolor: '#28A9E0' }}><SecurityIcon fontSize="small" /></Box>
        <Box><Typography sx={{ fontWeight: 800, letterSpacing: .7, lineHeight: 1.1 }}>CYBEREYE</Typography><Typography sx={{ color: '#718494', fontSize: 10, letterSpacing: 1.5, mt: .4 }}>SENTINEL PLATFORM</Typography></Box>
      </Box>
      {navGroups.map((group) => <Box key={group.label} sx={{ mb: 2 }}>
        <Typography sx={{ color: '#607383', fontSize: 10, fontWeight: 700, letterSpacing: 1.4, px: 1.2, mb: .7 }}>{group.label}</Typography>
        <List disablePadding>
          {group.items.map((item) => {
            const selected = item.path === location.pathname || (item.path !== '/dashboard' && location.pathname.startsWith(item.path));
            return <ListItemButton key={item.path} selected={selected} onClick={() => { navigate(item.path); setMobileOpen(false); }} sx={{ mb: .25, px: 1.2, py: .9, borderRadius: 1.5, color: selected ? '#F0F7FB' : '#929EAE', '& .MuiListItemIcon-root': { minWidth: 34, color: selected ? '#28A9E0' : '#718494' }, '&.Mui-selected': { backgroundColor: 'rgba(40,169,224,.12)', borderLeft: '2px solid #28A9E0' }, '&.Mui-selected:hover': { backgroundColor: 'rgba(40,169,224,.17)' }, '&:hover': { color: '#F3F7FA', backgroundColor: 'rgba(255,255,255,.035)' } }}>
              <ListItemIcon>{item.icon}</ListItemIcon><ListItemText primary={item.label} slotProps={{ primary: { sx: { fontSize: 13, fontWeight: selected ? 650 : 500 } } }} />
            </ListItemButton>;
          })}
        </List>
      </Box>)}
      <Box sx={{ mt: 'auto', p: 1.2, borderTop: '1px solid rgba(65,147,192,.22)' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: .6 }}><InsightsIcon sx={{ fontSize: 16, color: '#28A9E0' }} /><Typography sx={{ fontSize: 11, fontWeight: 700 }}>Gateway telemetry</Typography></Box>
        <Typography sx={{ color: '#929EAE', fontSize: 11, lineHeight: 1.5 }}>Live inspection for agent traffic and security signals.</Typography>
        <Divider sx={{ my: 1, borderColor: 'rgba(65,147,192,.22)' }} />
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}><Typography sx={{ color: '#7E91A3', fontSize: 10, fontFamily: 'monospace' }}>API · :8001</Typography><Box sx={{ width: 7, height: 7, borderRadius: '50%', bgcolor: statusConfig.color }} /></Box>
      </Box>
    </Box>
  );

  return (
    <Box sx={{ minHeight: '100vh', display: 'flex', color: 'text.primary', bgcolor: '#030407' }}>
      <Drawer variant={desktop ? 'permanent' : 'temporary'} open={desktop || mobileOpen} onClose={() => setMobileOpen(false)} ModalProps={{ keepMounted: true }} sx={{ width: { md: 240 }, flexShrink: 0, '& .MuiDrawer-paper': { width: 240, boxSizing: 'border-box', bgcolor: '#05080d', border: 0, borderRight: '1px solid rgba(65,147,192,.22)' } }}>{drawer}</Drawer>
      <Box sx={{ minWidth: 0, flex: 1 }}>
        <AppBar position="sticky" elevation={0} sx={{ bgcolor: '#05080d', borderBottom: '1px solid rgba(65,147,192,.22)' }}>
          <Toolbar sx={{ minHeight: '64px !important', px: { xs: 2, md: 3 } }}>
            {!desktop && <IconButton onClick={() => setMobileOpen(true)} sx={{ mr: 1.5, color: 'text.primary' }} aria-label="Open navigation"><MenuIcon /></IconButton>}
            <Box><Typography sx={{ color: '#8196A8', fontSize: 10, letterSpacing: 1.7, fontWeight: 800 }}>SECURITY OPERATIONS / {pageTitle.toUpperCase()}</Typography><Typography sx={{ fontSize: 15, fontWeight: 750, mt: .3 }}>{pageTitle}</Typography></Box>
            <Box sx={{ ml: 'auto', display: 'flex', alignItems: 'center', gap: { xs: 1, sm: 2 } }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: .9, px: 1.2, py: .7, bgcolor: statusConfig.bg, border: `1px solid ${statusConfig.border}`, borderRadius: 1.5 }}><Box sx={{ width: 7, height: 7, borderRadius: '50%', bgcolor: statusConfig.color }} /><Typography sx={{ fontSize: 10, fontWeight: 750, letterSpacing: .5, color: statusConfig.color, display: { xs: 'none', sm: 'block' } }}>{statusConfig.label}</Typography></Box>
              <Button variant="outlined" size="small" startIcon={<LogoutIcon />} onClick={handleLogout} sx={{ color: '#AAB8C2', borderColor: 'rgba(65,147,192,.3)', '&:hover': { borderColor: 'primary.main', color: 'primary.light' } }}>Sign out</Button>
            </Box>
          </Toolbar>
        </AppBar>
        <Box className="workspace-content" sx={{ width: '100%', maxWidth: 1680, mx: 'auto', p: { xs: 2, sm: 2.5, lg: 3.5 } }}>{children}</Box>
      </Box>
    </Box>
  );
};

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem('access_token');
    setIsAuthenticated(!!token);

    // Fired by services/api.ts logout() — either a manual logout or
    // an automatic one triggered by a 401 response from the backend.
    const handleLogout = () => setIsAuthenticated(false);
    window.addEventListener('auth:logout', handleLogout);
    return () => window.removeEventListener('auth:logout', handleLogout);
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
            <Route path="/terms" element={<LegalPage />} />
            <Route path="/privacy" element={<LegalPage />} />
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
          <Route path="/terms" element={<LegalPage />} />
          <Route path="/privacy" element={<LegalPage />} />
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
            path="/policies/sqli"
            element={
              <ProtectedRoute>
                <AppLayout>
                  <SQLiPolicies />
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
            path="/modules/payload"
            element={
              <ProtectedRoute>
                <AppLayout>
                  <PayloadModule />
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





