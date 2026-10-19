// App.tsx
import React, { useState, useEffect } from 'react';
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
  palette: {
    mode: 'dark',
    primary: { main: '#56E0C3', light: '#A1F3DF', dark: '#1D9F8C', contrastText: '#07130F' },
    secondary: { main: '#A99BFF', contrastText: '#0C1020' },
    background: { default: '#080D14', paper: '#101822' },
    text: { primary: '#F3F7FA', secondary: '#9BAAB7' },
  },
  components: {
    MuiLink: {
      styleOverrides: {
        root: { color: '#56E0C3' },
      },
    },
    MuiTab: {
      styleOverrides: {
        root: {
          '&.Mui-selected': { color: '#56E0C3' },
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: { borderRadius: 10, textTransform: 'none', fontWeight: 700 },
        outlined: { color: '#56E0C3', borderColor: 'rgba(86, 224, 195, 0.4)' },
      },
    },
    MuiSvgIcon: {
      styleOverrides: {
        colorPrimary: { color: '#56E0C3' },
      },
    },
    MuiPaper: { styleOverrides: { root: { backgroundImage: 'none', border: '1px solid rgba(154, 175, 193, 0.11)', borderRadius: 16 } } },
    MuiCard: { styleOverrides: { root: { backgroundImage: 'linear-gradient(145deg, rgba(18, 29, 41, .98), rgba(13, 21, 31, .98))', border: '1px solid rgba(154, 175, 193, 0.12)', borderRadius: 16 } } },
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

  const handleLogout = () => {
    logout();
    navigate('/login', { replace: true });
  };

  const pageTitle = navGroups.flatMap((group) => group.items).find((item) =>
    item.path === location.pathname || (item.path !== '/dashboard' && location.pathname.startsWith(item.path)),
  )?.label || 'Security workspace';

  const drawer = (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column', px: 2, py: 2.5 }}>
      <Box onClick={() => navigate('/dashboard')} sx={{ display: 'flex', alignItems: 'center', gap: 1.4, px: 1.2, mb: 4, cursor: 'pointer' }}>
        <Box sx={{ width: 40, height: 40, display: 'grid', placeItems: 'center', borderRadius: 2.5, color: '#07130F', background: 'linear-gradient(135deg, #76F0D0, #39BDA6)', boxShadow: '0 8px 24px rgba(57,189,166,.2)' }}><SecurityIcon /></Box>
        <Box><Typography sx={{ fontWeight: 900, letterSpacing: 1.1, lineHeight: 1.1 }}>CYBEREYE</Typography><Typography sx={{ color: '#718494', fontSize: 10, letterSpacing: 2.2, mt: .5 }}>SENTINEL PLATFORM</Typography></Box>
      </Box>
      {navGroups.map((group) => <Box key={group.label} sx={{ mb: 2.8 }}>
        <Typography sx={{ color: '#607383', fontSize: 10, fontWeight: 800, letterSpacing: 1.8, px: 1.5, mb: .8 }}>{group.label}</Typography>
        <List disablePadding>
          {group.items.map((item) => {
            const selected = item.path === location.pathname || (item.path !== '/dashboard' && location.pathname.startsWith(item.path));
            return <ListItemButton key={item.path} selected={selected} onClick={() => { navigate(item.path); setMobileOpen(false); }} sx={{ mb: .35, px: 1.5, py: 1.15, borderRadius: 2.5, color: selected ? '#EAFBF7' : '#93A3B1', '& .MuiListItemIcon-root': { minWidth: 38, color: selected ? '#56E0C3' : '#64798A' }, '&.Mui-selected': { background: 'linear-gradient(90deg, rgba(86,224,195,.16), rgba(86,224,195,.035))', boxShadow: 'inset 2px 0 #56E0C3' }, '&.Mui-selected:hover': { background: 'rgba(86,224,195,.18)' }, '&:hover': { color: '#F3F7FA', backgroundColor: 'rgba(255,255,255,.035)' } }}>
              <ListItemIcon>{item.icon}</ListItemIcon><ListItemText primary={item.label} slotProps={{ primary: { sx: { fontSize: 13, fontWeight: selected ? 750 : 550 } } }} />{selected && <Box sx={{ width: 5, height: 5, bgcolor: '#56E0C3', borderRadius: '50%', boxShadow: '0 0 12px #56E0C3' }} />}
            </ListItemButton>;
          })}
        </List>
      </Box>)}
      <Box sx={{ mt: 'auto', p: 1.5, border: '1px solid rgba(154,175,193,.12)', borderRadius: 3, background: 'linear-gradient(145deg, rgba(19,31,42,.9), rgba(12,20,29,.85))' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: .8 }}><InsightsIcon sx={{ fontSize: 17, color: '#56E0C3' }} /><Typography sx={{ fontSize: 11, fontWeight: 800 }}>Gateway telemetry</Typography></Box>
        <Typography sx={{ color: '#8293A0', fontSize: 11, lineHeight: 1.6 }}>Live inspection for agent traffic and security signals.</Typography>
        <Divider sx={{ my: 1.2, borderColor: 'rgba(154,175,193,.12)' }} />
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}><Typography sx={{ color: '#758795', fontSize: 10, fontFamily: 'monospace' }}>API · :8001</Typography><Box sx={{ width: 7, height: 7, borderRadius: '50%', bgcolor: statusConfig.color, boxShadow: `0 0 10px ${statusConfig.color}` }} /></Box>
      </Box>
    </Box>
  );

  return (
    <Box sx={{ minHeight: '100vh', display: 'flex', color: 'text.primary', background: 'radial-gradient(ellipse at 76% -12%, rgba(29,159,140,.10), transparent 32%), #080D14' }}>
      <Drawer variant={desktop ? 'permanent' : 'temporary'} open={desktop || mobileOpen} onClose={() => setMobileOpen(false)} ModalProps={{ keepMounted: true }} sx={{ width: { md: 264 }, flexShrink: 0, '& .MuiDrawer-paper': { width: 264, boxSizing: 'border-box', bgcolor: '#0A1119', border: 0, borderRight: '1px solid rgba(154,175,193,.1)' } }}>{drawer}</Drawer>
      <Box sx={{ minWidth: 0, flex: 1 }}>
        <AppBar position="sticky" elevation={0} sx={{ bgcolor: 'rgba(8,13,20,.86)', backdropFilter: 'blur(18px)', borderBottom: '1px solid rgba(154,175,193,.1)' }}>
          <Toolbar sx={{ minHeight: '72px !important', px: { xs: 2, md: 4 } }}>
            {!desktop && <IconButton onClick={() => setMobileOpen(true)} sx={{ mr: 1.5, color: 'text.primary' }} aria-label="Open navigation"><MenuIcon /></IconButton>}
            <Box><Typography sx={{ color: '#708393', fontSize: 10, letterSpacing: 1.7, fontWeight: 800 }}>SECURITY OPERATIONS / {pageTitle.toUpperCase()}</Typography><Typography sx={{ fontSize: 15, fontWeight: 750, mt: .3 }}>{pageTitle}</Typography></Box>
            <Box sx={{ ml: 'auto', display: 'flex', alignItems: 'center', gap: { xs: 1, sm: 2 } }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: .9, px: 1.4, py: .8, bgcolor: statusConfig.bg, border: `1px solid ${statusConfig.border}`, borderRadius: 20 }}><Box sx={{ width: 7, height: 7, borderRadius: '50%', bgcolor: statusConfig.color, boxShadow: `0 0 9px ${statusConfig.color}` }} /><Typography sx={{ fontSize: 10, fontWeight: 850, letterSpacing: .8, color: statusConfig.color, display: { xs: 'none', sm: 'block' } }}>{statusConfig.label}</Typography></Box>
              <Button variant="outlined" size="small" startIcon={<LogoutIcon />} onClick={handleLogout} sx={{ color: '#AAB8C2', borderColor: 'rgba(154,175,193,.18)', '&:hover': { borderColor: 'primary.main', color: 'primary.light' } }}>Sign out</Button>
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
