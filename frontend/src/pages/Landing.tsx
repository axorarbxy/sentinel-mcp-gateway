// pages/Landing.tsx
import React from 'react';
import {
  Box,
  Typography,
  Button,
  Container,
  Grid,
  Card,
  CardContent,
  AppBar,
  Toolbar,
  IconButton,
  useTheme,
  useMediaQuery,
  Chip,
  Avatar,
} from '@mui/material';
import {
  Security as SecurityIcon,
  Speed as SpeedIcon,
  Shield as ShieldIcon,
  Analytics as AnalyticsIcon,
  Warning as WarningIcon,
  Timeline as TimelineIcon,
  GitHub as GitHubIcon,
  Menu as MenuIcon,
  ArrowForward as ArrowForwardIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';

const features = [
  {
    icon: <SecurityIcon sx={{ fontSize: 40 }} />,
    title: 'AI Security Monitoring',
    description: 'Real-time monitoring of AI agent behavior with ML-based anomaly detection',
    color: '#90caf9',
  },
  {
    icon: <ShieldIcon sx={{ fontSize: 40 }} />,
    title: 'MCP Security Gateway',
    description: 'Protect AI agents at the Model Context Protocol layer with policy enforcement',
    color: '#4caf50',
  },
  {
    icon: <AnalyticsIcon sx={{ fontSize: 40 }} />,
    title: 'Threat Intelligence',
    description: '11 specialized detection modules for phishing, malware, IDS, and more',
    color: '#ff9800',
  },
  {
    icon: <SpeedIcon sx={{ fontSize: 40 }} />,
    title: 'Real-time Dashboard',
    description: 'Beautiful dark-themed dashboard with live statistics and alerts',
    color: '#f48fb1',
  },
  {
    icon: <WarningIcon sx={{ fontSize: 40 }} />,
    title: 'Anomaly Detection',
    description: 'Isolation Forest ML models detect behavioral deviations in real-time',
    color: '#f44336',
  },
  {
    icon: <TimelineIcon sx={{ fontSize: 40 }} />,
    title: 'Agent Profiling',
    description: 'Per-agent behavioral models with detailed activity tracking',
    color: '#ab47bc',
  },
];

const stats = [
  { label: 'Security Modules', value: '11', icon: <SecurityIcon /> },
  { label: 'ML Models', value: '7+', icon: <TimelineIcon /> },
  { label: 'Attack Vectors', value: '20+', icon: <WarningIcon /> },
  { label: 'Endpoints', value: '15+', icon: <AnalyticsIcon /> },
];

const Landing: React.FC = () => {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('sm'));
  const navigate = useNavigate();

  const isAuthenticated = !!localStorage.getItem('access_token');

  return (
    <Box sx={{ bgcolor: '#0a1929', minHeight: '100vh' }}>
      {/* Navigation */}
      <AppBar
        position="sticky"
        elevation={0}
        sx={{
          bgcolor: 'rgba(10, 25, 41, 0.95)',
          backdropFilter: 'blur(10px)',
          borderBottom: '1px solid rgba(255,255,255,0.05)',
        }}
      >
        <Toolbar>
          <Typography variant="h6" sx={{ flexGrow: 1, fontWeight: 600 }}>
            🛡️ Sentinel-MCP
          </Typography>
          
          {isMobile ? (
            <IconButton color="inherit">
              <MenuIcon />
            </IconButton>
          ) : (
            <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
              <Button color="inherit" href="#features">
                Features
              </Button>
              <Button color="inherit" href="#modules">
                Modules
              </Button>
              <Button
                variant="outlined"
                color="primary"
                onClick={() => navigate('/login')}
                sx={{ borderRadius: 2 }}
              >
                Sign In
              </Button>
              <Button
                variant="contained"
                color="primary"
                onClick={() => navigate('/register')}
                sx={{
                  borderRadius: 2,
                  background: 'linear-gradient(135deg, #90caf9, #42a5f5)',
                  '&:hover': {
                    background: 'linear-gradient(135deg, #42a5f5, #1e88e5)',
                  },
                }}
              >
                Get Started
              </Button>
            </Box>
          )}
        </Toolbar>
      </AppBar>

      {/* Hero Section */}
      <Box
        sx={{
          pt: { xs: 8, md: 12 },
          pb: { xs: 6, md: 10 },
          textAlign: 'center',
          position: 'relative',
          overflow: 'hidden',
        }}
      >
        <Container maxWidth="lg">
          <Box sx={{ position: 'relative', zIndex: 1 }}>
            <Chip
              label="🚀 2026 Research Implementation"
              color="primary"
              sx={{ mb: 3, fontSize: '0.9rem', py: 1 }}
            />
            <Typography
              variant="h2"
              component="h1"
              sx={{
                fontWeight: 800,
                mb: 2,
                background: 'linear-gradient(135deg, #90caf9 0%, #42a5f5 50%, #f48fb1 100%)',
                backgroundClip: 'text',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
                fontSize: { xs: '2.5rem', md: '4rem' },
              }}
            >
              AI/ML Security Monitoring Framework
            </Typography>
            <Typography
              variant="h5"
              color="textSecondary"
              sx={{ maxWidth: 700, mx: 'auto', mb: 4, fontWeight: 300 }}
            >
              Protect your AI agents with 3-layer defense: Policy Engine + Behavioral Analysis + ML Anomaly Detection
            </Typography>
            <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
              <Button
                variant="contained"
                size="large"
                onClick={() => navigate(isAuthenticated ? '/dashboard' : '/register')}
                endIcon={<ArrowForwardIcon />}
                sx={{
                  px: 4,
                  py: 1.5,
                  borderRadius: 3,
                  fontSize: '1.1rem',
                  background: 'linear-gradient(135deg, #90caf9, #42a5f5)',
                  '&:hover': {
                    background: 'linear-gradient(135deg, #42a5f5, #1e88e5)',
                  },
                }}
              >
                {isAuthenticated ? 'Go to Dashboard' : 'Get Started Free'}
              </Button>
              <Button
                variant="outlined"
                size="large"
                href="https://github.com/axorarbxy/sentinel-mcp-gateway"
                target="_blank"
                startIcon={<GitHubIcon />}
                sx={{
                  px: 4,
                  py: 1.5,
                  borderRadius: 3,
                  fontSize: '1.1rem',
                }}
              >
                View on GitHub
              </Button>
            </Box>
          </Box>
        </Container>
      </Box>

      {/* Stats Section - Using Box with flex instead of Grid */}
      <Container maxWidth="lg" sx={{ py: 4 }}>
        <Box sx={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'center', gap: 3 }}>
          {stats.map((stat, index) => (
            <Box key={index} sx={{ flex: '1 1 150px', maxWidth: 200, minWidth: 120 }}>
              <Card
                sx={{
                  textAlign: 'center',
                  bgcolor: 'rgba(26, 35, 50, 0.8)',
                  backdropFilter: 'blur(10px)',
                  border: '1px solid rgba(255,255,255,0.05)',
                  py: 2,
                }}
              >
                <Avatar
                  sx={{
                    mx: 'auto',
                    mb: 1,
                    bgcolor: 'rgba(144,202,249,0.15)',
                    color: '#90caf9',
                  }}
                >
                  {stat.icon}
                </Avatar>
                <Typography variant="h4" sx={{ fontWeight: 700 }}>
                  {stat.value}
                </Typography>
                <Typography variant="body2" color="textSecondary">
                  {stat.label}
                </Typography>
              </Card>
            </Box>
          ))}
        </Box>
      </Container>

      {/* Features Section - Using Box with flex instead of Grid */}
      <Container maxWidth="lg" sx={{ py: 8 }} id="features">
        <Typography
          variant="h3"
          component="h2"
          sx={{
            textAlign: 'center',
            mb: 2,
            fontWeight: 700,
          }}
        >
          Powerful Security Features
        </Typography>
        <Typography
          variant="body1"
          color="textSecondary"
          sx={{ textAlign: 'center', mb: 6, maxWidth: 600, mx: 'auto' }}
        >
          Built on 2026 research, combining rule-based policies with machine learning for comprehensive AI security
        </Typography>

        <Box sx={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'center', gap: 3 }}>
          {features.map((feature, index) => (
            <Box key={index} sx={{ flex: '1 1 280px', maxWidth: 360, minWidth: 250 }}>
              <Card
                sx={{
                  height: '100%',
                  bgcolor: 'rgba(26, 35, 50, 0.8)',
                  backdropFilter: 'blur(10px)',
                  border: '1px solid rgba(255,255,255,0.05)',
                  transition: 'transform 0.2s, box-shadow 0.2s',
                  '&:hover': {
                    transform: 'translateY(-8px)',
                    boxShadow: '0 8px 40px rgba(0,0,0,0.4)',
                  },
                }}
              >
                <CardContent>
                  <Box sx={{ color: feature.color, mb: 2 }}>{feature.icon}</Box>
                  <Typography variant="h6" gutterBottom>
                    {feature.title}
                  </Typography>
                  <Typography variant="body2" color="textSecondary">
                    {feature.description}
                  </Typography>
                </CardContent>
              </Card>
            </Box>
          ))}
        </Box>
      </Container>

      {/* Modules Section - Using Box with flex instead of Grid */}
      <Box sx={{ bgcolor: 'rgba(26, 35, 50, 0.5)', py: 8 }} id="modules">
        <Container maxWidth="lg">
          <Typography
            variant="h3"
            component="h2"
            sx={{
              textAlign: 'center',
              mb: 2,
              fontWeight: 700,
            }}
          >
            CyberEye 11-Module Suite
          </Typography>
          <Typography
            variant="body1"
            color="textSecondary"
            sx={{ textAlign: 'center', mb: 6, maxWidth: 600, mx: 'auto' }}
          >
            Comprehensive security coverage across multiple threat vectors
          </Typography>

          <Box sx={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'center', gap: 2 }}>
            {[
              { name: 'Phishing Detection', icon: '🔗', desc: 'URL classification' },
              { name: 'Malware Detection', icon: '🦠', desc: 'File/APK analysis' },
              { name: 'Network IDS', icon: '🌐', desc: 'Traffic monitoring' },
              { name: 'Insider Threat', icon: '👤', desc: 'Behavioral analysis' },
              { name: 'Android Security', icon: '📱', desc: 'App permission audit' },
              { name: 'Password Analyzer', icon: '🔑', desc: 'Strength check' },
              { name: 'QR Scanner', icon: '📷', desc: 'Safety checker' },
              { name: 'Risk Scoring', icon: '📊', desc: 'Unified risk' },
              { name: 'Auto Response', icon: '⚡', desc: 'Automated actions' },
            ].map((module, index) => (
              <Box key={index} sx={{ flex: '1 1 140px', maxWidth: 180, minWidth: 120 }}>
                <Card
                  sx={{
                    textAlign: 'center',
                    bgcolor: 'rgba(26, 35, 50, 0.6)',
                    border: '1px solid rgba(255,255,255,0.05)',
                    py: 2,
                    transition: 'transform 0.2s',
                    '&:hover': {
                      transform: 'scale(1.05)',
                      borderColor: 'primary.main',
                    },
                  }}
                >
                  <Typography variant="h3" sx={{ mb: 1 }}>
                    {module.icon}
                  </Typography>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>
                    {module.name}
                  </Typography>
                  <Typography variant="caption" color="textSecondary">
                    {module.desc}
                  </Typography>
                </Card>
              </Box>
            ))}
          </Box>
        </Container>
      </Box>

      {/* CTA Section */}
      <Container maxWidth="lg" sx={{ py: 8 }}>
        <Card
          sx={{
            p: { xs: 4, md: 6 },
            textAlign: 'center',
            background: 'linear-gradient(135deg, rgba(144,202,249,0.1), rgba(244,143,177,0.05))',
            border: '1px solid rgba(255,255,255,0.05)',
            borderRadius: 4,
          }}
        >
          <Typography variant="h4" sx={{ mb: 2, fontWeight: 700 }}>
            Ready to Secure Your AI Agents?
          </Typography>
          <Typography variant="body1" color="textSecondary" sx={{ mb: 4, maxWidth: 500, mx: 'auto' }}>
            Join the next generation of AI security with Sentinel-MCP
          </Typography>
          <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
            <Button
              variant="contained"
              size="large"
              onClick={() => navigate('/register')}
              endIcon={<ArrowForwardIcon />}
              sx={{
                px: 5,
                py: 1.5,
                borderRadius: 3,
                fontSize: '1.1rem',
                background: 'linear-gradient(135deg, #90caf9, #42a5f5)',
                '&:hover': {
                  background: 'linear-gradient(135deg, #42a5f5, #1e88e5)',
                },
              }}
            >
              Get Started Now
            </Button>
            <Button
              variant="outlined"
              size="large"
              href="https://github.com/axorarbxy/sentinel-mcp-gateway"
              target="_blank"
              startIcon={<GitHubIcon />}
              sx={{ px: 5, py: 1.5, borderRadius: 3, fontSize: '1.1rem' }}
            >
              GitHub
            </Button>
          </Box>
        </Card>
      </Container>

      {/* Footer */}
      <Box
        sx={{
          py: 4,
          textAlign: 'center',
          borderTop: '1px solid rgba(255,255,255,0.05)',
          mt: 4,
        }}
      >
        <Typography variant="body2" color="textSecondary">
          © 2026 Sentinel-MCP. Built with ❤️ for the AI/ML security community.
          <br />
          Based on SECUREVENT (arXiv 2606.01741) and 2026 research.
        </Typography>
      </Box>
    </Box>
  );
};

export default Landing;