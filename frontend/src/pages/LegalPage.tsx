import React from 'react';
import { ArrowBack as ArrowBackIcon } from '@mui/icons-material';
import { Box, Button, Divider, Paper, Typography } from '@mui/material';
import { Link as RouterLink, useLocation } from 'react-router-dom';

const LegalPage: React.FC = () => {
  const isPrivacy = useLocation().pathname === '/privacy';

  return (
    <Box sx={{ minHeight: '100vh', p: { xs: 2, sm: 4 }, background: 'linear-gradient(135deg, #080808 0%, #171214 100%)' }}>
      <Paper sx={{ maxWidth: 820, mx: 'auto', p: { xs: 3, sm: 5 }, bgcolor: 'rgba(23,18,20,.97)' }}>
        <Button component={RouterLink} to="/register" startIcon={<ArrowBackIcon />} sx={{ mb: 2 }}>
          Back to registration
        </Button>
        <Typography variant="h4" component="h1" sx={{ fontWeight: 700, mb: 1 }}>
          {isPrivacy ? 'Privacy Policy' : 'Terms of Service'}
        </Typography>
        <Typography color="text.secondary" sx={{ mb: 3 }}>
          Sentinel-MCP Security Platform
        </Typography>
        <Divider sx={{ mb: 3 }} />

        {isPrivacy ? (
          <Box sx={{ '& h2': { fontSize: '1.15rem', mt: 3, mb: 1 }, '& p': { color: 'text.secondary', lineHeight: 1.75 } }}>
            <Typography component="h2">Information we collect</Typography>
            <Typography component="p" sx={{ mb: 2 }}>When you create an account, we store your name, username, email address, and a securely hashed password. The platform also records account activity and security events needed to operate and protect the service.</Typography>
            <Typography component="h2">How information is used</Typography>
            <Typography component="p" sx={{ mb: 2 }}>We use account information to provide sign-in and platform features, maintain security, investigate suspicious activity, and improve service reliability. Security event records may include request metadata and redacted payload details.</Typography>
            <Typography component="h2">Storage and sharing</Typography>
            <Typography component="p" sx={{ mb: 2 }}>Account and event information is stored by the platform. We do not sell personal information. Information may be disclosed when required by law or when necessary to protect the service and its users.</Typography>
            <Typography component="h2">Your choices and contact</Typography>
            <Typography component="p" sx={{ mb: 2 }}>Do not submit secrets or sensitive personal information in monitored tool requests. To ask about access, correction, or deletion of account information, contact the administrator of this Sentinel-MCP deployment.</Typography>
          </Box>
        ) : (
          <Box sx={{ '& h2': { fontSize: '1.15rem', mt: 3, mb: 1 }, '& p': { color: 'text.secondary', lineHeight: 1.75 } }}>
            <Typography component="h2">Using the service</Typography>
            <Typography component="p" sx={{ mb: 2 }}>Use Sentinel-MCP only for lawful purposes and only with systems and tools you are authorized to access. You are responsible for keeping your sign-in credentials secure and for activity under your account.</Typography>
            <Typography component="h2">Security monitoring</Typography>
            <Typography component="p" sx={{ mb: 2 }}>The platform may inspect, log, and analyze requests routed through its gateway to enforce configured policies, detect threats, and maintain an audit trail. Access to monitored systems may be blocked or flagged according to the deployment configuration.</Typography>
            <Typography component="h2">Availability and acceptable use</Typography>
            <Typography component="p" sx={{ mb: 2 }}>Do not misuse the service, attempt unauthorized access, interfere with its operation, or use it to violate another party's rights. Features may change, be suspended, or be unavailable during maintenance.</Typography>
            <Typography component="h2">Accounts and these terms</Typography>
            <Typography component="p" sx={{ mb: 2 }}>Accounts may be disabled when needed to protect the service or enforce these terms. By creating an account, you agree to these terms and the Privacy Policy. The administrator of this deployment operates the service and can answer questions about its use.</Typography>
          </Box>
        )}
      </Paper>
    </Box>
  );
};

export default LegalPage;
