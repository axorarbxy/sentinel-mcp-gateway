// components/ExtensionBanner.tsx
import React, { useState } from 'react';
import {
  Alert,
  Button,
  Box,
  Typography,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Stepper,
  Step,
  StepLabel,
  Chip,
  IconButton,
} from '@mui/material';
import {
  Close as CloseIcon,
  Download as DownloadIcon,
  CheckCircle as CheckCircleIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';
import { useExtensionDetected } from '../hooks/useExtensionDetected';

const ExtensionBanner: React.FC = () => {
  const isInstalled = useExtensionDetected();
  const [dismissed, setDismissed] = useState(false);
  const [dialogOpen, setDialogOpen] = useState(false);

  // Don't show if dismissed or already installed
  if (dismissed || isInstalled === true) return null;

  const handleInstallClick = () => {
    setDialogOpen(true);
  };

  const handleDownloadZip = () => {
    const link = document.createElement('a');
    link.href = '/sentinel-extension.zip';
    link.download = 'sentinel-mcp-extension.zip';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <>
      <Alert
        severity="info"
        icon={<SecurityIcon />}
        sx={{
          mb: 3,
          bgcolor: 'rgba(66, 165, 245, 0.1)',
          border: '1px solid rgba(66, 165, 245, 0.3)',
          '& .MuiAlert-message': { width: '100%' },
        }}
        action={
          <IconButton size="small" onClick={() => setDismissed(true)}>
            <CloseIcon fontSize="small" />
          </IconButton>
        }
      >
        <Box
          sx={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: 2,
          }}
        >
          <Box>
            <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 0.5 }}>
              🛡️ Get Real-Time Protection in Your Browser
            </Typography>
            <Typography variant="body2" color="textSecondary">
              Install the Sentinel-MCP extension to automatically block phishing URLs before they load.
            </Typography>
          </Box>
          <Button
            variant="contained"
            startIcon={<DownloadIcon />}
            onClick={handleInstallClick}
            sx={{
              background: 'linear-gradient(135deg, #90caf9, #42a5f5)',
              '&:hover': { background: 'linear-gradient(135deg, #42a5f5, #1e88e5)' },
              borderRadius: 2,
              py: 1,
              px: 3,
            }}
          >
            Install Extension
          </Button>
        </Box>
      </Alert>

      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <SecurityIcon color="primary" />
            <Typography variant="h6">Install Sentinel-MCP Extension</Typography>
          </Box>
        </DialogTitle>
        <DialogContent>
          <Stepper activeStep={-1} orientation="vertical" sx={{ mt: 2 }}>
            <Step completed={false}>
              <StepLabel>
                <Typography variant="subtitle2">1. Download Extension</Typography>
              </StepLabel>
              <Box sx={{ pl: 4, pb: 2 }}>
                <Typography variant="body2" color="textSecondary" sx={{ mb: 1 }}>
                  Click below to download the extension package.
                </Typography>
                <Button
                  variant="outlined"
                  startIcon={<DownloadIcon />}
                  onClick={handleDownloadZip}
                  size="small"
                >
                  Download Sentinel-MCP Extension (ZIP)
                </Button>
              </Box>
            </Step>

            <Step completed={false}>
              <StepLabel>
                <Typography variant="subtitle2">2. Extract ZIP File</Typography>
              </StepLabel>
              <Box sx={{ pl: 4, pb: 2 }}>
                <Typography variant="body2" color="textSecondary">
                  Extract the ZIP to a folder on your computer. Remember the location.
                </Typography>
              </Box>
            </Step>

            <Step completed={false}>
              <StepLabel>
                <Typography variant="subtitle2">3. Open Chrome Extensions</Typography>
              </StepLabel>
              <Box sx={{ pl: 4, pb: 2 }}>
                <Typography variant="body2" color="textSecondary">
                  Open a new tab and go to:
                </Typography>
                <Chip
                  label="chrome://extensions"
                  size="small"
                  sx={{ mt: 0.5, fontFamily: 'monospace', cursor: 'pointer' }}
                  onClick={() => {
                    navigator.clipboard.writeText('chrome://extensions');
                  }}
                />
              </Box>
            </Step>

            <Step completed={false}>
              <StepLabel>
                <Typography variant="subtitle2">4. Enable Developer Mode</Typography>
              </StepLabel>
              <Box sx={{ pl: 4, pb: 2 }}>
                <Typography variant="body2" color="textSecondary">
                  Toggle <strong>"Developer mode"</strong> in the top-right corner.
                </Typography>
              </Box>
            </Step>

            <Step completed={false}>
              <StepLabel>
                <Typography variant="subtitle2">5. Load Unpacked Extension</Typography>
              </StepLabel>
              <Box sx={{ pl: 4, pb: 2 }}>
                <Typography variant="body2" color="textSecondary">
                  Click <strong>"Load unpacked"</strong> and select the extracted folder.
                </Typography>
              </Box>
            </Step>

            <Step completed={false}>
              <StepLabel>
                <Typography variant="subtitle2">6. Done! 🎉</Typography>
              </StepLabel>
              <Box sx={{ pl: 4 }}>
                <Typography variant="body2" color="textSecondary">
                  The 🛡️ shield icon should appear in your browser toolbar. You're now protected!
                </Typography>
              </Box>
            </Step>
          </Stepper>

          <Alert severity="success" icon={<CheckCircleIcon />} sx={{ mt: 2 }}>
            <Typography variant="caption">
              <strong>Coming Soon:</strong> We're working on publishing to the Chrome Web Store.
              Once live, this becomes a one-click install!
            </Typography>
          </Alert>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default ExtensionBanner;