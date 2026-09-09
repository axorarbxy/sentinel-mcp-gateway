// pages/modules/QRModule.tsx
import React, { useState, useRef, useCallback, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
  TextField,
  Button,
  Chip,
  Slider,
  IconButton,
  Divider,
  LinearProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Alert,
  Snackbar,
  Tabs,
  Tab,
  Avatar,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
} from '@mui/material';
import {
  QrCode as QrCodeIcon,
  CameraAlt as CameraIcon,
  Upload as UploadIcon,
  Download as DownloadIcon,
  ContentCopy as CopyIcon,
  Share as ShareIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Delete as DeleteIcon,
  History as HistoryIcon,
  QrCodeScanner as ScanIcon,
  Add as AddIcon,
  Security as SecurityIcon,
  ShoppingCart as ShoppingCartIcon,
  Payment as PaymentIcon,
  Restaurant as RestaurantIcon,
  LocationOn as LocationIcon,
  Wifi as WifiIcon,
  Hotel as HotelIcon,
  Event as EventIcon,
  Folder as FolderIcon,
  Email as EmailIcon,
  Videocam as VideoIcon,
  Close as CloseIcon,
} from '@mui/icons-material';
import { QRCodeSVG } from 'qrcode.react';
import Webcam from 'react-webcam';
import jsQR from 'jsqr';

interface QRHistoryItem {
  id: number;
  type: 'generated' | 'scanned';
  content: string;
  status: 'safe' | 'malicious' | 'unknown';
  timestamp: Date;
  metadata: {
    size?: string;
    color?: string;
    scanMethod?: string;
    qrType?: string;
  };
}

interface ScanResult {
  content: string;
  status: 'safe' | 'malicious' | 'unknown';
  suspicionScore: number;
  indicators: string[];
  confidence: number;
  timestamp: Date;
  qrType: string;
  upiId?: string;
  isPaymentQR?: boolean;
}

const detectQRType = (content: string): string => {
  if (!content) return 'Unknown';
  if (content.includes('upi://') || content.includes('pay.google.com') || content.includes('gpay')) return 'UPI Payment';
  if (content.startsWith('WIFI:')) return 'WiFi';
  if (content.startsWith('mailto:')) return 'Email';
  if (content.includes('maps.google.com')) return 'Location';
  if (content.includes('meet.google.com')) return 'Meeting';
  if (content.includes('amazon.in') || content.includes('amazon.com')) return 'Shopping';
  if (content.includes('zomato.com') || content.includes('swiggy.com')) return 'Restaurant';
  if (content.includes('booking.com')) return 'Hotel';
  if (content.includes('eventbrite.com')) return 'Event';
  if (content.includes('drive.google.com')) return 'File Share';
  if (content.includes('wa.me') || content.includes('whatsapp')) return 'WhatsApp';
  if (content.startsWith('http://') || content.startsWith('https://')) return 'URL';
  return 'Other';
};

const extractUPIId = (content: string): string => {
  if (!content) return '';
  if (content.includes('upi://')) {
    const match = content.match(/pa=([^&]*)/);
    if (match) return decodeURIComponent(match[1]);
  }
  return '';
};

const QRModule: React.FC = () => {
  const [tabValue, setTabValue] = useState(0);
  const [qrData, setQrData] = useState('');
  const [qrSize, setQrSize] = useState(256);
  const [qrColor, setQrColor] = useState('#000000');
  const [bgColor, setBgColor] = useState('#ffffff');
  const [history, setHistory] = useState<QRHistoryItem[]>([]);
  const [selectedResult, setSelectedResult] = useState<ScanResult | null>(null);
  const [uploadedImage, setUploadedImage] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [snackbarOpen, setSnackbarOpen] = useState(false);
  const [snackbarMessage, setSnackbarMessage] = useState('');
  const [snackbarSeverity, setSnackbarSeverity] = useState<'success' | 'error' | 'info' | 'warning'>('info');
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Camera state
  const [cameraOpen, setCameraOpen] = useState(false);
  const [cameraError, setCameraError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const webcamRef = useRef<Webcam>(null);
  const scanIntervalRef = useRef<NodeJS.Timeout | null>(null);

  const totalGenerated = history.filter(h => h.type === 'generated').length;
  const totalScanned = history.filter(h => h.type === 'scanned').length;
  const totalMalicious = history.filter(h => h.status === 'malicious').length;
  const scanSuccessRate = totalScanned > 0 ? ((totalScanned - totalMalicious) / totalScanned * 100) : 100;

  const showSnackbar = (msg: string, sev: 'success' | 'error' | 'info' | 'warning') => {
    setSnackbarMessage(msg);
    setSnackbarSeverity(sev);
    setSnackbarOpen(true);
  };

  // ============ CAMERA HANDLING ============
  const openCamera = () => {
    setCameraError(null);
    setCameraOpen(true);
    setScanning(true);
    setSelectedResult(null);
  };

  const closeCamera = () => {
    if (scanIntervalRef.current) {
      clearInterval(scanIntervalRef.current);
      scanIntervalRef.current = null;
    }
    setCameraOpen(false);
    setScanning(false);
  };

  const analyzeQRContent = useCallback(async (content: string) => {
    try {
      const response = await fetch('http://localhost:8001/ml/analyze/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: content }),
      });

      if (response.ok) {
        const result = await response.json();
        
        const isUPI = content.includes('upi://') ||
                      content.includes('pay.google.com') ||
                      content.includes('gpay');
        
        const upiId = extractUPIId(content);

        const scanResult: ScanResult = {
          content: content,
          status: isUPI ? 'safe' : (result.is_suspicious ? 'malicious' : 'safe'),
          suspicionScore: isUPI ? 0 : (result.risk_score * 100),
          indicators: isUPI ? ['✅ Verified UPI Payment QR'] : (result.risk_factors || []),
          confidence: isUPI ? 1.0 : result.risk_score,
          timestamp: new Date(),
          qrType: detectQRType(content),
          upiId: upiId,
          isPaymentQR: isUPI
        };

        setSelectedResult(scanResult);

        const newEntry: QRHistoryItem = {
          id: Date.now(),
          type: 'scanned',
          content: content,
          status: isUPI ? 'safe' : (result.is_suspicious ? 'malicious' : 'safe'),
          timestamp: new Date(),
          metadata: { scanMethod: 'camera', qrType: scanResult.qrType },
        };
        setHistory(prev => [newEntry, ...prev]);

        showSnackbar(
          isUPI ? '✅ UPI Payment QR verified safely' :
          (result.is_suspicious ? '⚠️ Suspicious QR detected' : '✅ QR code scanned successfully'),
          isUPI ? 'success' : (result.is_suspicious ? 'error' : 'success')
        );

        return true;
      }
      return false;
    } catch (error) {
      console.error('Analysis error:', error);
      showSnackbar('Network error while analyzing QR', 'error');
      return false;
    }
  }, []);

  const captureAndDecode = useCallback(async () => {
    if (!webcamRef.current) return;

    const imageSrc = webcamRef.current.getScreenshot();
    if (!imageSrc) return;

    // Decode QR from image using jsQR
    const img = new Image();
    img.src = imageSrc;
    
    await new Promise((resolve) => { img.onload = resolve; });

    const canvas = document.createElement('canvas');
    canvas.width = img.width;
    canvas.height = img.height;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    
    const qrCode = jsQR(imageData.data, imageData.width, imageData.height, {
      inversionAttempts: 'dontInvert',
    });

    if (qrCode && qrCode.data) {
      console.log('✅ QR detected:', qrCode.data);
      
      // Stop scanning
      if (scanIntervalRef.current) {
        clearInterval(scanIntervalRef.current);
        scanIntervalRef.current = null;
      }
      setScanning(false);
      
      // Show preview image
      setUploadedImage(imageSrc);
      
      // Analyze the QR content
      await analyzeQRContent(qrCode.data);
      
      // Close camera
      closeCamera();
    }
  }, [analyzeQRContent]);

  useEffect(() => {
    if (cameraOpen && scanning) {
      // Scan every 500ms
      scanIntervalRef.current = setInterval(() => {
        captureAndDecode();
      }, 500);

      return () => {
        if (scanIntervalRef.current) {
          clearInterval(scanIntervalRef.current);
        }
      };
    }
  }, [cameraOpen, scanning, captureAndDecode]);

  // ============ GENERATE QR ============
  const handleGenerateQR = () => {
    if (!qrData.trim()) {
      showSnackbar('Please enter text or URL to generate QR code', 'warning');
      return;
    }

    const newEntry: QRHistoryItem = {
      id: Date.now(),
      type: 'generated',
      content: qrData,
      status: 'safe',
      timestamp: new Date(),
      metadata: { size: `${qrSize}x${qrSize}`, color: qrColor, qrType: 'Generated' },
    };
    setHistory([newEntry, ...history]);
    showSnackbar('QR Code generated successfully!', 'success');
  };

  // ============ SCAN UPLOADED IMAGE ============
  const handleScanQR = async (file?: File) => {
    if (!file && !uploadedImage) {
      showSnackbar('Please upload an image first', 'warning');
      return;
    }

    setIsScanning(true);
    setSelectedResult(null);

    try {
      let imageBase64 = uploadedImage;

      if (file) {
        const reader = new FileReader();
        const base64 = await new Promise<string>((resolve, reject) => {
          reader.onload = (e) => resolve(e.target?.result as string);
          reader.onerror = () => reject('Failed to read file');
          reader.readAsDataURL(file);
        });
        imageBase64 = base64;
        setUploadedImage(imageBase64);
      }

      if (!imageBase64) {
        throw new Error('No image to scan');
      }

      const response = await fetch('http://localhost:8001/ml/scan/qr', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ image: imageBase64, scan_type: 'base64' }),
      });

      if (response.ok) {
        const result = await response.json();

        if (!result.decoded_content || result.decoded_content === 'No QR code found in image') {
          showSnackbar('❌ No QR code found in the image.', 'warning');
          setSelectedResult({
            content: 'No QR code detected in this image',
            status: 'unknown',
            suspicionScore: 0,
            indicators: ['No QR code found'],
            confidence: 0,
            timestamp: new Date(),
            qrType: 'No QR Code',
          });
          setIsScanning(false);
          return;
        }

        const isUPI = result.decoded_content.includes('upi://') ||
                      result.decoded_content.includes('pay.google.com') ||
                      result.decoded_content.includes('gpay');

        const upiId = extractUPIId(result.decoded_content);

        const scanResult: ScanResult = {
          content: result.decoded_content,
          status: isUPI ? 'safe' : (result.is_malicious ? 'malicious' : 'safe'),
          suspicionScore: isUPI ? 0 : (result.confidence * 100),
          indicators: isUPI ? ['✅ Verified UPI Payment QR'] : (result.risk_factors || []),
          confidence: isUPI ? 1.0 : result.confidence,
          timestamp: new Date(),
          qrType: detectQRType(result.decoded_content),
          upiId: upiId,
          isPaymentQR: isUPI
        };

        setSelectedResult(scanResult);

        const newEntry: QRHistoryItem = {
          id: Date.now(),
          type: 'scanned',
          content: result.decoded_content,
          status: isUPI ? 'safe' : (result.is_malicious ? 'malicious' : 'safe'),
          timestamp: new Date(),
          metadata: { scanMethod: file ? 'upload' : 'camera', qrType: scanResult.qrType },
        };
        setHistory([newEntry, ...history]);

        showSnackbar(
          isUPI ? '✅ UPI Payment QR code verified safely' :
          (result.is_malicious ? '⚠️ Suspicious QR code detected' : '✅ QR code scanned successfully'),
          isUPI ? 'success' : (result.is_malicious ? 'error' : 'success')
        );
      } else {
        const error = await response.json();
        showSnackbar(`Scan failed: ${error.detail || 'Unknown error'}`, 'error');
      }
    } catch (error) {
      console.error('❌ Scan error:', error);
      showSnackbar('Network error. Make sure the ML scanner is running.', 'error');
    } finally {
      setIsScanning(false);
    }
  };

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        setUploadedImage(e.target?.result as string);
        handleScanQR(file);
      };
      reader.readAsDataURL(file);
    }
  };

  const handleDownloadQR = () => {
    if (tabValue === 0 && qrData) {
      const canvas = document.getElementById('qr-code-canvas') as HTMLCanvasElement;
      if (canvas) {
        const link = document.createElement('a');
        link.download = `qr-code-${Date.now()}.png`;
        link.href = canvas.toDataURL('image/png');
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        showSnackbar('✅ QR Code downloaded!', 'success');
      }
      return;
    }

    if (tabValue === 1 && selectedResult && selectedResult.qrType !== 'No QR Code') {
      const content = selectedResult.content;
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const blob = new Blob(
        [`QR Code Content\n${'='.repeat(40)}\n\nDecoded Content: ${content}\n\nTimestamp: ${new Date().toLocaleString()}`],
        { type: 'text/plain' }
      );
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.download = `qr-content-${timestamp}.txt`;
      link.href = url;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      showSnackbar('✅ Downloaded!', 'success');
      return;
    }

    showSnackbar('⚠️ No content to download.', 'warning');
  };

  const handleCopyContent = (content: string) => {
    navigator.clipboard.writeText(content);
    showSnackbar('📋 Copied to clipboard!', 'success');
  };

  const handleShare = async (content: string, title: string = 'QR Code') => {
    try {
      if (navigator.share) {
        await navigator.share({
          title: title,
          text: `QR Code Content: ${content}`,
          url: content.startsWith('http') ? content : undefined,
        });
        showSnackbar('✅ Shared!', 'success');
      } else {
        await navigator.clipboard.writeText(content);
        showSnackbar('📋 Copied to clipboard!', 'info');
      }
    } catch (error: any) {
      if (error.name === 'AbortError') return;
      await navigator.clipboard.writeText(content);
      showSnackbar('📋 Copied to clipboard!', 'success');
    }
  };

  const handleDeleteHistory = (id: number) => {
    setHistory(history.filter(h => h.id !== id));
    showSnackbar('Deleted', 'info');
  };

  const getRiskColor = (score: number) => {
    if (score > 70) return 'error';
    if (score > 40) return 'warning';
    return 'success';
  };

  const getQRTypeIcon = (type: string) => {
    switch (type) {
      case 'UPI Payment': return <PaymentIcon />;
      case 'Restaurant': return <RestaurantIcon />;
      case 'Shopping': return <ShoppingCartIcon />;
      case 'WiFi': return <WifiIcon />;
      case 'Meeting': return <VideoIcon />;
      case 'Location': return <LocationIcon />;
      case 'Event': return <EventIcon />;
      case 'Hotel': return <HotelIcon />;
      case 'File Share': return <FolderIcon />;
      case 'Email': return <EmailIcon />;
      case 'WhatsApp': return <EmailIcon />;
      default: return <QrCodeIcon />;
    }
  };

  return (
    <Box sx={{ p: 3, maxWidth: 1400, mx: 'auto' }}>
      <Paper sx={{ p: 3, mb: 3, bgcolor: 'rgba(26,35,50,0.8)' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Avatar sx={{ bgcolor: 'primary.main', width: 56, height: 56 }}>
              <QrCodeIcon sx={{ fontSize: 32 }} />
            </Avatar>
            <Box>
              <Typography variant="h4" sx={{ fontWeight: 600 }}>QR Module</Typography>
              <Typography variant="body2" color="textSecondary">
                Generate, scan, and analyze QR codes with security checks
              </Typography>
            </Box>
          </Box>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Chip icon={<SecurityIcon />} label="Security Scan Enabled" color="success" />
            <Chip icon={<HistoryIcon />} label={`${history.length} entries`} variant="outlined" />
          </Box>
        </Box>
      </Paper>

      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid size={{ xs: 6, sm: 3 }}>
          <Card sx={{ bgcolor: 'rgba(26,35,50,0.8)' }}>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="caption" color="textSecondary">QR Codes Generated</Typography>
              <Typography variant="h4" sx={{ fontWeight: 700 }}>{totalGenerated}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <Card sx={{ bgcolor: 'rgba(26,35,50,0.8)' }}>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="caption" color="textSecondary">QR Codes Scanned</Typography>
              <Typography variant="h4" sx={{ fontWeight: 700 }}>{totalScanned}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <Card sx={{ bgcolor: 'rgba(26,35,50,0.8)' }}>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="caption" color="textSecondary">Malicious Detected</Typography>
              <Typography variant="h4" sx={{ fontWeight: 700, color: 'error.main' }}>{totalMalicious}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <Card sx={{ bgcolor: 'rgba(26,35,50,0.8)' }}>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="caption" color="textSecondary">Scan Success Rate</Typography>
              <Typography variant="h4" sx={{ fontWeight: 700, color: 'success.main' }}>
                {scanSuccessRate.toFixed(0)}%
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Paper sx={{ mb: 3 }}>
        <Tabs value={tabValue} onChange={(e, v) => setTabValue(v)}>
          <Tab icon={<AddIcon />} label="Generate" />
          <Tab icon={<ScanIcon />} label="Scan" />
          <Tab icon={<HistoryIcon />} label="History" />
        </Tabs>
      </Paper>

      {tabValue === 0 && (
        <Grid container spacing={3}>
          <Grid size={{ xs: 12, md: 7 }}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>Generate QR Code</Typography>
              <TextField
                fullWidth multiline rows={3}
                placeholder="Enter text, URL, or data here..."
                value={qrData}
                onChange={(e) => setQrData(e.target.value)}
                sx={{ mb: 2 }}
                slotProps={{ htmlInput: { maxLength: 1000 } }}
              />
              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid size={{ xs: 6 }}>
                  <Typography variant="caption">Size: {qrSize}x{qrSize}</Typography>
                  <Slider value={qrSize} onChange={(e, v) => setQrSize(v as number)} min={100} max={500} step={50} />
                </Grid>
                <Grid size={{ xs: 6 }}>
                  <Box sx={{ display: 'flex', gap: 2, mt: 1 }}>
                    <Box>
                      <Typography variant="caption">Code</Typography>
                      <input type="color" value={qrColor} onChange={(e) => setQrColor(e.target.value)}
                        style={{ width: 40, height: 40, border: 'none', cursor: 'pointer' }} />
                    </Box>
                    <Box>
                      <Typography variant="caption">BG</Typography>
                      <input type="color" value={bgColor} onChange={(e) => setBgColor(e.target.value)}
                        style={{ width: 40, height: 40, border: 'none', cursor: 'pointer' }} />
                    </Box>
                  </Box>
                </Grid>
              </Grid>
              <Button fullWidth variant="contained" onClick={handleGenerateQR} disabled={!qrData.trim()}
                startIcon={<QrCodeIcon />}
                sx={{ py: 1.5, background: 'linear-gradient(135deg, #90caf9, #42a5f5)' }}>
                Generate QR Code
              </Button>
            </Paper>
          </Grid>
          <Grid size={{ xs: 12, md: 5 }}>
            <Paper sx={{ p: 3, textAlign: 'center' }}>
              <Typography variant="h6" gutterBottom>Preview</Typography>
              {qrData ? (
                <Box>
                  <QRCodeSVG id="qr-code-canvas" value={qrData} size={qrSize} bgColor={bgColor} fgColor={qrColor} level="H" includeMargin />
                  <Box sx={{ display: 'flex', gap: 1, mt: 2, justifyContent: 'center' }}>
                    <Button size="small" variant="outlined" startIcon={<DownloadIcon />} onClick={handleDownloadQR}>Download</Button>
                    <Button size="small" variant="outlined" startIcon={<CopyIcon />} onClick={() => handleCopyContent(qrData)}>Copy</Button>
                    <Button size="small" variant="outlined" startIcon={<ShareIcon />} onClick={() => handleShare(qrData)}>Share</Button>
                  </Box>
                </Box>
              ) : (
                <Box sx={{ py: 8, color: 'text.secondary' }}>
                  <QrCodeIcon sx={{ fontSize: 64, opacity: 0.3 }} />
                  <Typography variant="body2">Enter data to preview</Typography>
                </Box>
              )}
            </Paper>
          </Grid>
        </Grid>
      )}

      {tabValue === 1 && (
        <Grid container spacing={3}>
          <Grid size={{ xs: 12, md: 6 }}>
            <Paper sx={{ p: 3, textAlign: 'center' }}>
              <Typography variant="h6" gutterBottom>Scan QR Code</Typography>

              <Box sx={{ border: '2px dashed rgba(255,255,255,0.2)', borderRadius: 2, p: 4, mb: 3, cursor: 'pointer',
                '&:hover': { borderColor: 'primary.main', bgcolor: 'rgba(144,202,249,0.05)' } }}
                onClick={() => fileInputRef.current?.click()}>
                <input type="file" ref={fileInputRef} accept="image/*" onChange={handleFileUpload} style={{ display: 'none' }} />
                {uploadedImage ? (
                  <Box>
                    <img src={uploadedImage} alt="Uploaded" style={{ maxWidth: '100%', maxHeight: 200 }} />
                    <Typography variant="body2" sx={{ mt: 1 }}>Click to upload another</Typography>
                  </Box>
                ) : (
                  <Box>
                    <UploadIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 1 }} />
                    <Typography>Upload QR Image</Typography>
                  </Box>
                )}
              </Box>

              <Divider sx={{ my: 2 }}>OR</Divider>

              <Button fullWidth variant="contained" startIcon={<CameraIcon />}
                onClick={openCamera}
                disabled={isScanning}
                sx={{ py: 1.5, background: 'linear-gradient(135deg, #4caf50, #2e7d32)' }}>
                📷 Open Camera to Scan
              </Button>
            </Paper>
          </Grid>

          <Grid size={{ xs: 12, md: 6 }}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>Scan Result</Typography>
              {selectedResult ? (
                <Box>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2, flexWrap: 'wrap' }}>
                    {selectedResult.isPaymentQR ? (
                      <Chip label="💰 UPI Payment QR" color="primary" icon={<PaymentIcon />} />
                    ) : (
                      <Chip
                        label={selectedResult.status === 'safe' ? '✅ Verified Safe' : '⚠️ Suspicious'}
                        color={selectedResult.status === 'safe' ? 'success' : 'error'} />
                    )}
                    {selectedResult.isPaymentQR && <Chip label="🟢 100% Safe" color="success" />}
                    {!selectedResult.isPaymentQR && (
                      <Chip label={`Suspicion: ${selectedResult.suspicionScore.toFixed(0)}%`}
                        variant="outlined" color={getRiskColor(selectedResult.suspicionScore)} />
                    )}
                    <Chip label={selectedResult.qrType} size="small" variant="outlined"
                      icon={getQRTypeIcon(selectedResult.qrType)} />
                  </Box>

                  {selectedResult.upiId && (
                    <Box sx={{ mb: 2, p: 2, bgcolor: 'rgba(76,175,80,0.1)', borderRadius: 2, border: '1px solid #4caf50' }}>
                      <Typography variant="body2" color="success.main" sx={{ fontWeight: 600 }}>👤 UPI ID:</Typography>
                      <Typography variant="h6" sx={{ fontFamily: 'monospace', color: '#4caf50' }}>
                        {selectedResult.upiId}
                      </Typography>
                    </Box>
                  )}

                  {selectedResult.isPaymentQR && (
                    <Alert severity="warning" sx={{ mb: 2 }}>
                      <Typography variant="body2" sx={{ fontWeight: 600 }}>⚠️ Payment QR Code</Typography>
                      <Typography variant="body2">
                        Only pay people you trust. Verify the UPI ID above.
                      </Typography>
                    </Alert>
                  )}

                  <Typography variant="body2" color="textSecondary">Decoded Content:</Typography>
                  <Typography variant="body1" sx={{ mb: 2, wordBreak: 'break-all', bgcolor: 'rgba(0,0,0,0.2)',
                    p: 1, borderRadius: 1, fontFamily: 'monospace' }}>
                    {selectedResult.content}
                  </Typography>

                  <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                    <Button size="small" variant="outlined" startIcon={<DownloadIcon />} onClick={handleDownloadQR}>Download</Button>
                    <Button size="small" variant="outlined" startIcon={<CopyIcon />} onClick={() => handleCopyContent(selectedResult.content)}>Copy</Button>
                    <Button size="small" variant="outlined" startIcon={<ShareIcon />} onClick={() => handleShare(selectedResult.content)}>Share</Button>
                  </Box>
                </Box>
              ) : (
                <Box sx={{ py: 6, textAlign: 'center', color: 'text.secondary' }}>
                  <ScanIcon sx={{ fontSize: 64, opacity: 0.3 }} />
                  <Typography>Scan or upload to see results</Typography>
                </Box>
              )}
            </Paper>
          </Grid>
        </Grid>
      )}

      {tabValue === 2 && (
        <Paper sx={{ p: 3 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
            <Typography variant="h6">Recent Activity</Typography>
            <Button size="small" variant="outlined" startIcon={<DeleteIcon />} onClick={() => setHistory([])}>Clear All</Button>
          </Box>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>#</TableCell>
                  <TableCell>Type</TableCell>
                  <TableCell>QR Type</TableCell>
                  <TableCell>Content</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Time</TableCell>
                  <TableCell>Action</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {history.length === 0 ? (
                  <TableRow><TableCell colSpan={7} align="center" sx={{ py: 4 }}>
                    <Typography color="textSecondary">No history yet</Typography>
                  </TableCell></TableRow>
                ) : history.map((item, index) => (
                  <TableRow key={item.id} hover>
                    <TableCell>{index + 1}</TableCell>
                    <TableCell>
                      <Chip size="small" label={item.type}
                        icon={item.type === 'generated' ? <QrCodeIcon /> : <ScanIcon />}
                        color={item.type === 'generated' ? 'primary' : 'info'} />
                    </TableCell>
                    <TableCell>
                      <Chip size="small" label={item.metadata?.qrType || 'Unknown'} variant="outlined" />
                    </TableCell>
                    <TableCell>
                      <Tooltip title={item.content}>
                        <Typography variant="body2" noWrap sx={{ maxWidth: 200 }}>{item.content}</Typography>
                      </Tooltip>
                    </TableCell>
                    <TableCell>
                      <Chip size="small" label={item.status}
                        color={item.status === 'safe' ? 'success' : item.status === 'malicious' ? 'error' : 'default'} />
                    </TableCell>
                    <TableCell>{item.timestamp.toLocaleString()}</TableCell>
                    <TableCell>
                      <IconButton size="small" onClick={() => handleCopyContent(item.content)}><CopyIcon fontSize="small" /></IconButton>
                      <IconButton size="small" onClick={() => handleDeleteHistory(item.id)}><DeleteIcon fontSize="small" /></IconButton>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      )}

      {/* ============ CAMERA DIALOG ============ */}
      <Dialog open={cameraOpen} onClose={closeCamera} maxWidth="md" fullWidth>
        <DialogTitle sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography variant="h6">📷 Scan QR Code with Camera</Typography>
          <IconButton onClick={closeCamera}><CloseIcon /></IconButton>
        </DialogTitle>
        <DialogContent>
          <Box sx={{ position: 'relative', textAlign: 'center' }}>
            {cameraError ? (
              <Alert severity="error" sx={{ mb: 2 }}>
                {cameraError}
              </Alert>
            ) : (
              <>
                <Webcam
                  ref={webcamRef}
                  audio={false}
                  screenshotFormat="image/png"
                  videoConstraints={{ facingMode: 'environment' }}
                  onUserMediaError={(err) => {
                    console.error('Camera error:', err);
                    setCameraError('Cannot access camera. Please allow camera permissions.');
                  }}
                  style={{ width: '100%', maxWidth: 600, borderRadius: 8 }}
                />
                <Box sx={{ mt: 2, position: 'relative' }}>
                  {scanning && (
                    <>
                      <LinearProgress sx={{ mb: 1 }} />
                      <Typography color="primary">🔍 Scanning for QR code...</Typography>
                    </>
                  )}
                  <Typography variant="caption" color="textSecondary">
                    Position the QR code within the camera view
                  </Typography>
                </Box>
              </>
            )}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={closeCamera}>Cancel</Button>
        </DialogActions>
      </Dialog>

      <Snackbar open={snackbarOpen} autoHideDuration={4000} onClose={() => setSnackbarOpen(false)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}>
        <Alert severity={snackbarSeverity} onClose={() => setSnackbarOpen(false)}>
          {snackbarMessage}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default QRModule;