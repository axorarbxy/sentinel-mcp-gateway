// pages/modules/QRModule.tsx
import React, { useState, useRef } from 'react';
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
} from '@mui/icons-material';
import { QRCodeSVG } from 'qrcode.react';

// Types
interface QRHistoryItem {
  id: number;
  type: 'generated' | 'scanned';
  content: string;
  status: 'safe' | 'malicious' | 'unknown';
  timestamp: Date;
  metadata: {
    size?: string;
    color?: string;
    format?: string;
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

// Helper function to detect QR type from content
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
  if (content.startsWith('http://') || content.startsWith('https://')) return 'URL';
  return 'Other';
};

// Helper to extract UPI ID from UPI URL
const extractUPIId = (content: string): string => {
  if (!content) return '';
  if (content.includes('upi://')) {
    const match = content.match(/pa=([^&]*)/);
    if (match) return decodeURIComponent(match[1]);
  }
  return '';
};

const QRModule: React.FC = () => {
  // State
  const [tabValue, setTabValue] = useState(0);
  const [qrData, setQrData] = useState('');
  const [qrSize, setQrSize] = useState(256);
  const [qrColor, setQrColor] = useState('#000000');
  const [bgColor, setBgColor] = useState('#ffffff');
  const [history, setHistory] = useState<QRHistoryItem[]>([
    {
      id: 1,
      type: 'generated',
      content: 'https://pay.google.com/gp/p/ui/pay?sid=GP123456789&am=500.00',
      status: 'safe',
      timestamp: new Date(Date.now() - 3600000),
      metadata: { size: '300x300', color: '#000000', qrType: 'Payment' },
    },
    {
      id: 2,
      type: 'scanned',
      content: 'WIFI:T:WPA;S:Cafe_WiFi;P:CoffeeShop2024;;',
      status: 'safe',
      timestamp: new Date(Date.now() - 7200000),
      metadata: { scanMethod: 'camera', qrType: 'WiFi' },
    },
    {
      id: 3,
      type: 'scanned',
      content: 'https://www.zomato.com/restaurant/order?table=42',
      status: 'safe',
      timestamp: new Date(Date.now() - 86400000),
      metadata: { scanMethod: 'upload', qrType: 'Restaurant' },
    },
    {
      id: 4,
      type: 'scanned',
      content: 'https://secure-login.xyz/verify?token=xyz123',
      status: 'malicious',
      timestamp: new Date(Date.now() - 172800000),
      metadata: { scanMethod: 'upload', qrType: 'Phishing' },
    },
  ]);
  const [selectedResult, setSelectedResult] = useState<ScanResult | null>(null);
  const [uploadedImage, setUploadedImage] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [snackbarOpen, setSnackbarOpen] = useState(false);
  const [snackbarMessage, setSnackbarMessage] = useState('');
  const [snackbarSeverity, setSnackbarSeverity] = useState<'success' | 'error' | 'info' | 'warning'>('info');
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Stats
  const totalGenerated = history.filter(h => h.type === 'generated').length;
  const totalScanned = history.filter(h => h.type === 'scanned').length;
  const totalMalicious = history.filter(h => h.status === 'malicious').length;
  const scanSuccessRate = totalScanned > 0 ? ((totalScanned - totalMalicious) / totalScanned * 100) : 100;

  const handleGenerateQR = () => {
    if (!qrData.trim()) {
      setSnackbarMessage('Please enter text or URL to generate QR code');
      setSnackbarSeverity('warning');
      setSnackbarOpen(true);
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
    setSnackbarMessage('QR Code generated successfully!');
    setSnackbarSeverity('success');
    setSnackbarOpen(true);
  };

  const handleScanQR = async (file?: File) => {
    if (!file && !uploadedImage) {
      setSnackbarMessage('Please upload an image first');
      setSnackbarSeverity('warning');
      setSnackbarOpen(true);
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

      // Clean the base64 string
      let cleanBase64 = imageBase64;
      if (cleanBase64.includes(',')) {
        cleanBase64 = cleanBase64.split(',')[1];
      }

      console.log('📤 Sending image for scanning...');

      // Call the ML scanner API
      const response = await fetch('http://localhost:8001/ml/scan/qr', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          image: imageBase64,
          scan_type: 'base64'
        }),
      });

      console.log('📥 Response status:', response.status);

      if (response.ok) {
        const result = await response.json();
        console.log('🔍 API Response:', result);
        
        // Check if QR code was found
        if (!result.decoded_content || result.decoded_content === 'No QR code found in image') {
          console.log('❌ No QR code found in image');
          setSnackbarMessage('❌ No QR code found in the image. Please upload a valid QR code.');
          setSnackbarSeverity('warning');
          setSnackbarOpen(true);
          
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

        console.log('✅ QR Code Content:', result.decoded_content);

        // Check if it's a UPI/GPay QR code
        const isUPI = result.decoded_content.includes('upi://') || 
                      result.decoded_content.includes('pay.google.com') ||
                      result.decoded_content.includes('gpay') ||
                      result.decoded_content.includes('UPI');

        const isPaymentQR = result.decoded_content.includes('upi://') ||
                            result.decoded_content.includes('pay.google.com') ||
                            result.decoded_content.includes('gpay') ||
                            (result.decoded_content.includes('pay') && result.decoded_content.includes('?'));

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
          isPaymentQR: isPaymentQR
        };

        setSelectedResult(scanResult);

        const newEntry: QRHistoryItem = {
          id: Date.now(),
          type: 'scanned',
          content: result.decoded_content,
          status: isUPI ? 'safe' : (result.is_malicious ? 'malicious' : 'safe'),
          timestamp: new Date(),
          metadata: { 
            scanMethod: file ? 'upload' : 'camera',
            qrType: scanResult.qrType
          },
        };
        setHistory([newEntry, ...history]);

        setSnackbarMessage(
          isUPI 
            ? '✅ UPI Payment QR code verified safely' 
            : (result.is_malicious 
              ? '⚠️ Suspicious QR code detected' 
              : '✅ QR code scanned successfully')
        );
        setSnackbarSeverity(isUPI ? 'success' : (result.is_malicious ? 'error' : 'success'));
        setSnackbarOpen(true);

      } else {
        const error = await response.json();
        console.error('❌ API Error:', error);
        setSnackbarMessage(`Scan failed: ${error.detail || 'Unknown error'}`);
        setSnackbarSeverity('error');
        setSnackbarOpen(true);
      }
    } catch (error) {
      console.error('❌ Scan error:', error);
      setSnackbarMessage('Network error. Make sure the ML scanner is running.');
      setSnackbarSeverity('error');
      setSnackbarOpen(true);
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
    // Case 1: Generate tab - download QR code image
    if (tabValue === 0 && qrData) {
      const canvas = document.getElementById('qr-code-canvas') as HTMLCanvasElement;
      if (canvas) {
        try {
          const link = document.createElement('a');
          link.download = `qr-code-${Date.now()}.png`;
          link.href = canvas.toDataURL('image/png');
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
          setSnackbarMessage('✅ QR Code downloaded successfully!');
          setSnackbarSeverity('success');
          setSnackbarOpen(true);
        } catch (error) {
          setSnackbarMessage('❌ Failed to download QR code');
          setSnackbarSeverity('error');
          setSnackbarOpen(true);
        }
      } else {
        setSnackbarMessage('⚠️ No QR code to download. Generate one first.');
        setSnackbarSeverity('warning');
        setSnackbarOpen(true);
      }
      return;
    }

    // Case 2: Scan tab - download decoded content as text file
    if (tabValue === 1 && selectedResult && selectedResult.qrType !== 'No QR Code') {
      try {
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
        setSnackbarMessage('✅ QR content downloaded as text file!');
        setSnackbarSeverity('success');
        setSnackbarOpen(true);
      } catch (error) {
        setSnackbarMessage('❌ Failed to download content');
        setSnackbarSeverity('error');
        setSnackbarOpen(true);
      }
      return;
    }

    // Case 3: No content available
    setSnackbarMessage('⚠️ No content to download. Scan or generate a QR code first.');
    setSnackbarSeverity('warning');
    setSnackbarOpen(true);
  };

  const handleCopyContent = (content: string) => {
    navigator.clipboard.writeText(content);
    setSnackbarMessage('Content copied to clipboard!');
    setSnackbarSeverity('success');
    setSnackbarOpen(true);
  };

  const handleDeleteHistory = (id: number) => {
    setHistory(history.filter(h => h.id !== id));
    setSnackbarMessage('History entry deleted');
    setSnackbarSeverity('info');
    setSnackbarOpen(true);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'safe': return 'success';
      case 'malicious': return 'error';
      default: return 'default';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'safe': return <CheckCircleIcon fontSize="small" />;
      case 'malicious': return <ErrorIcon fontSize="small" />;
      default: return undefined;
    }
  };

  const getRiskColor = (score: number) => {
    if (score > 70) return 'error';
    if (score > 40) return 'warning';
    return 'success';
  };

  const getRiskLabel = (score: number) => {
    if (score > 70) return 'High Suspicion';
    if (score > 40) return 'Medium Suspicion';
    return 'Low Suspicion';
  };

  const getQRTypeIcon = (type: string) => {
    switch (type) {
      case 'UPI Payment': return <PaymentIcon />;
      case 'Payment': return <PaymentIcon />;
      case 'Restaurant': return <RestaurantIcon />;
      case 'Shopping': return <ShoppingCartIcon />;
      case 'WiFi': return <WifiIcon />;
      case 'Meeting': return <VideoIcon />;
      case 'Location': return <LocationIcon />;
      case 'Event': return <EventIcon />;
      case 'Hotel Booking': return <HotelIcon />;
      case 'File Share': return <FolderIcon />;
      case 'Email': return <EmailIcon />;
      default: return <QrCodeIcon />;
    }
  };

  return (
    <Box sx={{ p: 3, maxWidth: 1400, mx: 'auto' }}>
      {/* Header */}
      <Paper sx={{ p: 3, mb: 3, bgcolor: 'rgba(26,35,50,0.8)' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Avatar sx={{ bgcolor: 'primary.main', width: 56, height: 56 }}>
              <QrCodeIcon sx={{ fontSize: 32 }} />
            </Avatar>
            <Box>
              <Typography variant="h4" sx={{ fontWeight: 600 }}>
                QR Module
              </Typography>
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

      {/* Stats Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid size={{ xs: 6, sm: 3 }}>
          <Card sx={{ bgcolor: 'rgba(26,35,50,0.8)', border: '1px solid rgba(255,255,255,0.05)' }}>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="caption" color="textSecondary">QR Codes Generated</Typography>
              <Typography variant="h4" sx={{ fontWeight: 700 }}>{totalGenerated}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <Card sx={{ bgcolor: 'rgba(26,35,50,0.8)', border: '1px solid rgba(255,255,255,0.05)' }}>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="caption" color="textSecondary">QR Codes Scanned</Typography>
              <Typography variant="h4" sx={{ fontWeight: 700 }}>{totalScanned}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <Card sx={{ bgcolor: 'rgba(26,35,50,0.8)', border: '1px solid rgba(255,255,255,0.05)' }}>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="caption" color="textSecondary">Malicious Detected</Typography>
              <Typography variant="h4" sx={{ fontWeight: 700, color: 'error.main' }}>{totalMalicious}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <Card sx={{ bgcolor: 'rgba(26,35,50,0.8)', border: '1px solid rgba(255,255,255,0.05)' }}>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="caption" color="textSecondary">Scan Success Rate</Typography>
              <Typography variant="h4" sx={{ fontWeight: 700, color: scanSuccessRate > 90 ? 'success.main' : 'warning.main' }}>
                {scanSuccessRate.toFixed(0)}%
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs value={tabValue} onChange={(e, v) => setTabValue(v)}>
          <Tab icon={<AddIcon />} label="Generate" />
          <Tab icon={<ScanIcon />} label="Scan" />
          <Tab icon={<HistoryIcon />} label="History" />
        </Tabs>
      </Paper>

      {/* Tab 1: Generate QR Code */}
      {tabValue === 0 && (
        <Grid container spacing={3}>
          <Grid size={{ xs: 12, md: 7 }}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>Generate QR Code</Typography>
              <Typography variant="body2" color="textSecondary" sx={{ mb: 3 }}>
                Enter text, URL, or any data to generate a QR code
              </Typography>

              <TextField
                fullWidth
                multiline
                rows={3}
                placeholder="Enter text, URL, or data here..."
                value={qrData}
                onChange={(e) => setQrData(e.target.value)}
                variant="outlined"
                sx={{ mb: 2 }}
                slotProps={{
                  htmlInput: { maxLength: 1000 }
                }}
              />
              <Typography variant="caption" color="textSecondary" sx={{ display: 'block', textAlign: 'right', mb: 2 }}>
                {qrData.length}/1000
              </Typography>

              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid size={{ xs: 6 }}>
                  <Typography variant="caption" color="textSecondary">Size</Typography>
                  <Typography variant="body2">{qrSize} x {qrSize}</Typography>
                  <Slider
                    value={qrSize}
                    onChange={(e, v) => setQrSize(v as number)}
                    min={100}
                    max={500}
                    step={50}
                    valueLabelDisplay="auto"
                  />
                </Grid>
                <Grid size={{ xs: 6 }}>
                  <Typography variant="caption" color="textSecondary">Color</Typography>
                  <Box sx={{ display: 'flex', gap: 2, mt: 1 }}>
                    <Box>
                      <Typography variant="caption">Code</Typography>
                      <input
                        type="color"
                        value={qrColor}
                        onChange={(e) => setQrColor(e.target.value)}
                        style={{ width: 40, height: 40, border: 'none', cursor: 'pointer', background: 'transparent' }}
                      />
                    </Box>
                    <Box>
                      <Typography variant="caption">Background</Typography>
                      <input
                        type="color"
                        value={bgColor}
                        onChange={(e) => setBgColor(e.target.value)}
                        style={{ width: 40, height: 40, border: 'none', cursor: 'pointer', background: 'transparent' }}
                      />
                    </Box>
                  </Box>
                </Grid>
              </Grid>

              <Button
                fullWidth
                variant="contained"
                onClick={handleGenerateQR}
                disabled={!qrData.trim()}
                startIcon={<QrCodeIcon />}
                sx={{
                  py: 1.5,
                  borderRadius: 2,
                  background: 'linear-gradient(135deg, #90caf9, #42a5f5)',
                  '&:hover': { background: 'linear-gradient(135deg, #42a5f5, #1e88e5)' },
                }}
              >
                Generate QR Code
              </Button>
            </Paper>
          </Grid>

          <Grid size={{ xs: 12, md: 5 }}>
            <Paper sx={{ p: 3, textAlign: 'center' }}>
              <Typography variant="h6" gutterBottom>QR Code Preview</Typography>
              {qrData ? (
                <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                  <QRCodeSVG
                    id="qr-code-canvas"
                    value={qrData}
                    size={qrSize}
                    bgColor={bgColor}
                    fgColor={qrColor}
                    level="H"
                    includeMargin
                  />
                  <Box sx={{ display: 'flex', gap: 1, mt: 2, flexWrap: 'wrap', justifyContent: 'center' }}>
                    <Button 
                      variant="outlined" 
                      size="small" 
                      startIcon={<DownloadIcon />} 
                      onClick={handleDownloadQR}
                    >
                      Download
                    </Button>
                    <Button variant="outlined" size="small" startIcon={<CopyIcon />} onClick={() => handleCopyContent(qrData)}>
                      Copy Data
                    </Button>
                    <Button variant="outlined" size="small" startIcon={<ShareIcon />}>
                      Share
                    </Button>
                  </Box>
                </Box>
              ) : (
                <Box sx={{ py: 8, color: 'text.secondary' }}>
                  <QrCodeIcon sx={{ fontSize: 64, opacity: 0.3 }} />
                  <Typography variant="body2">Enter data to generate QR code</Typography>
                </Box>
              )}
            </Paper>
          </Grid>
        </Grid>
      )}

      {/* Tab 2: Scan QR Code */}
      {tabValue === 1 && (
        <Grid container spacing={3}>
          <Grid size={{ xs: 12, md: 6 }}>
            <Paper sx={{ p: 3, textAlign: 'center' }}>
              <Typography variant="h6" gutterBottom>Scan QR Code</Typography>
              <Typography variant="body2" color="textSecondary" sx={{ mb: 3 }}>
                Upload an image or use your camera to scan a QR code
              </Typography>

              {/* Upload Area */}
              <Box
                sx={{
                  border: '2px dashed rgba(255,255,255,0.2)',
                  borderRadius: 2,
                  p: 4,
                  mb: 3,
                  cursor: 'pointer',
                  '&:hover': { borderColor: 'primary.main', bgcolor: 'rgba(144,202,249,0.05)' },
                }}
                onClick={() => fileInputRef.current?.click()}
              >
                <input
                  type="file"
                  ref={fileInputRef}
                  accept="image/*"
                  onChange={handleFileUpload}
                  style={{ display: 'none' }}
                />
                {uploadedImage ? (
                  <Box>
                    <img src={uploadedImage} alt="Uploaded QR" style={{ maxWidth: '100%', maxHeight: 200 }} />
                    <Typography variant="body2" sx={{ mt: 1 }}>Click to upload another</Typography>
                  </Box>
                ) : (
                  <Box>
                    <UploadIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 1 }} />
                    <Typography variant="body1">Drag and drop an image here or click to browse</Typography>
                    <Typography variant="caption" color="textSecondary">
                      Supports: PNG, JPG, JPEG (Max 5MB)
                    </Typography>
                  </Box>
                )}
              </Box>

              <Divider sx={{ my: 2 }}>OR</Divider>

              <Button
                fullWidth
                variant="outlined"
                startIcon={<CameraIcon />}
                onClick={() => handleScanQR()}
                disabled={isScanning}
                sx={{ py: 1.5, borderRadius: 2 }}
              >
                {isScanning ? 'Scanning...' : 'Use Camera'}
              </Button>

              {isScanning && <LinearProgress sx={{ mt: 2 }} />}
            </Paper>
          </Grid>

          <Grid size={{ xs: 12, md: 6 }}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>Scan Result</Typography>
              {selectedResult ? (
                <Box>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2, flexWrap: 'wrap' }}>
                    {selectedResult.qrType === 'No QR Code' ? (
                      <Chip
                        label="❌ No QR Code Found"
                        color="warning"
                        icon={<ErrorIcon />}
                      />
                    ) : selectedResult.isPaymentQR ? (
                      <Chip
                        label="💰 UPI Payment QR Code"
                        color="primary"
                        icon={<PaymentIcon />}
                      />
                    ) : (
                      <Chip
                        label={selectedResult.status === 'safe' ? '✅ Verified Safe' : '⚠️ Potentially Suspicious'}
                        color={selectedResult.status === 'safe' ? 'success' : 'error'}
                        icon={selectedResult.status === 'safe' ? <CheckCircleIcon /> : <ErrorIcon />}
                      />
                    )}
                    {selectedResult.qrType !== 'No QR Code' && selectedResult.isPaymentQR && (
                      <Chip 
                        label="🟢 100% Safe" 
                        color="success"
                      />
                    )}
                    {selectedResult.qrType !== 'No QR Code' && !selectedResult.isPaymentQR && selectedResult.status === 'safe' && (
                      <Chip label={`Suspicion Score: ${selectedResult.suspicionScore.toFixed(0)}%`} variant="outlined" color="success" />
                    )}
                    {selectedResult.qrType !== 'No QR Code' && selectedResult.status === 'malicious' && (
                      <Chip label={`Suspicion Score: ${selectedResult.suspicionScore.toFixed(0)}%`} variant="outlined" color="error" />
                    )}
                    {selectedResult.qrType !== 'No QR Code' && (
                      <>
                        <Chip label={`Confidence: ${(selectedResult.confidence * 100).toFixed(0)}%`} variant="outlined" />
                        <Chip 
                          label={selectedResult.qrType} 
                          size="small"
                          variant="outlined"
                          icon={getQRTypeIcon(selectedResult.qrType)}
                        />
                      </>
                    )}
                  </Box>

                  {/* UPI ID Display */}
                  {selectedResult.upiId && (
                    <Box sx={{ mb: 2, p: 2, bgcolor: 'rgba(76,175,80,0.1)', borderRadius: 2, border: '1px solid #4caf50' }}>
                      <Typography variant="body2" color="success.main" sx={{ fontWeight: 600 }}>
                        👤 UPI ID:
                      </Typography>
                      <Typography variant="h6" sx={{ fontFamily: 'monospace', color: '#4caf50' }}>
                        {selectedResult.upiId}
                      </Typography>
                    </Box>
                  )}

                  {/* Payment Warning */}
                  {selectedResult.isPaymentQR && (
                    <Alert severity="warning" sx={{ mb: 2 }}>
                      <Typography variant="body2" sx={{ fontWeight: 600 }}>
                        ⚠️ Payment QR Code Detected
                      </Typography>
                      <Typography variant="body2">
                        Please verify the UPI ID above and only send money to people you trust.
                        Double-check the amount and recipient before confirming any payment.
                      </Typography>
                    </Alert>
                  )}

                  <Typography variant="body2" color="textSecondary">
                    {selectedResult.qrType === 'No QR Code' ? 'Analysis Result:' : 'Decoded Content:'}
                  </Typography>
                  <Typography 
                    variant="body1" 
                    sx={{ 
                      mb: 2, 
                      wordBreak: 'break-all', 
                      bgcolor: selectedResult.qrType === 'No QR Code' ? 'rgba(255,165,0,0.1)' : 'rgba(0,0,0,0.2)',
                      p: 1, 
                      borderRadius: 1, 
                      fontFamily: selectedResult.qrType === 'No QR Code' ? 'inherit' : 'monospace',
                      color: selectedResult.qrType === 'No QR Code' ? 'warning.main' : 'inherit',
                    }}
                  >
                    {selectedResult.content}
                  </Typography>

                  {selectedResult.indicators.length > 0 && selectedResult.qrType !== 'No QR Code' && !selectedResult.isPaymentQR && (
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="body2" color="textSecondary">Detected Indicators:</Typography>
                      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>
                        {selectedResult.indicators.map((ind, i) => (
                          <Chip key={i} size="small" label={ind} color="warning" />
                        ))}
                      </Box>
                    </Box>
                  )}

                  {selectedResult.qrType !== 'No QR Code' && (
                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                      <Button 
                        variant="outlined" 
                        size="small" 
                        startIcon={<DownloadIcon />}
                        onClick={handleDownloadQR}
                      >
                        Download
                      </Button>
                      <Button variant="outlined" size="small" startIcon={<CopyIcon />} onClick={() => handleCopyContent(selectedResult.content)}>
                        Copy Data
                      </Button>
                      <Button variant="outlined" size="small" startIcon={<ShareIcon />}>
                        Share
                      </Button>
                    </Box>
                  )}
                </Box>
              ) : (
                <Box sx={{ py: 6, textAlign: 'center', color: 'text.secondary' }}>
                  <ScanIcon sx={{ fontSize: 64, opacity: 0.3 }} />
                  <Typography variant="body2">Scan or upload a QR code to see results</Typography>
                </Box>
              )}
            </Paper>
          </Grid>
        </Grid>
      )}

      {/* Tab 3: History */}
      {tabValue === 2 && (
        <Paper sx={{ p: 3 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="h6">Recent Activity</Typography>
            <Button variant="outlined" size="small" startIcon={<DeleteIcon />} onClick={() => setHistory([])}>
              Clear All
            </Button>
          </Box>

          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>#</TableCell>
                  <TableCell>Type</TableCell>
                  <TableCell>QR Type</TableCell>
                  <TableCell>Content Preview</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Date & Time</TableCell>
                  <TableCell>Action</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {history.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} align="center" sx={{ py: 4 }}>
                      <Typography variant="body2" color="textSecondary">No history entries yet</Typography>
                    </TableCell>
                  </TableRow>
                ) : (
                  history.map((item, index) => (
                    <TableRow key={item.id} hover>
                      <TableCell>{index + 1}</TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          label={item.type}
                          icon={item.type === 'generated' ? <QrCodeIcon /> : <ScanIcon />}
                          color={item.type === 'generated' ? 'primary' : 'info'}
                        />
                      </TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          label={item.metadata?.qrType || 'Unknown'}
                          variant="outlined"
                          icon={getQRTypeIcon(item.metadata?.qrType || 'Unknown')}
                        />
                      </TableCell>
                      <TableCell>
                        <Tooltip title={item.content}>
                          <Typography variant="body2" noWrap sx={{ maxWidth: 200 }}>
                            {item.content}
                          </Typography>
                        </Tooltip>
                      </TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          label={item.status === 'safe' ? '✅ Safe' : item.status === 'malicious' ? '⚠️ Suspicious' : '❓ Unknown'}
                          color={item.status === 'safe' ? 'success' : item.status === 'malicious' ? 'error' : 'default'}
                          icon={getStatusIcon(item.status)}
                        />
                      </TableCell>
                      <TableCell>
                        {item.timestamp.toLocaleString()}
                      </TableCell>
                      <TableCell>
                        <IconButton size="small" onClick={() => handleCopyContent(item.content)}>
                          <CopyIcon fontSize="small" />
                        </IconButton>
                        <IconButton size="small" onClick={() => handleDeleteHistory(item.id)}>
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      )}

      {/* Snackbar */}
      <Snackbar
        open={snackbarOpen}
        autoHideDuration={4000}
        onClose={() => setSnackbarOpen(false)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert severity={snackbarSeverity} onClose={() => setSnackbarOpen(false)}>
          {snackbarMessage}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default QRModule;