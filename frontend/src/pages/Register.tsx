// pages/Register.tsx - Production Level Registration
import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Alert,
  Link,
  InputAdornment,
  IconButton,
  Stepper,
  Step,
  StepLabel,
  Checkbox,
  FormControlLabel,
  LinearProgress,
  Divider,
  CircularProgress,
} from '@mui/material';
import {
  Visibility,
  VisibilityOff,
  PersonAdd as PersonAddIcon,
  Check as CheckIcon,
  Close as CloseIcon,
  Google as GoogleIcon,
  GitHub as GitHubIcon,
} from '@mui/icons-material';
import { useNavigate, Link as RouterLink } from 'react-router-dom';

// Password strength checker
const checkPasswordStrength = (password: string) => {
  let score = 0;
  const checks = {
    length: password.length >= 8,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    number: /\d/.test(password),
    special: /[^A-Za-z0-9]/.test(password),
  };
  
  score += checks.length ? 1 : 0;
  score += checks.uppercase ? 1 : 0;
  score += checks.lowercase ? 1 : 0;
  score += checks.number ? 1 : 0;
  score += checks.special ? 1 : 0;
  
  return { score, checks };
};

const Register: React.FC = () => {
  const navigate = useNavigate();
  const [activeStep, setActiveStep] = useState(0);
  const [formData, setFormData] = useState({
    firstName: '',
    lastName: '',
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
  });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [error, setError] = useState('');
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const [acceptedTerms, setAcceptedTerms] = useState(false);
  
  // Password strength
  const [passwordStrength, setPasswordStrength] = useState({ score: 0, checks: {} as any });
  const [passwordFocused, setPasswordFocused] = useState(false);

  // Real-time password validation
  useEffect(() => {
    if (formData.password) {
      setPasswordStrength(checkPasswordStrength(formData.password));
    } else {
      setPasswordStrength({ score: 0, checks: {} });
    }
  }, [formData.password]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
    if (fieldErrors[name]) {
      setFieldErrors({ ...fieldErrors, [name]: '' });
    }
  };

  const validateField = (name: string, value: string): string => {
    switch (name) {
      case 'firstName':
        return value.trim().length < 2 ? 'First name must be at least 2 characters' : '';
      case 'lastName':
        return value.trim().length < 2 ? 'Last name must be at least 2 characters' : '';
      case 'username':
        if (!/^[a-zA-Z0-9_]{3,20}$/.test(value)) {
          return 'Username must be 3-20 characters (letters, numbers, underscores only)';
        }
        return '';
      case 'email':
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
          return 'Please enter a valid email address';
        }
        return '';
      case 'password':
        const strength = checkPasswordStrength(value);
        if (strength.score < 3) {
          return 'Password must meet all requirements below';
        }
        return '';
      case 'confirmPassword':
        return value !== formData.password ? 'Passwords do not match' : '';
      default:
        return '';
    }
  };

  const handleBlur = (e: React.FocusEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    const error = validateField(name, value);
    if (error) {
      setFieldErrors({ ...fieldErrors, [name]: error });
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    const errors: Record<string, string> = {};
    Object.entries(formData).forEach(([key, value]) => {
      const error = validateField(key, value);
      if (error) errors[key] = error;
    });
    
    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      setError('Please fix all errors before continuing');
      return;
    }
    
    if (!acceptedTerms) {
      setError('You must agree to the Terms of Service and Privacy Policy');
      return;
    }
    
    setError('');
    setLoading(true);
    setActiveStep(1);

    try {
      const response = await fetch('http://localhost:8001/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: formData.username,
          email: formData.email,
          password: formData.password,
          full_name: `${formData.firstName} ${formData.lastName}`.trim(),
        }),
      });

      const data = await response.json();

      if (response.ok) {
        setSuccess('Account created successfully!');
        setActiveStep(2);
        // Auto redirect to login after 2 seconds
        setTimeout(() => {
          navigate('/login');
        }, 2000);
      } else {
        if (data.detail?.includes('username')) {
          setFieldErrors({ ...fieldErrors, username: 'Username already taken' });
          setError('Username is already registered');
        } else if (data.detail?.includes('email')) {
          setFieldErrors({ ...fieldErrors, email: 'Email already registered' });
          setError('Email is already registered. Log in instead?');
        } else {
          setError(data.detail || 'Registration failed. Please try again.');
        }
        setActiveStep(0);
      }
    } catch (err) {
      setError('Network error. Please check your connection and try again.');
      setActiveStep(0);
    } finally {
      setLoading(false);
    }
  };

  const getPasswordStrengthLabel = (score: number) => {
    if (score <= 1) return { label: 'Weak', color: 'error' };
    if (score <= 2) return { label: 'Fair', color: 'warning' };
    if (score <= 3) return { label: 'Good', color: 'info' };
    if (score <= 4) return { label: 'Strong', color: 'success' };
    return { label: 'Very Strong', color: 'success' };
  };

  return (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'linear-gradient(135deg, #0a1929 0%, #1a2332 100%)',
        p: { xs: 2, sm: 3 },
      }}
    >
      <Paper
        elevation={24}
        sx={{
          maxWidth: 520,
          width: '100%',
          p: { xs: 3, sm: 4 },
          borderRadius: 3,
          background: 'rgba(26, 35, 50, 0.95)',
          backdropFilter: 'blur(10px)',
          border: '1px solid rgba(255,255,255,0.05)',
          maxHeight: '90vh',
          overflowY: 'auto',
        }}
      >
        <Stepper activeStep={activeStep} sx={{ mb: 4 }}>
          <Step>
            <StepLabel>Details</StepLabel>
          </Step>
          <Step>
            <StepLabel>Verify</StepLabel>
          </Step>
          <Step>
            <StepLabel>Done</StepLabel>
          </Step>
        </Stepper>

        {error && (
          <Alert 
            severity="error" 
            sx={{ mb: 3 }}
            action={
              error.includes('already registered') ? (
                <Button color="inherit" size="small" onClick={() => navigate('/login')}>
                  Log in
                </Button>
              ) : undefined
            }
          >
            {error}
          </Alert>
        )}

        {success && (
          <Alert severity="success" sx={{ mb: 3 }} icon={<CheckIcon />}>
            {success}
          </Alert>
        )}

        {activeStep === 0 && (
          <>
            <Box sx={{ textAlign: 'center', mb: 4 }}>
              <Typography variant="h3" component="h1" sx={{ mb: 1 }}>
                🛡️
              </Typography>
              <Typography variant="h5" component="h1" sx={{ fontWeight: 600 }}>
                Create an Account
              </Typography>
              <Typography variant="body2" color="textSecondary">
                Join Sentinel-MCP Security Platform
              </Typography>
            </Box>

            <Box sx={{ mb: 3 }}>
              <Button
                fullWidth
                variant="outlined"
                startIcon={<GoogleIcon />}
                sx={{ mb: 1.5, py: 1.5, borderRadius: 2 }}
              >
                Continue with Google
              </Button>
              <Button
                fullWidth
                variant="outlined"
                startIcon={<GitHubIcon />}
                sx={{ py: 1.5, borderRadius: 2 }}
              >
                Continue with GitHub
              </Button>
              <Divider sx={{ my: 3 }}>
                <Typography variant="body2" color="textSecondary">
                  OR
                </Typography>
              </Divider>
            </Box>

            <form onSubmit={handleSubmit} noValidate>
              <Box sx={{ display: 'flex', gap: 2 }}>
                <TextField
                  fullWidth
                  label="First Name"
                  name="firstName"
                  value={formData.firstName}
                  onChange={handleChange}
                  onBlur={handleBlur}
                  margin="normal"
                  required
                  autoFocus
                  error={!!fieldErrors.firstName}
                  helperText={fieldErrors.firstName}
                  autoComplete="given-name"
                />
                <TextField
                  fullWidth
                  label="Last Name"
                  name="lastName"
                  value={formData.lastName}
                  onChange={handleChange}
                  onBlur={handleBlur}
                  margin="normal"
                  required
                  error={!!fieldErrors.lastName}
                  helperText={fieldErrors.lastName}
                  autoComplete="family-name"
                />
              </Box>

              <TextField
                fullWidth
                label="Username"
                name="username"
                value={formData.username}
                onChange={handleChange}
                onBlur={handleBlur}
                margin="normal"
                required
                error={!!fieldErrors.username}
                helperText={fieldErrors.username || '3-20 characters, letters/numbers/underscores only'}
                autoComplete="username"
              />

              <TextField
                fullWidth
                label="Email Address"
                name="email"
                type="email"
                value={formData.email}
                onChange={handleChange}
                onBlur={handleBlur}
                margin="normal"
                required
                error={!!fieldErrors.email}
                helperText={fieldErrors.email}
                autoComplete="email"
              />

              <TextField
                fullWidth
                label="Password"
                name="password"
                type={showPassword ? 'text' : 'password'}
                value={formData.password}
                onChange={handleChange}
                onBlur={handleBlur}
                onFocus={() => setPasswordFocused(true)}
                margin="normal"
                required
                error={!!fieldErrors.password}
                helperText={fieldErrors.password}
                autoComplete="new-password"
                slotProps={{
                  input: {
                    endAdornment: (
                      <InputAdornment position="end">
                        <IconButton
                          onClick={() => setShowPassword(!showPassword)}
                          edge="end"
                          aria-label="toggle password visibility"
                        >
                          {showPassword ? <VisibilityOff /> : <Visibility />}
                        </IconButton>
                      </InputAdornment>
                    ),
                  },
                }}
              />

              {formData.password && (passwordFocused || formData.password.length > 0) && (
                <Box sx={{ mt: 1, p: 2, bgcolor: 'rgba(0,0,0,0.2)', borderRadius: 2 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
                    <Typography variant="caption" sx={{ fontWeight: 600 }}>
                      Password Strength:
                    </Typography>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <LinearProgress
                        variant="determinate"
                        value={(passwordStrength.score / 5) * 100}
                        sx={{ width: 100, height: 6, borderRadius: 3 }}
                        color={
                          passwordStrength.score <= 1 ? 'error' :
                          passwordStrength.score <= 2 ? 'warning' :
                          passwordStrength.score <= 3 ? 'info' :
                          'success'
                        }
                      />
                      <Typography
                        variant="caption"
                        color={getPasswordStrengthLabel(passwordStrength.score).color}
                      >
                        {getPasswordStrengthLabel(passwordStrength.score).label}
                      </Typography>
                    </Box>
                  </Box>
                  
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                    {Object.entries(passwordStrength.checks).map(([key, value]) => (
                      <Box
                        key={key}
                        sx={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 0.5,
                          color: value ? 'success.main' : 'text.secondary',
                          fontSize: '0.75rem',
                        }}
                      >
                        {value ? <CheckIcon sx={{ fontSize: 14 }} /> : <CloseIcon sx={{ fontSize: 14 }} />}
                        <span>
                          {key === 'length' && '8+ characters'}
                          {key === 'uppercase' && 'Uppercase'}
                          {key === 'lowercase' && 'Lowercase'}
                          {key === 'number' && 'Number'}
                          {key === 'special' && 'Special character'}
                        </span>
                      </Box>
                    ))}
                  </Box>
                </Box>
              )}

              <TextField
                fullWidth
                label="Confirm Password"
                name="confirmPassword"
                type={showConfirmPassword ? 'text' : 'password'}
                value={formData.confirmPassword}
                onChange={handleChange}
                onBlur={handleBlur}
                margin="normal"
                required
                error={!!fieldErrors.confirmPassword}
                helperText={fieldErrors.confirmPassword}
                autoComplete="new-password"
                slotProps={{
                  input: {
                    endAdornment: (
                      <InputAdornment position="end">
                        <IconButton
                          onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                          edge="end"
                          aria-label="toggle password visibility"
                        >
                          {showConfirmPassword ? <VisibilityOff /> : <Visibility />}
                        </IconButton>
                      </InputAdornment>
                    ),
                  },
                }}
              />

              <FormControlLabel
                control={
                  <Checkbox
                    checked={acceptedTerms}
                    onChange={(e) => setAcceptedTerms(e.target.checked)}
                    color="primary"
                  />
                }
                label={
                  <Typography variant="body2">
                    I agree to the{' '}
                    <Link href="#" color="primary" underline="hover">
                      Terms of Service
                    </Link>
                    {' '}and{' '}
                    <Link href="#" color="primary" underline="hover">
                      Privacy Policy
                    </Link>
                  </Typography>
                }
                sx={{ mt: 2, alignItems: 'flex-start' }}
              />

              <Button
                fullWidth
                type="submit"
                variant="contained"
                size="large"
                disabled={loading}
                startIcon={loading ? <CircularProgress size={20} color="inherit" /> : <PersonAddIcon />}
                sx={{
                  mt: 3,
                  py: 1.5,
                  fontSize: '1rem',
                  borderRadius: 2,
                  background: 'linear-gradient(135deg, #90caf9, #42a5f5)',
                  '&:hover': {
                    background: 'linear-gradient(135deg, #42a5f5, #1e88e5)',
                  },
                  '&:disabled': {
                    background: 'rgba(144,202,249,0.3)',
                  },
                }}
              >
                {loading ? 'Creating Account...' : 'Create Account'}
              </Button>
            </form>

            <Box sx={{ textAlign: 'center', mt: 3 }}>
              <Typography variant="body2" color="textSecondary">
                Already have an account?{' '}
                <Link component={RouterLink} to="/login" color="primary" sx={{ fontWeight: 600 }}>
                  Log in
                </Link>
              </Typography>
            </Box>
          </>
        )}

        {activeStep === 1 && (
          <Box sx={{ textAlign: 'center', py: 4 }}>
            <Box sx={{ fontSize: 48, mb: 2 }}>⏳</Box>
            <Typography variant="h5" sx={{ fontWeight: 600, mb: 2 }}>
              Creating Your Account...
            </Typography>
            <CircularProgress sx={{ mt: 2 }} />
          </Box>
        )}

        {activeStep === 2 && (
          <Box sx={{ textAlign: 'center', py: 4 }}>
            <Box sx={{ fontSize: 64, mb: 2 }}>✅</Box>
            <Typography variant="h5" sx={{ fontWeight: 600, mb: 2 }}>
              Account Created!
            </Typography>
            <Typography variant="body1" color="textSecondary" sx={{ mb: 2 }}>
              Your account has been successfully created.
            </Typography>
            <Typography variant="body2" color="textSecondary" sx={{ mb: 4 }}>
              Redirecting to login...
            </Typography>
            <Button
              variant="contained"
              size="large"
              onClick={() => navigate('/login')}
              sx={{
                py: 1.5,
                px: 4,
                borderRadius: 2,
                background: 'linear-gradient(135deg, #90caf9, #42a5f5)',
                '&:hover': {
                  background: 'linear-gradient(135deg, #42a5f5, #1e88e5)',
                },
              }}
            >
              Go to Login
            </Button>
          </Box>
        )}
      </Paper>
    </Box>
  );
};

export default Register;