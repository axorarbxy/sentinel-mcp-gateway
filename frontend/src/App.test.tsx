import React from 'react';
import { render, screen } from '@testing-library/react';
import App from './App';

test('renders the Sentinel landing page for unauthenticated users', () => {
  localStorage.removeItem('access_token');
  render(<App />);
  expect(screen.getByText('Sentinel-MCP')).toBeInTheDocument();
});
