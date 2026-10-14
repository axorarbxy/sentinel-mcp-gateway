// pages/modules/PasswordModule.tsx
import React from 'react';
import ModuleBase from './ModuleBase';
import { gatewayFetch } from '../../services/api';

const PasswordModule: React.FC = () => {
  const handleAnalyze = async (input: string) => {
    const response = await gatewayFetch('/cybereye/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: 'password',
        data: input,
      }),
    });

    if (!response.ok) {
      const body = await response.json().catch(() => null);
      throw new Error(body?.detail || body?.error || `Analysis failed (${response.status})`);
    }

    return response.json();
  };

  return (
    <ModuleBase
      title="Password Analyzer"
      icon="🔑"
      description="Check password strength, entropy, and security against common patterns"
      inputLabel="Enter password to analyze"
      inputPlaceholder="e.g., MySecurePassword123!"
      inputType="password"
      onAnalyze={handleAnalyze}
    />
  );
};

export default PasswordModule;