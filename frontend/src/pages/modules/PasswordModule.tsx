// pages/modules/PasswordModule.tsx
import React from 'react';
import ModuleBase from './ModuleBase';

const PasswordModule: React.FC = () => {
  const handleAnalyze = async (input: string) => {
    const response = await fetch('http://localhost:8001/cybereye/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: 'password',
        data: input,
      }),
    });

    if (!response.ok) {
      throw new Error('Analysis failed');
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