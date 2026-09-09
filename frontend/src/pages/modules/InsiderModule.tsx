// pages/modules/InsiderModule.tsx
import React from 'react';
import ModuleBase from './ModuleBase';

const InsiderModule: React.FC = () => {
  const handleAnalyze = async (input: string) => {
    let userData;
    try {
      userData = JSON.parse(input);
    } catch {
      userData = {
        user_id: input || 'unknown',
        timestamp: new Date().toISOString(),
        flags: ['suspicious_activity'],
      };
    }

    const response = await fetch('http://localhost:8001/cybereye/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: 'user',
        data: userData,
      }),
    });

    if (!response.ok) {
      throw new Error('Analysis failed');
    }

    return response.json();
  };

  return (
    <ModuleBase
      title="Insider Threat Detection"
      icon="👤"
      description="Detect anomalous user behavior, suspicious access patterns, and insider threats"
      inputLabel="Enter user activity data"
      inputPlaceholder="e.g., {'user_id': 'john.doe', 'data_size': 150, 'external_transfer': true}"
      inputType="user"
      onAnalyze={handleAnalyze}
    />
  );
};

export default InsiderModule;