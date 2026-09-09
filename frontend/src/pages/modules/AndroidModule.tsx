// pages/modules/AndroidModule.tsx
import React from 'react';
import ModuleBase from './ModuleBase';

const AndroidModule: React.FC = () => {
  const handleAnalyze = async (input: string) => {
    let androidData;
    try {
      androidData = JSON.parse(input);
    } catch {
      androidData = {
        app_name: 'Unknown App',
        permissions: input.split(',').map(p => p.trim()),
      };
    }

    const response = await fetch('http://localhost:8001/cybereye/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: 'android',
        data: androidData,
      }),
    });

    if (!response.ok) {
      throw new Error('Analysis failed');
    }

    return response.json();
  };

  return (
    <ModuleBase
      title="Android App Security Analyzer"
      icon="📱"
      description="Audit app permissions, detect malicious behavior, and security risks"
      inputLabel="Enter app permissions or data"
      inputPlaceholder="e.g., ['READ_SMS', 'INTERNET', 'CAMERA']"
      inputType="android"
      onAnalyze={handleAnalyze}
    />
  );
};

export default AndroidModule;