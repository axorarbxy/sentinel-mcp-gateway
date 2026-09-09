// pages/modules/PhishingModule.tsx
import React from 'react';
import ModuleBase from './ModuleBase';

const PhishingModule: React.FC = () => {
  const handleAnalyze = async (input: string) => {
    const response = await fetch('http://localhost:8001/cybereye/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: 'url',
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
      title="Phishing Detection"
      icon="🔗"
      description="Analyze URLs for phishing indicators, malicious domains, and suspicious patterns"
      inputLabel="Enter URL to analyze"
      inputPlaceholder="e.g., https://example.com/login/verify"
      inputType="url"
      onAnalyze={handleAnalyze}
    />
  );
};

export default PhishingModule;