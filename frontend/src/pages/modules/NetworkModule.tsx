// pages/modules/NetworkModule.tsx
import React from 'react';
import ModuleBase from './ModuleBase';

const NetworkModule: React.FC = () => {
  const handleAnalyze = async (input: string) => {
    // Parse network data from text input
    let networkData;
    try {
      networkData = JSON.parse(input);
    } catch {
      // Try to parse as simple format
      const parts = input.split(' ');
      networkData = {
        src_ip: parts[0] || '',
        dst_ip: parts[1] || '',
        dst_port: parseInt(parts[2]) || 0,
        protocol: parts[3] || 'TCP',
        payload: parts.slice(4).join(' ') || '',
      };
    }

    const response = await fetch('http://localhost:8001/cybereye/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: 'network',
        data: networkData,
      }),
    });

    if (!response.ok) {
      throw new Error('Analysis failed');
    }

    return response.json();
  };

  return (
    <ModuleBase
      title="Network Intrusion Detection"
      icon="🌐"
      description="Monitor network traffic for attack patterns, suspicious ports, and intrusion attempts"
      inputLabel="Enter network data to analyze"
      inputPlaceholder="e.g., 192.168.1.100 203.0.113.1 22 TCP 'failed login attempt'"
      inputType="network"
      onAnalyze={handleAnalyze}
    />
  );
};

export default NetworkModule;