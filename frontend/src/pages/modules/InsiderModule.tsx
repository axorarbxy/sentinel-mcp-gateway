// pages/modules/InsiderModule.tsx
import React from 'react';
import ModuleBase from './ModuleBase';
import { gatewayFetch } from '../../services/api';

const InsiderModule: React.FC = () => {
  const handleAnalyze = async (input: string) => {
    let userData;
    try {
      userData = JSON.parse(input);
    } catch {
      // Also accept readable, labeled activity summaries (User:, Action:,
      // Result:, Location:) so safe prose is not automatically marked suspicious.
      const fields: Record<string, string> = {};
      input.split(/\r?\n/).forEach(line => {
        const match = line.match(/^\s*([\w ]+)\s*:\s*(.+)\s*$/);
        if (match) fields[match[1].trim().toLowerCase()] = match[2].trim();
      });
      const action = fields.action || input.trim();
      const result = fields.result || '';
      const combined = `${action} ${result}`;
      const recordMatch = combined.match(/([\d,]+)\s*(?:customer\s+)?records?/i);
      const sizeMatch = combined.match(/([\d.]+)\s*(gb|mb)\b/i);
      const location = fields.location || '';
      userData = {
        user_id: fields.user || fields.username || 'demo-user',
        timestamp: new Date().toISOString(),
        local_hour: new Date().getHours(),
        local_weekday: new Date().getDay() === 0 ? 6 : new Date().getDay() - 1,
        action,
        resource: fields.resource || '',
        result,
        location,
        ...(recordMatch ? { records_count: Number(recordMatch[1].replace(/,/g, '')) } : {}),
        ...(sizeMatch ? { data_size: Number(sizeMatch[1]) * (sizeMatch[2].toLowerCase() === 'gb' ? 1024 : 1) } : {}),
        unfamiliar_location: /unfamiliar|unknown|foreign/i.test(location),
        external_transfer: /external transfer|uploaded externally|sent to external/i.test(combined),
        flags: [],
      };
    }

    const response = await gatewayFetch('/cybereye/analyze', {
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
