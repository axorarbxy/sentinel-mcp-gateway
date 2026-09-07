// pages/AgentDetails.tsx
import React, { useEffect, useState } from 'react';
import {
  Box,
  Typography,
  Paper,
  Grid,
  Card,
  CardContent,
  Chip,
  IconButton,
  Tooltip,
  LinearProgress,
  TextField,
  InputAdornment,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  Search as SearchIcon,
  Person as PersonIcon,
  Timeline as TimelineIcon,
  Warning as WarningIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';
import { gatewayApi } from '../services/api';
import { AgentStats, LogEntry } from '../types';

interface AgentWithLogs extends AgentStats {
  recent_logs?: LogEntry[];
}

const AgentDetailsPage: React.FC = () => {
  const [agents, setAgents] = useState<Record<string, AgentWithLogs>>({});
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');

  const fetchAgents = async () => {
    try {
      const logsData = await gatewayApi.getLogs(100);
      const logs = logsData.logs;

      const agentIds: string[] = [];
      const seen = new Set<string>();
      logs.forEach(log => {
        if (!seen.has(log.agent_id)) {
          seen.add(log.agent_id);
          agentIds.push(log.agent_id);
        }
      });

      const agentStats: Record<string, AgentWithLogs> = {};
      for (const agentId of agentIds) {
        try {
          const stats = await gatewayApi.getAgentStats(agentId);
          const agentLogs = logs.filter(log => log.agent_id === agentId).slice(0, 10);
          agentStats[agentId] = {
            ...stats,
            recent_logs: agentLogs,
          };
        } catch (error) {
          console.error(`Failed to fetch stats for agent ${agentId}:`, error);
        }
      }

      setAgents(agentStats);
    } catch (error) {
      console.error('Error fetching agents:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAgents();
    const interval = setInterval(fetchAgents, 10000);
    return () => clearInterval(interval);
  }, []);

  const getAgentStatus = (agent: AgentWithLogs) => {
    if (agent.anomaly_count > 0) {
      return { label: 'Suspicious', color: 'error' as const };
    } else if (agent.is_monitored) {
      return { label: 'Monitored', color: 'success' as const };
    } else {
      return { label: 'Unmonitored', color: 'default' as const };
    }
  };

  const filteredAgents = Object.values(agents).filter(agent =>
    agent.agent_id.toLowerCase().includes(searchTerm.toLowerCase())
  );

  if (loading) {
    return (
      <Box sx={{ width: '100%', mt: 4 }}>
        <LinearProgress />
        <Typography align="center" sx={{ mt: 2 }}>
          Loading agent details...
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ flexGrow: 1, p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1">
          🤖 Agent Details
        </Typography>
        <Box>
          <Tooltip title="Refresh">
            <IconButton onClick={fetchAgents}>
              <RefreshIcon />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>

      <Paper sx={{ p: 2, mb: 3 }}>
        <TextField
          fullWidth
          placeholder="Search agents by ID..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          slotProps={{
            input: {
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon />
                </InputAdornment>
              ),
            },
          }}
        />
      </Paper>

      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Total Agents
              </Typography>
              <Typography variant="h4">{Object.keys(agents).length}</Typography>
              <Chip size="small" icon={<PersonIcon />} label="Active" color="primary" />
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Monitored Agents
              </Typography>
              <Typography variant="h4">
                {Object.values(agents).filter(a => a.is_monitored).length}
              </Typography>
              <Chip size="small" icon={<SecurityIcon />} label="ML tracking" color="success" />
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Suspicious Agents
              </Typography>
              <Typography variant="h4" color="error">
                {Object.values(agents).filter(a => a.anomaly_count > 0).length}
              </Typography>
              <Chip size="small" icon={<WarningIcon />} label="Has anomalies" color="error" />
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Total Requests
              </Typography>
              <Typography variant="h4">
                {Object.values(agents).reduce((sum, a) => sum + a.request_count, 0)}
              </Typography>
              <Chip size="small" icon={<TimelineIcon />} label="Across all agents" color="info" />
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {filteredAgents.length === 0 ? (
        <Paper sx={{ p: 4, textAlign: 'center' }}>
          <Typography variant="h6" color="textSecondary">
            No agents found
          </Typography>
        </Paper>
      ) : (
        <Grid container spacing={3}>
          {filteredAgents.map((agent) => {
            const status = getAgentStatus(agent);
            const methodKeys = Object.keys(agent.method_distribution || {});
            return (
              <Grid size={{ xs: 12, md: 6, lg: 4 }} key={agent.agent_id}>
                <Card
                  sx={{
                    height: '100%',
                    transition: 'transform 0.2s',
                    '&:hover': {
                      transform: 'translateY(-4px)',
                      boxShadow: 6,
                    },
                    borderLeft: `4px solid ${
                      status.color === 'error' ? '#f44336' :
                      status.color === 'success' ? '#4caf50' :
                      '#9e9e9e'
                    }`,
                  }}
                >
                  <CardContent>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                      <Box>
                        <Typography variant="h6" component="div">
                          {agent.agent_id}
                        </Typography>
                        <Chip size="small" label={status.label} color={status.color} sx={{ mt: 1 }} />
                      </Box>
                    </Box>

                    <Grid container spacing={2} sx={{ mt: 2 }}>
                      <Grid size={{ xs: 6 }}>
                        <Typography variant="caption" color="textSecondary">
                          Requests
                        </Typography>
                        <Typography variant="h6">{agent.request_count}</Typography>
                      </Grid>
                      <Grid size={{ xs: 6 }}>
                        <Typography variant="caption" color="textSecondary">
                          Anomalies
                        </Typography>
                        <Typography variant="h6" color={agent.anomaly_count > 0 ? 'error' : 'text.primary'}>
                          {agent.anomaly_count}
                        </Typography>
                      </Grid>
                      <Grid size={{ xs: 6 }}>
                        <Typography variant="caption" color="textSecondary">
                          Method Types
                        </Typography>
                        <Typography variant="h6">{methodKeys.length}</Typography>
                      </Grid>
                      <Grid size={{ xs: 6 }}>
                        <Typography variant="caption" color="textSecondary">
                          ML Model
                        </Typography>
                        <Typography variant="h6">
                          {agent.is_monitored ? '✅' : '❌'}
                        </Typography>
                      </Grid>
                    </Grid>

                    {methodKeys.length > 0 && (
                      <Box sx={{ mt: 2 }}>
                        <Typography variant="caption" color="textSecondary">
                          Method Distribution
                        </Typography>
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 1 }}>
                          {methodKeys.slice(0, 5).map((method) => (
                            <Chip
                              key={method}
                              size="small"
                              label={`${method}: ${agent.method_distribution?.[method] || 0}`}
                              variant="outlined"
                            />
                          ))}
                          {methodKeys.length > 5 && (
                            <Chip size="small" label={`+${methodKeys.length - 5} more`} variant="outlined" />
                          )}
                        </Box>
                      </Box>
                    )}

                    {agent.last_request && (
                      <Typography variant="caption" color="textSecondary" sx={{ display: 'block', mt: 1 }}>
                        Last request: {new Date(agent.last_request).toLocaleString()}
                      </Typography>
                    )}
                  </CardContent>
                </Card>
              </Grid>
            );
          })}
        </Grid>
      )}
    </Box>
  );
};

export default AgentDetailsPage;