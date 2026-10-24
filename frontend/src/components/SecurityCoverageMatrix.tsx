import React from 'react';
import {
  Box,
  Card,
  CardContent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material';
import {
  CheckCircleOutlined as CheckCircleOutlineIcon,
  RemoveCircleOutlined as RemoveCircleOutlineIcon,
  InfoOutlined as InfoOutlinedIcon,
} from '@mui/icons-material';

type Coverage = 'enforced' | 'contextual' | 'not-applicable';

const columns = [
  { key: 'runtime', label: 'Runtime\ninterception' },
  { key: 'context', label: 'Cross-step\ncontext' },
  { key: 'rate', label: 'Rate\ncontrol' },
  { key: 'audit', label: 'Audit\nevidence' },
] as const;

const rows: {
  threat: string;
  detail: string;
  coverage: Record<(typeof columns)[number]['key'], Coverage>;
}[] = [
  {
    threat: 'Path traversal',
    detail: 'Encoded parent segments, null bytes, and sensitive paths',
    coverage: { runtime: 'enforced', context: 'not-applicable', rate: 'not-applicable', audit: 'enforced' },
  },
  {
    threat: 'User-guided data exfiltration',
    detail: 'Outbound tool calls after upstream data is returned in the session',
    coverage: { runtime: 'contextual', context: 'contextual', rate: 'not-applicable', audit: 'enforced' },
  },
  {
    threat: 'Injected sensitive action',
    detail: 'Operator-listed write, execute, or transfer tools after upstream data',
    coverage: { runtime: 'contextual', context: 'enforced', rate: 'not-applicable', audit: 'enforced' },
  },
  {
    threat: 'High-frequency tool abuse',
    detail: 'Repeated calls to the same tool (default: 30 calls per minute)',
    coverage: { runtime: 'enforced', context: 'not-applicable', rate: 'enforced', audit: 'enforced' },
  },
];

const statusLabel: Record<Coverage, string> = {
  enforced: 'Enforced',
  contextual: 'Context dependent',
  'not-applicable': 'Not applicable',
};

const SecurityCoverageMatrix: React.FC = () => (
  <Card
    sx={{
      overflow: 'hidden',
      background: 'linear-gradient(145deg, rgba(15, 25, 34, .98), rgba(10, 17, 25, .98))',
      border: '1px solid rgba(154,175,193,.16)',
      borderRadius: 3,
    }}
  >
    <CardContent sx={{ p: { xs: 0, sm: 1 } }}>
      <TableContainer sx={{ overflowX: 'auto' }}>
        <Table aria-label="Sentinel MCP gateway security coverage matrix" sx={{ minWidth: 720, tableLayout: 'fixed' }}>
          <TableHead>
            <TableRow sx={{ '& th': { borderBottom: '1px solid rgba(154,175,193,.2)' } }}>
              <TableCell sx={{ width: '37%', color: '#AAB8C2', fontWeight: 800, fontSize: 12, letterSpacing: '.08em', textTransform: 'uppercase' }}>
                Threat class
              </TableCell>
              {columns.map((column) => (
                <TableCell key={column.key} align="center" sx={{ color: '#AAB8C2', fontWeight: 800, fontSize: 11, letterSpacing: '.04em', whiteSpace: 'pre-line', lineHeight: 1.45 }}>
                  {column.label}
                </TableCell>
              ))}
            </TableRow>
          </TableHead>
          <TableBody>
            {rows.map((row) => (
              <TableRow key={row.threat} hover sx={{ '&:last-child td': { borderBottom: 0 } }}>
                <TableCell component="th" scope="row" sx={{ py: 2, borderColor: 'rgba(154,175,193,.12)' }}>
                  <Typography sx={{ color: '#F3F7FA', fontSize: 14, fontWeight: 750 }}>{row.threat}</Typography>
                  <Typography sx={{ color: '#8293A0', fontSize: 11, lineHeight: 1.5, mt: .45 }}>{row.detail}</Typography>
                </TableCell>
                {columns.map((column) => {
                  const coverage = row.coverage[column.key];
                  return (
                    <TableCell key={column.key} align="center" sx={{ py: 2, borderColor: 'rgba(154,175,193,.12)' }}>
                      {coverage === 'enforced' ? (
                        <Box component="span" role="img" aria-label={statusLabel[coverage]} title={statusLabel[coverage]} sx={{ display: 'inline-flex', color: '#56E0C3' }}>
                          <CheckCircleOutlineIcon fontSize="small" />
                        </Box>
                      ) : coverage === 'contextual' ? (
                        <Box component="span" role="img" aria-label={statusLabel[coverage]} title={statusLabel[coverage]} sx={{ display: 'inline-flex', color: '#F0B95B' }}>
                          <InfoOutlinedIcon fontSize="small" />
                        </Box>
                      ) : (
                        <Box component="span" role="img" aria-label={statusLabel[coverage]} title={statusLabel[coverage]} sx={{ display: 'inline-flex', color: '#607383' }}>
                          <RemoveCircleOutlineIcon fontSize="small" />
                        </Box>
                      )}
                    </TableCell>
                  );
                })}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
      <Box sx={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 2.5, px: { xs: 2, sm: 2.5 }, py: 1.8, borderTop: '1px solid rgba(154,175,193,.1)' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: .8 }}><CheckCircleOutlineIcon sx={{ fontSize: 16, color: '#56E0C3' }} /><Typography sx={{ fontSize: 11, color: '#AAB8C2' }}>Enforced at the gateway</Typography></Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: .8 }}><InfoOutlinedIcon sx={{ fontSize: 16, color: '#F0B95B' }} /><Typography sx={{ fontSize: 11, color: '#AAB8C2' }}>Context dependent</Typography></Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: .8 }}><RemoveCircleOutlineIcon sx={{ fontSize: 16, color: '#607383' }} /><Typography sx={{ fontSize: 11, color: '#AAB8C2' }}>Not applicable to this threat</Typography></Box>
      </Box>
    </CardContent>
  </Card>
);

export default SecurityCoverageMatrix;
