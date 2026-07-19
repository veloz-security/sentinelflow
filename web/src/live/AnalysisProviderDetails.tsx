import { Box, Stack, Typography } from '@mui/material';
import { DetailList } from '../components/DetailList';
import { StatusBadge } from '../components/StatusBadge';
import type { AnalysisSummary } from './contracts';

export function AnalysisProviderDetails({
  analysis,
}: {
  readonly analysis: Readonly<AnalysisSummary>;
}) {
  const deterministic = analysis.provider_kind === 'deterministic_stub';
  return (
    <Box
      component="section"
      aria-label="Analysis provider provenance"
      sx={{
        mt: 2,
        p: 2,
        border: 1,
        borderColor: 'divider',
        borderRadius: 1.5,
        bgcolor: 'background.default',
      }}
    >
      <Stack spacing={1.5}>
        <Stack
          direction={{ xs: 'column', sm: 'row' }}
          spacing={1}
          alignItems={{ xs: 'flex-start', sm: 'center' }}
          justifyContent="space-between"
        >
          <Typography component="h3" variant="h3">
            Analysis provider
          </Typography>
          <StatusBadge
            label={
              deterministic
                ? 'Deterministic offline stub'
                : 'OpenAI Responses API'
            }
            tone={deterministic ? 'info' : 'warning'}
          />
        </Stack>
        <DetailList
          items={
            deterministic
              ? [
                  {
                    label: 'Provider',
                    value: 'Deterministic offline stub',
                  },
                  {
                    label: 'Adapter ID',
                    value: <code>{analysis.adapter_id}</code>,
                  },
                  {
                    label: 'Provenance',
                    value: 'Offline deterministic adapter',
                  },
                ]
              : [
                  { label: 'Provider', value: 'OpenAI Responses API' },
                  {
                    label: 'Adapter ID',
                    value: <code>{analysis.adapter_id}</code>,
                  },
                  { label: 'Model', value: <code>{analysis.model}</code> },
                  {
                    label: 'Reasoning effort',
                    value: analysis.reasoning_effort,
                  },
                  {
                    label: 'Rate card',
                    value: <code>{analysis.rate_card_version}</code>,
                  },
                ]
          }
        />
        <Typography variant="caption" color="text.secondary">
          Provider identity is decoded from the server response and never
          inferred from incident state or policy content.
        </Typography>
      </Stack>
    </Box>
  );
}
