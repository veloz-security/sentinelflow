import { Box, Typography } from '@mui/material';
import { semanticTokens } from '../theme';

type ProvenanceKind =
  'observed' | 'deterministic' | 'ai' | 'human' | 'enforcement';

const labelByKind: Readonly<Record<ProvenanceKind, string>> = {
  observed: 'Observed',
  deterministic: 'Deterministic',
  ai: 'AI interpretation',
  human: 'Human decision',
  enforcement: 'Enforcement result',
};

export function ProvenanceTag({ kind }: { readonly kind: ProvenanceKind }) {
  return (
    <Box
      component="span"
      sx={{ display: 'inline-flex', alignItems: 'center', gap: 0.75 }}
    >
      <Box
        component="span"
        aria-hidden="true"
        sx={{
          width: 7,
          height: 7,
          borderRadius: 1,
          bgcolor: semanticTokens.provenance[kind],
        }}
      />
      <Typography component="span" variant="caption" sx={{ fontWeight: 720 }}>
        {labelByKind[kind]}
      </Typography>
    </Box>
  );
}
