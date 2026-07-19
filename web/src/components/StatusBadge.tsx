import { Box, Chip } from '@mui/material';
import { semanticTokens } from '../theme';

export type SemanticTone =
  'neutral' | 'info' | 'positive' | 'warning' | 'critical';

export interface StatusBadgeProps {
  readonly label: string;
  readonly tone?: SemanticTone;
  readonly ariaLabel?: string;
}

export function StatusBadge({
  label,
  tone = 'neutral',
  ariaLabel,
}: StatusBadgeProps) {
  const token = semanticTokens[tone];

  return (
    <Chip
      aria-label={ariaLabel}
      label={
        <Box
          component="span"
          sx={{ display: 'inline-flex', alignItems: 'center', gap: 0.75 }}
        >
          <Box
            component="span"
            aria-hidden="true"
            sx={{
              width: 6,
              height: 6,
              borderRadius: '50%',
              bgcolor: token.foreground,
            }}
          />
          {label}
        </Box>
      }
      variant="outlined"
      sx={{
        color: token.foreground,
        bgcolor: token.background,
        borderColor: token.border,
      }}
    />
  );
}
