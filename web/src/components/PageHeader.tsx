import { Box, Stack, Typography } from '@mui/material';
import type { ReactNode } from 'react';

export interface PageHeaderProps {
  readonly eyebrow: string;
  readonly title: string;
  readonly description: string;
  readonly status?: ReactNode;
}

export function PageHeader({
  eyebrow,
  title,
  description,
  status,
}: PageHeaderProps) {
  return (
    <Stack
      direction={{ xs: 'column', sm: 'row' }}
      spacing={2.5}
      alignItems={{ xs: 'flex-start', sm: 'flex-end' }}
      justifyContent="space-between"
    >
      <Box sx={{ maxWidth: '72ch' }}>
        <Typography variant="overline" color="primary.dark">
          {eyebrow}
        </Typography>
        <Typography component="h1" variant="h1" sx={{ mt: 0.5 }}>
          {title}
        </Typography>
        <Typography color="text.secondary" sx={{ mt: 1.25, maxWidth: '70ch' }}>
          {description}
        </Typography>
      </Box>
      {status}
    </Stack>
  );
}
