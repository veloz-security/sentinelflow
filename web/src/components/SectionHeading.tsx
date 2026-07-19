import { Box, Stack, Typography } from '@mui/material';
import type { ReactNode } from 'react';

export interface SectionHeadingProps {
  readonly id: string;
  readonly eyebrow?: string;
  readonly title: string;
  readonly description?: string;
  readonly action?: ReactNode;
}

export function SectionHeading({
  id,
  eyebrow,
  title,
  description,
  action,
}: SectionHeadingProps) {
  return (
    <Stack
      direction={{ xs: 'column', sm: 'row' }}
      spacing={2}
      alignItems={{ xs: 'flex-start', sm: 'flex-end' }}
      justifyContent="space-between"
    >
      <Box sx={{ maxWidth: '72ch' }}>
        {eyebrow ? (
          <Typography variant="overline" color="primary.dark">
            {eyebrow}
          </Typography>
        ) : null}
        <Typography
          id={id}
          component="h2"
          variant="h2"
          gutterBottom={Boolean(description)}
        >
          {title}
        </Typography>
        {description ? (
          <Typography color="text.secondary">{description}</Typography>
        ) : null}
      </Box>
      {action}
    </Stack>
  );
}
