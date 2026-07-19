import { Box, Typography } from '@mui/material';
import type { ReactNode } from 'react';

export interface DetailItem {
  readonly label: string;
  readonly value: ReactNode;
}

export function DetailList({
  items,
}: {
  readonly items: readonly DetailItem[];
}) {
  return (
    <Box
      component="dl"
      sx={{
        m: 0,
        display: 'grid',
        gridTemplateColumns: {
          xs: 'minmax(0, 1fr)',
          sm: 'repeat(2, minmax(0, 1fr))',
        },
        columnGap: 4,
      }}
    >
      {items.map((item) => (
        <Box
          key={item.label}
          sx={{
            py: 1.5,
            borderBottom: 1,
            borderColor: 'divider',
            minWidth: 0,
          }}
        >
          <Typography component="dt" variant="caption" color="text.secondary">
            {item.label}
          </Typography>
          <Typography
            component="dd"
            variant="body2"
            sx={{ m: 0, mt: 0.35, fontWeight: 670, overflowWrap: 'anywhere' }}
          >
            {item.value}
          </Typography>
        </Box>
      ))}
    </Box>
  );
}
