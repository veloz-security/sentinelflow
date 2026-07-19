import { Box, Button, Paper, Stack, Typography } from '@mui/material';
import { StatusBadge } from './StatusBadge';

export function ReviewControl() {
  return (
    <Paper
      component="section"
      variant="outlined"
      aria-labelledby="review-control-title"
      sx={{ p: { xs: 2.5, md: 3 }, bgcolor: 'background.paper' }}
    >
      <Stack spacing={2.5}>
        <Stack
          direction="row"
          spacing={2}
          justifyContent="space-between"
          alignItems="center"
        >
          <Box>
            <Typography id="review-control-title" component="h2" variant="h3">
              Review control
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
              Fixture mode presents state only. It cannot issue or consume a HIL
              challenge.
            </Typography>
          </Box>
          <StatusBadge label="Presentation only" tone="warning" />
        </Stack>
        <Button variant="contained" disabled fullWidth>
          Approve exact artifact
        </Button>
      </Stack>
    </Paper>
  );
}
