import { Box, Button, Grid, Paper, Stack, Typography } from '@mui/material';
import { Link as RouterLink } from 'react-router-dom';
import { PageHeader } from '../components/PageHeader';
import { PresentationState } from '../components/PresentationState';
import { StatusBadge, type SemanticTone } from '../components/StatusBadge';
import {
  MOCK_PRESENTATION_STATES,
  PRESENTATION_STATE_ORDER,
} from '../mocks/presentationStates';

const semanticLegend: ReadonlyArray<{ label: string; tone: SemanticTone }> = [
  { label: 'Neutral', tone: 'neutral' },
  { label: 'Information', tone: 'info' },
  { label: 'Positive', tone: 'positive' },
  { label: 'Warning', tone: 'warning' },
  { label: 'Critical', tone: 'critical' },
];

export function StateMatrixPage() {
  return (
    <Stack spacing={{ xs: 4, md: 5 }}>
      <PageHeader
        eyebrow="Design system"
        title="Presentation state library"
        description="Six deeply frozen resource variants verify that absence, failure, denial, disabled authority, loading, and success remain visually and semantically distinct."
        status={<StatusBadge label="Fixture-backed" tone="neutral" />}
      />

      <Paper
        component="section"
        variant="outlined"
        aria-labelledby="semantic-tone-title"
        sx={{ p: { xs: 2, md: 2.5 } }}
      >
        <Stack
          direction={{ xs: 'column', md: 'row' }}
          spacing={2}
          alignItems={{ xs: 'flex-start', md: 'center' }}
          justifyContent="space-between"
        >
          <Box>
            <Typography id="semantic-tone-title" component="h2" variant="h3">
              Semantic tones
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
              Text labels and markers supplement color in every status token.
            </Typography>
          </Box>
          <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap">
            {semanticLegend.map((item) => (
              <StatusBadge
                key={item.tone}
                label={item.label}
                tone={item.tone}
              />
            ))}
          </Stack>
        </Stack>
      </Paper>

      <Grid container spacing={3}>
        <Grid size={{ xs: 12, md: 6, xl: 4 }}>
          <Paper
            component="section"
            variant="outlined"
            aria-labelledby="incident-state-library-title"
            sx={{ p: { xs: 2, md: 2.5 }, height: '100%' }}
          >
            <Stack spacing={2} alignItems="flex-start">
              <Box>
                <Typography
                  id="incident-state-library-title"
                  component="h2"
                  variant="h3"
                >
                  Incident list states
                </Typography>
                <Typography
                  variant="body2"
                  color="text.secondary"
                  sx={{ mt: 0.5 }}
                >
                  Inspect loading, empty, error, permission, and populated list
                  fixtures in the application shell.
                </Typography>
              </Box>
              <Button
                component={RouterLink}
                to="/states/incidents/populated"
                variant="outlined"
              >
                Open list states
              </Button>
            </Stack>
          </Paper>
        </Grid>
        <Grid size={{ xs: 12, md: 6, xl: 4 }}>
          <Paper
            component="section"
            variant="outlined"
            aria-labelledby="incident-detail-state-library-title"
            sx={{ p: { xs: 2, md: 2.5 }, height: '100%' }}
          >
            <Stack spacing={2} alignItems="flex-start">
              <Box>
                <Typography
                  id="incident-detail-state-library-title"
                  component="h2"
                  variant="h3"
                >
                  Incident detail states
                </Typography>
                <Typography
                  variant="body2"
                  color="text.secondary"
                  sx={{ mt: 0.5 }}
                >
                  Inspect eight detail outcomes, including degraded coverage and
                  failed model analysis.
                </Typography>
              </Box>
              <Button
                component={RouterLink}
                to="/states/incident-detail/complete"
                variant="outlined"
              >
                Open detail states
              </Button>
            </Stack>
          </Paper>
        </Grid>
        <Grid size={{ xs: 12, md: 6, xl: 4 }}>
          <Paper
            component="section"
            variant="outlined"
            aria-labelledby="validation-review-state-library-title"
            sx={{ p: { xs: 2, md: 2.5 }, height: '100%' }}
          >
            <Stack spacing={2} alignItems="flex-start">
              <Box>
                <Typography
                  id="validation-review-state-library-title"
                  component="h2"
                  variant="h3"
                >
                  Validation review states
                </Typography>
                <Typography
                  variant="body2"
                  color="text.secondary"
                  sx={{ mt: 0.5 }}
                >
                  Inspect complete and fail-closed policy, artifact, coverage,
                  impact, freshness, and permission outcomes.
                </Typography>
              </Box>
              <Button
                component={RouterLink}
                to="/states/validation/ready"
                variant="outlined"
              >
                Open validation states
              </Button>
            </Stack>
          </Paper>
        </Grid>
        <Grid size={{ xs: 12, md: 6, xl: 4 }}>
          <Paper
            component="section"
            variant="outlined"
            aria-labelledby="hil-authorization-state-library-title"
            sx={{ p: { xs: 2, md: 2.5 }, height: '100%' }}
          >
            <Stack spacing={2} alignItems="flex-start">
              <Box>
                <Typography
                  id="hil-authorization-state-library-title"
                  component="h2"
                  variant="h3"
                >
                  HIL authorization states
                </Typography>
                <Typography
                  variant="body2"
                  color="text.secondary"
                  sx={{ mt: 0.5 }}
                >
                  Inspect approval, rejection, step-up, challenge, conflict,
                  expiry, permission, and terminal fixture outcomes.
                </Typography>
              </Box>
              <Button
                component={RouterLink}
                to="/states/hil/ready"
                variant="outlined"
              >
                Open HIL states
              </Button>
            </Stack>
          </Paper>
        </Grid>
        <Grid size={{ xs: 12, md: 6, xl: 4 }}>
          <Paper
            component="section"
            variant="outlined"
            aria-labelledby="enforcement-lifecycle-state-library-title"
            sx={{ p: { xs: 2, md: 2.5 }, height: '100%' }}
          >
            <Stack spacing={2} alignItems="flex-start">
              <Box>
                <Typography
                  id="enforcement-lifecycle-state-library-title"
                  component="h2"
                  variant="h3"
                >
                  Enforcement lifecycle states
                </Typography>
                <Typography
                  variant="body2"
                  color="text.secondary"
                  sx={{ mt: 0.5 }}
                >
                  Inspect pending through terminal outcomes plus read-only
                  recovery, torn journals, and corrupt journals.
                </Typography>
              </Box>
              <Button
                component={RouterLink}
                to="/states/enforcement/active"
                variant="outlined"
              >
                Open enforcement states
              </Button>
            </Stack>
          </Paper>
        </Grid>
      </Grid>

      <Grid container spacing={3} data-testid="resource-state-visual-grid">
        {PRESENTATION_STATE_ORDER.map((kind) => (
          <Grid key={kind} size={{ xs: 12, lg: 6 }}>
            <PresentationState state={MOCK_PRESENTATION_STATES[kind]} />
          </Grid>
        ))}
      </Grid>
    </Stack>
  );
}
