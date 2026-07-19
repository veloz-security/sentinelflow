import {
  Box,
  Button,
  Divider,
  Grid,
  List,
  ListItem,
  ListItemText,
  Paper,
  Stack,
  Typography,
} from '@mui/material';
import { Link as RouterLink } from 'react-router-dom';
import { DetailList } from '../components/DetailList';
import { PageHeader } from '../components/PageHeader';
import { ProvenanceTag } from '../components/ProvenanceTag';
import { ReviewControl } from '../components/ReviewControl';
import { SectionHeading } from '../components/SectionHeading';
import { StatusBadge } from '../components/StatusBadge';
import {
  MOCK_INCIDENT_SUMMARY,
  MOCK_SOURCE_HEALTH,
  MOCK_VALIDATION,
} from '../mocks/contractFixtures';
import {
  formatUtc,
  humanizeIdentifier,
  shortDigest,
} from '../utils/presentation';

const overviewValidationResults = [
  {
    label: 'Schema, grammar, and canonicalization',
    digest: MOCK_VALIDATION.checks[1]!.input_digest,
  },
  {
    label: 'Policy, evidence, and command consistency',
    digest: MOCK_VALIDATION.checks[2]!.input_digest,
  },
  {
    label: 'Protected target',
    digest: MOCK_VALIDATION.checks[3]!.input_digest,
  },
  {
    label: 'nft syntax and owned schema',
    digest: MOCK_VALIDATION.checks[4]!.input_digest,
  },
  {
    label: 'Historical impact',
    digest: MOCK_VALIDATION.checks[5]!.input_digest,
  },
] as const;

export function OverviewPage() {
  return (
    <Stack spacing={{ xs: 4, md: 5 }}>
      <PageHeader
        eyebrow="Operations snapshot"
        title="Review queue"
        description="A typed, synthetic incident is staged to demonstrate information hierarchy. No live service, administrator session, or executor is connected."
        status={<StatusBadge label="1 fixture incident" tone="info" />}
      />

      <Grid container spacing={3}>
        <Grid size={{ xs: 12, lg: 8 }}>
          <Paper
            component="section"
            variant="outlined"
            aria-labelledby="focus-incident-title"
            sx={{ p: { xs: 2.5, md: 3.5 }, height: '100%' }}
          >
            <Stack spacing={3}>
              <SectionHeading
                id="focus-incident-title"
                eyebrow="Focus incident"
                title="Failed login activity requires review"
                description="Observed metadata, a deterministic signal, and AI interpretation remain separate in the investigation view."
                action={
                  <Button
                    component={RouterLink}
                    to={`/incidents/${MOCK_INCIDENT_SUMMARY.incident_id}`}
                    variant="outlined"
                  >
                    Open investigation
                  </Button>
                }
              />

              <DetailList
                items={[
                  {
                    label: 'State',
                    value: <StatusBadge label="Review ready" tone="warning" />,
                  },
                  {
                    label: 'Service',
                    value: MOCK_INCIDENT_SUMMARY.service_label,
                  },
                  {
                    label: 'Documentation source',
                    value: MOCK_INCIDENT_SUMMARY.source_ip,
                  },
                  {
                    label: 'Deterministic signals',
                    value: MOCK_INCIDENT_SUMMARY.signal_count,
                  },
                  {
                    label: 'First observed',
                    value: formatUtc(MOCK_INCIDENT_SUMMARY.first_seen_at),
                  },
                  {
                    label: 'Last update',
                    value: formatUtc(MOCK_INCIDENT_SUMMARY.updated_at),
                  },
                ]}
              />

              <Divider />

              <Stack
                direction={{ xs: 'column', sm: 'row' }}
                spacing={{ xs: 1.25, sm: 3 }}
                aria-label="Investigation provenance"
              >
                <ProvenanceTag kind="observed" />
                <ProvenanceTag kind="deterministic" />
                <ProvenanceTag kind="ai" />
                <ProvenanceTag kind="human" />
                <ProvenanceTag kind="enforcement" />
              </Stack>
            </Stack>
          </Paper>
        </Grid>

        <Grid size={{ xs: 12, lg: 4 }}>
          <Stack spacing={3} sx={{ height: '100%' }}>
            <Paper
              component="section"
              variant="outlined"
              aria-labelledby="source-coverage-title"
              sx={{ p: 2.5, flex: 1 }}
            >
              <Stack spacing={2}>
                <Stack
                  direction="row"
                  justifyContent="space-between"
                  alignItems="center"
                >
                  <Typography
                    id="source-coverage-title"
                    component="h2"
                    variant="h3"
                  >
                    Source coverage
                  </Typography>
                  <StatusBadge label="Recovered" tone="positive" />
                </Stack>
                <Typography variant="body2" color="text.secondary">
                  The fixture marks its source-health interval as recovered with
                  no dropped records.
                </Typography>
                <DetailList
                  items={[
                    { label: 'Source', value: MOCK_SOURCE_HEALTH.source_id },
                    {
                      label: 'Detail',
                      value: humanizeIdentifier(MOCK_SOURCE_HEALTH.detail_code),
                    },
                    {
                      label: 'Dropped',
                      value: MOCK_SOURCE_HEALTH.dropped_count,
                    },
                    {
                      label: 'Recorded',
                      value: formatUtc(MOCK_SOURCE_HEALTH.occurred_at),
                    },
                  ]}
                />
              </Stack>
            </Paper>

            <Paper
              component="section"
              variant="outlined"
              aria-labelledby="lifecycle-summary-title"
              sx={{ p: 2.5, flex: 1 }}
            >
              <Stack spacing={2}>
                <Stack
                  direction="row"
                  justifyContent="space-between"
                  alignItems="center"
                >
                  <Typography
                    id="lifecycle-summary-title"
                    component="h2"
                    variant="h3"
                  >
                    Lifecycle fixture
                  </Typography>
                  <StatusBadge label="Revoked" tone="neutral" />
                </Stack>
                <Typography variant="body2" color="text.secondary">
                  Signed add, read-only inspect, and revoke results are present
                  for layout testing.
                </Typography>
                <Button
                  component={RouterLink}
                  to="/fixtures/enforcement"
                  variant="text"
                  sx={{ alignSelf: 'flex-start' }}
                >
                  Inspect lifecycle
                </Button>
              </Stack>
            </Paper>
          </Stack>
        </Grid>
      </Grid>

      <Box component="section" aria-labelledby="validation-readiness-title">
        <Stack spacing={2.5}>
          <SectionHeading
            id="validation-readiness-title"
            eyebrow="Ordered safety evidence"
            title="Validation readiness"
            description="The UI preserves server order and displays the immutable snapshot without deriving approval eligibility."
            action={
              <StatusBadge
                label={`Valid until ${formatUtc(MOCK_VALIDATION.valid_until)}`}
                tone="positive"
              />
            }
          />

          <Grid container spacing={3}>
            <Grid size={{ xs: 12, lg: 8 }}>
              <Paper variant="outlined" sx={{ overflow: 'hidden' }}>
                <List disablePadding aria-label="Ordered validation checks">
                  {overviewValidationResults.map((check, index) => (
                    <ListItem
                      key={check.label}
                      divider={index < overviewValidationResults.length - 1}
                      sx={{ px: { xs: 2, md: 3 }, py: 1.5, gap: 2 }}
                    >
                      <Typography
                        aria-hidden="true"
                        variant="caption"
                        sx={{
                          display: 'grid',
                          placeItems: 'center',
                          width: 26,
                          height: 26,
                          borderRadius: '50%',
                          bgcolor: 'action.selected',
                          color: 'primary.dark',
                          fontWeight: 780,
                          flexShrink: 0,
                        }}
                      >
                        {index + 1}
                      </Typography>
                      <ListItemText
                        primary={check.label}
                        secondary={shortDigest(check.digest)}
                        primaryTypographyProps={{
                          variant: 'body2',
                          fontWeight: 690,
                        }}
                        secondaryTypographyProps={{
                          variant: 'caption',
                          fontFamily: 'monospace',
                        }}
                      />
                      <StatusBadge label="Pass" tone="positive" />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid size={{ xs: 12, lg: 4 }}>
              <ReviewControl />
            </Grid>
          </Grid>
        </Stack>
      </Box>

      <Typography variant="caption" color="text.secondary">
        Boundary: root schemas plus frontend DTO v1 registry. Validation digest{' '}
        <Box component="span" sx={{ fontFamily: 'monospace' }}>
          {shortDigest(MOCK_VALIDATION.canonical_artifact_digest)}
        </Box>
        .
      </Typography>
    </Stack>
  );
}
