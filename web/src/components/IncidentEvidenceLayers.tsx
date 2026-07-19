import {
  Box,
  Divider,
  Grid,
  List,
  ListItem,
  Stack,
  Typography,
} from '@mui/material';
import type { AuthBindingState } from '../incidents/incidentDetailModel';
import type { IncidentInvestigationView } from '../incidents/incidentDetailModel';
import { semanticTokens } from '../theme';
import {
  formatUtc,
  humanizeIdentifier,
  shortDigest,
  shortIdentifier,
} from '../utils/presentation';
import { DetailList } from './DetailList';
import { ProvenanceTag } from './ProvenanceTag';
import { StatusBadge, type SemanticTone } from './StatusBadge';

const bindingTone: Readonly<Record<AuthBindingState, SemanticTone>> = {
  pending: 'warning',
  verified: 'positive',
  untrusted: 'critical',
};

function ObservedLayer({ view }: { readonly view: IncidentInvestigationView }) {
  const gateway = view.detail.gateway_events[0];

  return (
    <Box
      component="li"
      aria-labelledby="observed-layer-title"
      sx={{
        px: { xs: 2.25, md: 3 },
        py: { xs: 2.5, md: 3 },
        bgcolor: 'oklch(0.97 0.015 245)',
      }}
    >
      <Stack spacing={2.5}>
        <Box>
          <ProvenanceTag kind="observed" />
          <Typography
            id="observed-layer-title"
            component="h3"
            variant="h2"
            sx={{ mt: 1 }}
          >
            Observed facts
          </Typography>
          <Typography color="text.secondary" sx={{ mt: 0.6 }}>
            Gateway and authenticated application records stay distinct while
            sharing safe request and trace identifiers.
          </Typography>
        </Box>

        {gateway ? (
          <Box component="section" aria-labelledby="gateway-observation-title">
            <Stack
              direction={{ xs: 'column', sm: 'row' }}
              spacing={1.5}
              alignItems={{ xs: 'flex-start', sm: 'center' }}
              justifyContent="space-between"
            >
              <Box>
                <Typography
                  id="gateway-observation-title"
                  component="h4"
                  variant="h3"
                >
                  Gateway observation
                </Typography>
                <Typography
                  variant="body2"
                  color="text.secondary"
                  sx={{ mt: 0.35 }}
                >
                  Client identity comes from the canonical direct TCP peer.
                </Typography>
              </Box>
              <StatusBadge label="Direct-peer provenance" tone="info" />
            </Stack>
            <Box sx={{ mt: 2 }}>
              <DetailList
                items={[
                  { label: 'Canonical source', value: gateway.source_ip },
                  { label: 'Method', value: gateway.method },
                  { label: 'Stored route label', value: gateway.route_label },
                  { label: 'Response status', value: gateway.status_code },
                  { label: 'Service', value: gateway.service_label },
                  { label: 'Latency', value: `${gateway.latency_ms} ms` },
                  {
                    label: 'Request relation',
                    value: shortIdentifier(gateway.request_id),
                  },
                  {
                    label: 'Trace relation',
                    value: shortIdentifier(gateway.trace_id),
                  },
                  { label: 'Observed', value: formatUtc(gateway.started_at) },
                ]}
              />
            </Box>
          </Box>
        ) : (
          <Typography role="status">
            No Gateway observation is present.
          </Typography>
        )}

        <Divider />

        <Box component="section" aria-labelledby="auth-observation-title">
          <Typography id="auth-observation-title" component="h4" variant="h3">
            Authenticated application evidence
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.35 }}>
            Binding state is fixture presentation metadata. The underlying auth
            event remains checked against its root schema.
          </Typography>

          <Stack spacing={2} sx={{ mt: 2 }}>
            {view.authEvidence.map((auth) => (
              <Box key={auth.event.event_id}>
                <Stack
                  direction={{ xs: 'column', sm: 'row' }}
                  spacing={1}
                  alignItems={{ xs: 'flex-start', sm: 'center' }}
                  justifyContent="space-between"
                >
                  <Typography variant="body2" sx={{ fontWeight: 720 }}>
                    {humanizeIdentifier(auth.event.outcome)} authentication
                  </Typography>
                  <StatusBadge
                    label={`Binding ${humanizeIdentifier(auth.bindingState)}`}
                    tone={bindingTone[auth.bindingState]}
                  />
                </Stack>
                <Box sx={{ mt: 1.5 }}>
                  <DetailList
                    items={[
                      { label: 'Service', value: auth.event.service_label },
                      { label: 'Route label', value: auth.event.route_label },
                      { label: 'Source', value: auth.event.source_ip },
                      { label: 'Outcome', value: auth.event.outcome },
                      {
                        label: 'Binding reason',
                        value: humanizeIdentifier(auth.bindingReason),
                      },
                      {
                        label: 'Request relation',
                        value: shortIdentifier(auth.event.gateway_request_id),
                      },
                      {
                        label: 'Trace relation',
                        value: shortIdentifier(auth.event.trace_id),
                      },
                      {
                        label: 'Gateway event relation',
                        value: auth.boundGatewayEventId
                          ? shortIdentifier(auth.boundGatewayEventId)
                          : 'Not bound',
                      },
                      {
                        label: 'Occurred',
                        value: formatUtc(auth.event.occurred_at),
                      },
                    ]}
                  />
                </Box>
              </Box>
            ))}
          </Stack>
        </Box>
      </Stack>
    </Box>
  );
}

function DeterministicLayer({
  view,
}: {
  readonly view: IncidentInvestigationView;
}) {
  return (
    <Box
      component="li"
      aria-labelledby="deterministic-layer-title"
      sx={{
        px: { xs: 2.25, md: 3 },
        py: { xs: 2.5, md: 3 },
        bgcolor: 'oklch(0.97 0.018 155)',
        borderTop: 1,
        borderColor: 'divider',
      }}
    >
      <Stack spacing={2.25}>
        <Box>
          <ProvenanceTag kind="deterministic" />
          <Typography
            id="deterministic-layer-title"
            component="h3"
            variant="h2"
            sx={{ mt: 1 }}
          >
            Deterministic signals
          </Typography>
          <Typography color="text.secondary" sx={{ mt: 0.6 }}>
            Rule results are reproducible facts and do not inherit model
            confidence.
          </Typography>
        </Box>
        <List disablePadding aria-label="Deterministic signals">
          {view.detail.deterministic_signals.map((signal, index) => (
            <ListItem
              key={signal.signal_id}
              disableGutters
              divider={index < view.detail.deterministic_signals.length - 1}
              sx={{ display: 'block', py: 2 }}
            >
              <Stack
                direction={{ xs: 'column', sm: 'row' }}
                spacing={1.5}
                alignItems={{ xs: 'flex-start', sm: 'center' }}
                justifyContent="space-between"
              >
                <Box>
                  <Typography component="h4" variant="h3">
                    {humanizeIdentifier(signal.classification)}
                  </Typography>
                  <Typography
                    variant="body2"
                    color="text.secondary"
                    sx={{ mt: 0.35 }}
                  >
                    {signal.rule_id}, {signal.event_count} retained events
                  </Typography>
                </Box>
                <StatusBadge label="Rule matched" tone="positive" />
              </Stack>
              <Box sx={{ mt: 1.75 }}>
                <DetailList
                  items={[
                    {
                      label: 'Window start',
                      value: formatUtc(signal.window_start),
                    },
                    {
                      label: 'Window end',
                      value: formatUtc(signal.window_end),
                    },
                    { label: 'Event count', value: signal.event_count },
                    {
                      label: 'Distinct accounts',
                      value: signal.distinct_account_count,
                    },
                    {
                      label: 'Suspicious classes',
                      value: signal.distinct_suspicious_path_count,
                    },
                    {
                      label: 'Evidence digest',
                      value: shortDigest(signal.evidence_digest),
                    },
                  ]}
                />
              </Box>
            </ListItem>
          ))}
        </List>
      </Stack>
    </Box>
  );
}

function AnalysisProvenance({
  view,
}: {
  readonly view: IncidentInvestigationView;
}) {
  const provenance = view.analysisProvenance;
  if (!provenance) return null;

  return (
    <Box
      component="section"
      aria-labelledby="analysis-provenance-title"
      sx={{ pt: 2.25, borderTop: 1, borderColor: semanticTokens.info.border }}
    >
      <Typography id="analysis-provenance-title" component="h4" variant="h3">
        Analysis provenance
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.35 }}>
        The profile label is frozen fixture metadata. Digests come from the
        checked validation snapshot, not a live provider response.
      </Typography>
      <Box sx={{ mt: 1.75 }}>
        <DetailList
          items={[
            { label: 'Model profile', value: provenance.model },
            { label: 'Reasoning effort', value: provenance.reasoningEffort },
            { label: 'Input schema', value: provenance.inputSchemaVersion },
            { label: 'Output schema', value: provenance.outputSchemaVersion },
            { label: 'Prompt version', value: provenance.promptVersion },
            {
              label: 'Input digest',
              value: shortDigest(provenance.inputDigest),
            },
            {
              label: 'Output schema digest',
              value: shortDigest(provenance.outputSchemaDigest),
            },
            {
              label: 'Prompt digest',
              value: shortDigest(provenance.promptDigest),
            },
          ]}
        />
      </Box>
    </Box>
  );
}

function AiLayer({ view }: { readonly view: IncidentInvestigationView }) {
  const analysis = view.detail.ai_analysis;

  return (
    <Box
      component="li"
      aria-labelledby="ai-layer-title"
      sx={{
        px: { xs: 2.25, md: 3 },
        py: { xs: 2.5, md: 3 },
        bgcolor: 'oklch(0.97 0.018 305)',
        borderTop: 1,
        borderColor: 'divider',
      }}
    >
      <Stack spacing={2.25}>
        <Box>
          <ProvenanceTag kind="ai" />
          <Typography
            id="ai-layer-title"
            component="h3"
            variant="h2"
            sx={{ mt: 1 }}
          >
            AI interpretation
          </Typography>
          <Typography color="text.secondary" sx={{ mt: 0.6 }}>
            Model output explains the evidence but never rewrites observed or
            deterministic facts.
          </Typography>
        </Box>

        {analysis ? (
          <>
            <Stack
              direction={{ xs: 'column', sm: 'row' }}
              spacing={1.5}
              alignItems={{ xs: 'flex-start', sm: 'center' }}
              justifyContent="space-between"
            >
              <Typography component="h4" variant="h3">
                {humanizeIdentifier(analysis.classification)}
              </Typography>
              <StatusBadge
                label={`${Math.round(analysis.confidence * 100)}% model confidence`}
                tone="info"
              />
            </Stack>
            <Typography>{analysis.incident_summary}</Typography>
            <Grid container spacing={2.5}>
              <Grid size={{ xs: 12, md: 6 }}>
                <Typography component="h4" variant="subtitle1">
                  Uncertainty
                </Typography>
                <Typography sx={{ mt: 0.6 }}>{analysis.uncertainty}</Typography>
              </Grid>
              <Grid size={{ xs: 12, md: 6 }}>
                <Typography component="h4" variant="subtitle1">
                  Possible false positives
                </Typography>
                <List dense disablePadding sx={{ mt: 0.4 }}>
                  {analysis.false_positive_factors.map((factor) => (
                    <ListItem
                      key={factor}
                      disableGutters
                      sx={{ alignItems: 'flex-start', py: 0.35 }}
                    >
                      <Box
                        component="span"
                        aria-hidden="true"
                        sx={{
                          mr: 1,
                          mt: 0.8,
                          width: 5,
                          height: 5,
                          borderRadius: '50%',
                          bgcolor: 'text.secondary',
                          flexShrink: 0,
                        }}
                      />
                      <Typography variant="body2">{factor}</Typography>
                    </ListItem>
                  ))}
                </List>
              </Grid>
            </Grid>
            <AnalysisProvenance view={view} />
          </>
        ) : (
          <Box role="status" aria-live="polite">
            <StatusBadge label="Analysis unavailable" tone="warning" />
            <Typography component="h4" variant="h3" sx={{ mt: 1.5 }}>
              Deterministic evidence remains available
            </Typography>
            <Typography color="text.secondary" sx={{ mt: 0.6 }}>
              No model output is presented for this fixture state. This does not
              weaken source-health or validation requirements.
            </Typography>
          </Box>
        )}
      </Stack>
    </Box>
  );
}

export function IncidentEvidenceLayers({
  view,
}: {
  readonly view: IncidentInvestigationView;
}) {
  return (
    <Box
      component="ol"
      aria-label="Evidence provenance layers"
      sx={{ p: 0, m: 0, listStyle: 'none' }}
    >
      <ObservedLayer view={view} />
      <DeterministicLayer view={view} />
      <AiLayer view={view} />
    </Box>
  );
}
