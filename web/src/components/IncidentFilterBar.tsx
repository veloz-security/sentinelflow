import {
  Box,
  Button,
  Grid,
  MenuItem,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import { useState } from 'react';
import { INCIDENT_STATES } from '../contracts/apiDtos';
import { DETECTION_CLASSIFICATIONS } from '../contracts/rootContracts';
import type { IncidentListFilters } from '../incidents/incidentListModel';
import { validateIncidentListFilters } from '../incidents/incidentListSearch';
import { humanizeIdentifier } from '../utils/presentation';

export interface IncidentFilterBarProps {
  readonly filters: IncidentListFilters;
  readonly services: readonly string[];
  readonly onApply: (filters: IncidentListFilters) => void;
  readonly onReset: () => void;
}

function countActiveFilters(filters: IncidentListFilters): number {
  return [
    filters.sourceIp !== '',
    filters.state !== 'all',
    filters.scenario !== 'all',
    filters.service !== '',
    filters.fromUtc !== '',
    filters.toUtc !== '',
  ].filter(Boolean).length;
}

export function IncidentFilterBar({
  filters,
  services,
  onApply,
  onReset,
}: IncidentFilterBarProps) {
  const [draft, setDraft] = useState(filters);

  const validation = validateIncidentListFilters(draft);
  const activeCount = countActiveFilters(filters);

  function update<Key extends keyof IncidentListFilters>(
    key: Key,
    value: IncidentListFilters[Key],
  ) {
    setDraft((current) => ({ ...current, [key]: value }));
  }

  return (
    <Box
      component="form"
      aria-label="Incident filters"
      noValidate
      onSubmit={(event) => {
        event.preventDefault();
        if (validation.valid) onApply(draft);
      }}
    >
      <Stack spacing={2.25}>
        <Stack
          direction={{ xs: 'column', sm: 'row' }}
          spacing={1}
          alignItems={{ xs: 'flex-start', sm: 'baseline' }}
          justifyContent="space-between"
        >
          <Box>
            <Typography component="h2" variant="h3">
              Filter incidents
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 0.4 }}>
              Values are stored in the page URL. Applying a filter resets the
              opaque cursor.
            </Typography>
          </Box>
          <Typography variant="caption" color="text.secondary">
            {activeCount === 0
              ? 'No active filters'
              : `${activeCount} active ${activeCount === 1 ? 'filter' : 'filters'}`}
          </Typography>
        </Stack>

        <Grid container spacing={1.5}>
          <Grid size={{ xs: 12, sm: 6, lg: 2.5 }}>
            <TextField
              fullWidth
              size="small"
              label="Canonical source IPv4"
              name="source"
              autoComplete="off"
              placeholder="203.0.113.20"
              value={draft.sourceIp}
              error={validation.sourceIp !== null}
              helperText={validation.sourceIp ?? 'Exact direct-peer identity'}
              onChange={(event) =>
                update('sourceIp', event.target.value.trim())
              }
            />
          </Grid>
          <Grid size={{ xs: 12, sm: 6, lg: 1.5 }}>
            <TextField
              select
              fullWidth
              size="small"
              label="State"
              name="state"
              value={draft.state}
              onChange={(event) =>
                update(
                  'state',
                  event.target.value as IncidentListFilters['state'],
                )
              }
            >
              <MenuItem value="all">All states</MenuItem>
              {INCIDENT_STATES.map((state) => (
                <MenuItem key={state} value={state}>
                  {humanizeIdentifier(state)}
                </MenuItem>
              ))}
            </TextField>
          </Grid>
          <Grid size={{ xs: 12, sm: 6, lg: 2 }}>
            <TextField
              select
              fullWidth
              size="small"
              label="Scenario"
              name="scenario"
              value={draft.scenario}
              onChange={(event) =>
                update(
                  'scenario',
                  event.target.value as IncidentListFilters['scenario'],
                )
              }
            >
              <MenuItem value="all">All scenarios</MenuItem>
              {DETECTION_CLASSIFICATIONS.map((scenario) => (
                <MenuItem key={scenario} value={scenario}>
                  {humanizeIdentifier(scenario)}
                </MenuItem>
              ))}
            </TextField>
          </Grid>
          <Grid size={{ xs: 12, sm: 6, lg: 2 }}>
            <TextField
              select
              fullWidth
              size="small"
              label="Service"
              name="service"
              value={draft.service}
              error={validation.service !== null}
              helperText={validation.service ?? 'Allowlisted service label'}
              onChange={(event) => update('service', event.target.value)}
            >
              <MenuItem value="">All services</MenuItem>
              {services.map((service) => (
                <MenuItem key={service} value={service}>
                  {service}
                </MenuItem>
              ))}
            </TextField>
          </Grid>
          <Grid size={{ xs: 12, sm: 6, lg: 2 }}>
            <TextField
              fullWidth
              size="small"
              type="datetime-local"
              label="From (UTC)"
              name="from"
              value={draft.fromUtc}
              error={validation.time !== null}
              slotProps={{ inputLabel: { shrink: true } }}
              onChange={(event) => update('fromUtc', event.target.value)}
            />
          </Grid>
          <Grid size={{ xs: 12, sm: 6, lg: 2 }}>
            <TextField
              fullWidth
              size="small"
              type="datetime-local"
              label="To (UTC)"
              name="to"
              value={draft.toUtc}
              error={validation.time !== null}
              helperText={validation.time}
              slotProps={{ inputLabel: { shrink: true } }}
              onChange={(event) => update('toUtc', event.target.value)}
            />
          </Grid>
        </Grid>

        <Stack direction="row" spacing={1} justifyContent="flex-end">
          <Button type="button" variant="text" onClick={onReset}>
            Reset
          </Button>
          <Button
            type="submit"
            variant="contained"
            disabled={!validation.valid}
          >
            Apply filters
          </Button>
        </Stack>
      </Stack>
    </Box>
  );
}
