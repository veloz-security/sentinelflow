import { CssBaseline, ThemeProvider } from '@mui/material';
import { render, screen } from '@testing-library/react';
import type { ReactNode } from 'react';
import { describe, expect, it } from 'vitest';
import { appTheme } from '../theme';
import { ProvenanceTag } from './ProvenanceTag';
import { ReviewControl } from './ReviewControl';
import { StatusBadge } from './StatusBadge';

function renderWithTheme(node: ReactNode) {
  return render(
    <ThemeProvider theme={appTheme}>
      <CssBaseline />
      {node}
    </ThemeProvider>,
  );
}

describe('design-system primitives', () => {
  it('pairs semantic color with a visible state label', () => {
    renderWithTheme(<StatusBadge label="Coverage complete" tone="positive" />);

    expect(screen.getByText('Coverage complete')).toBeVisible();
  });

  it('identifies provenance in text', () => {
    renderWithTheme(<ProvenanceTag kind="deterministic" />);

    expect(screen.getByText('Deterministic')).toBeVisible();
  });

  it('keeps fixture review authority disabled', () => {
    renderWithTheme(<ReviewControl />);

    expect(
      screen.getByRole('button', { name: 'Approve exact artifact' }),
    ).toBeDisabled();
    expect(
      screen.getByText(/cannot issue or consume a HIL challenge/i),
    ).toBeVisible();
  });
});
