import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { ApiClientError } from './apiClient';
import { EmptyState, LiveError, LiveLoading } from './LiveFeedback';

const traceID = '019b0000-0000-4000-8000-000000000201';

function error(status: number, permissionDenied = false): ApiClientError {
  return new ApiClientError(
    status,
    Object.freeze({
      code: permissionDenied ? 'permission_denied' : 'service_unavailable',
      message: permissionDenied
        ? 'this administrator cannot read incidents'
        : 'the management service is unavailable',
      trace_id: traceID,
      details: Object.freeze({}),
    }),
    null,
  );
}

describe('live resource feedback', () => {
  it('announces loading and empty states without inventing data', () => {
    const { unmount } = render(<LiveLoading label="Loading incidents" />);
    expect(
      screen.getByRole('status', { name: 'Loading incidents' }),
    ).toHaveAttribute('aria-busy', 'true');
    unmount();

    render(
      <EmptyState
        title="No incidents on this page"
        detail="No authenticated snapshot matches."
      />,
    );
    expect(screen.getByRole('status')).toHaveTextContent(
      'No incidents on this page',
    );
  });

  it('distinguishes permission denial and exposes a keyboard retry', async () => {
    const retry = vi.fn();
    const user = userEvent.setup();
    render(<LiveError error={error(403, true)} onRetry={retry} />);

    expect(screen.getByRole('alert')).toHaveTextContent('Permission required');
    expect(screen.getByRole('alert')).toHaveTextContent('permission_denied');
    const button = screen.getByRole('button', { name: 'Retry' });
    button.focus();
    await user.keyboard('{Enter}');
    expect(retry).toHaveBeenCalledOnce();
  });

  it('shows the exact server error and trace for other failures', () => {
    render(<LiveError error={error(503)} onRetry={vi.fn()} />);
    expect(screen.getByRole('alert')).toHaveTextContent(
      'the management service is unavailable',
    );
    expect(screen.getByRole('alert')).toHaveTextContent(traceID);
  });
});
