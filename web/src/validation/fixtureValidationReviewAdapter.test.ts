import { describe, expect, it } from 'vitest';
import { decodeContract } from '../contracts/registry';
import { MOCK_POLICY } from '../mocks/contractFixtures';
import {
  MOCK_READY_VALIDATION_REVIEW,
  MOCK_REVIEW_ANALYSIS,
  MOCK_REVIEW_VALIDATION,
  MOCK_SIGNED_DEMO_HISTORY_FIXTURE,
  MOCK_VALIDATION_REVIEW_STATES,
  VALIDATION_REVIEW_STATE_NAMES,
} from '../mocks/validationReviewFixtures';
import { VALIDATION_REVIEW_GATE_IDS } from './validationReviewModel';
import { fixtureValidationReviewAdapter } from './fixtureValidationReviewAdapter';

const forbiddenPresentationKeys = new Set([
  'path',
  'raw_path',
  'decoded_path',
  'exact_path',
  'query',
  'query_string',
  'body',
  'request_body',
  'response_body',
  'cookie',
  'cookies',
  'authorization',
  'headers',
  'raw_headers',
  'private_key',
  'private_key_b64url',
  'signature',
  'signature_b64url',
  'public_key',
  'public_key_b64url',
]);

const forbiddenPresentationValues = [
  /^\/(?!\/)/,
  /(?:\?|&)[a-z0-9_.~-]+=/i,
  /\bbearer\s+[a-z0-9._~-]+/i,
  /authorization\s*:/i,
  /cookie\s*:/i,
  /-----begin (?:private|public) key-----/i,
] as const;

function expectSafePresentation(value: unknown): void {
  if (typeof value === 'string') {
    for (const pattern of forbiddenPresentationValues) {
      expect(
        pattern.test(value),
        `forbidden presentation value: ${value}`,
      ).toBe(false);
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach(expectSafePresentation);
    return;
  }
  if (typeof value !== 'object' || value === null) return;

  for (const [key, child] of Object.entries(value)) {
    expect(
      forbiddenPresentationKeys.has(key.toLowerCase()),
      `forbidden presentation key: ${key}`,
    ).toBe(false);
    expectSafePresentation(child);
  }
}

describe('fixture validation review adapter', () => {
  it('resolves the frozen ready state and honors abort', async () => {
    await expect(fixtureValidationReviewAdapter.load()).resolves.toEqual(
      MOCK_VALIDATION_REVIEW_STATES.ready,
    );

    const controller = new AbortController();
    controller.abort();
    await expect(
      fixtureValidationReviewAdapter.load(controller.signal),
    ).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('keeps every root-owned input on its checked contract boundary', () => {
    for (const fixture of [
      MOCK_REVIEW_ANALYSIS,
      MOCK_POLICY,
      MOCK_REVIEW_VALIDATION,
      MOCK_SIGNED_DEMO_HISTORY_FIXTURE.manifest,
      MOCK_SIGNED_DEMO_HISTORY_FIXTURE,
    ]) {
      expect(decodeContract(fixture)).toMatchObject({ ok: true });
    }
  });

  it('groups six root checks into exactly five presentation gates in order', () => {
    expect(MOCK_REVIEW_VALIDATION.checks).toHaveLength(6);
    expect(MOCK_READY_VALIDATION_REVIEW.gates).toHaveLength(5);
    expect(MOCK_READY_VALIDATION_REVIEW.gates.map((gate) => gate.id)).toEqual(
      VALIDATION_REVIEW_GATE_IDS,
    );
    expect(MOCK_READY_VALIDATION_REVIEW.gates[0].sourceCheckIds).toEqual([
      'structured_output',
      'command_grammar',
    ]);
    expect(MOCK_READY_VALIDATION_REVIEW.gates[1].sourceCheckIds).toEqual([
      'policy_evidence_command_consistency',
    ]);
    expect(MOCK_READY_VALIDATION_REVIEW.gates[2].sourceCheckIds).toEqual([
      'protected_network',
    ]);
  });

  it('makes integer, generated, and canonical TTL equality explicit', () => {
    const command = MOCK_READY_VALIDATION_REVIEW.command;

    expect(command).toMatchObject({
      renderMode: 'inert-text',
      policyTtlSeconds: 1800,
      generatedTimeoutToken: '1800s',
      generatedParsedSeconds: 1800,
      canonicalTimeoutToken: '30m',
      canonicalParsedSeconds: 1800,
      ttlEquality: 'equal',
    });
    expect(command.canonicalCommand.endsWith('\n')).toBe(true);
  });

  it('never puts signature bytes, key material, or request content in a review view', () => {
    for (const stateName of VALIDATION_REVIEW_STATE_NAMES) {
      const state = MOCK_VALIDATION_REVIEW_STATES[stateName];
      if ('view' in state) expectSafePresentation(state.view);
    }
  });

  it('keeps every unsafe state fail-closed and HIL unavailable', () => {
    for (const stateName of VALIDATION_REVIEW_STATE_NAMES) {
      const state = MOCK_VALIDATION_REVIEW_STATES[stateName];
      if (!('view' in state)) continue;

      expect(state.view.hilControls).toBe('not-implemented');
      if (state.kind === 'ready') {
        expect(state.view.gates.every((gate) => gate.outcome === 'pass')).toBe(
          true,
        );
        expect(state.view.validity.status).toBe('fresh');
        continue;
      }
      expect(
        state.view.gates.some((gate) => gate.outcome !== 'pass') ||
          state.view.validity.status !== 'fresh',
      ).toBe(true);
    }
  });

  it('deep-freezes review state and nested proof data', () => {
    expect(Object.isFrozen(MOCK_VALIDATION_REVIEW_STATES)).toBe(true);
    expect(Object.isFrozen(MOCK_READY_VALIDATION_REVIEW)).toBe(true);
    expect(Object.isFrozen(MOCK_READY_VALIDATION_REVIEW.gates)).toBe(true);
    expect(Object.isFrozen(MOCK_READY_VALIDATION_REVIEW.demoHistory)).toBe(
      true,
    );
  });
});
