import { describe, expect, it } from 'vitest';
import { decodeContract } from '../contracts/registry';
import {
  AUDIT_PROVENANCE_KINDS,
  ENFORCEMENT_LIFECYCLE_STATE_NAMES,
} from '../enforcement/enforcementLifecycleModel';
import { MOCK_ENFORCEMENT_LIFECYCLE_STATES } from './enforcementLifecycleFixtures';

function canonicalFixtureJson(value: unknown): string {
  if (
    value === null ||
    typeof value === 'boolean' ||
    typeof value === 'string'
  ) {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') return String(value);
  if (Array.isArray(value)) {
    return `[${value.map(canonicalFixtureJson).join(',')}]`;
  }
  if (typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map(
        (key) =>
          `${JSON.stringify(key)}:${canonicalFixtureJson(Reflect.get(value, key))}`,
      )
      .join(',')}}`;
  }
  throw new Error(`Unsupported fixture value: ${typeof value}`);
}

describe('enforcement lifecycle fixtures', () => {
  it('decodes every frozen lifecycle, result, and audit DTO', () => {
    for (const stateName of ENFORCEMENT_LIFECYCLE_STATE_NAMES) {
      const state = MOCK_ENFORCEMENT_LIFECYCLE_STATES[stateName];
      expect(Object.isFrozen(state), stateName).toBe(true);
      if (state.kind !== 'ready') continue;

      expect(decodeContract(state.view.lifecycle), stateName).toMatchObject({
        ok: true,
      });
      for (const entry of state.view.lifecycle.operations) {
        expect(entry.result?.operation ?? entry.operation).toBe(
          entry.operation,
        );
        if (entry.result) {
          expect(
            decodeContract(entry.result),
            `${stateName} result`,
          ).toMatchObject({ ok: true });
          expect(entry.result.action_id).toBe(state.view.lifecycle.action_id);
          expect(entry.result.target_ipv4).toBe(
            state.view.lifecycle.target_ipv4,
          );
          expect(state.view.resultDigests[entry.result.result_id]).toMatch(
            /^sha256:[0-9a-f]{64}$/,
          );
        }
      }
      for (const audit of state.view.auditTrail) {
        expect(decodeContract(audit.event), `${stateName} audit`).toMatchObject(
          {
            ok: true,
          },
        );
      }
    }
  });

  it('keeps journal records ordered and terminal digests bound to results', () => {
    for (const [stateName, state] of Object.entries(
      MOCK_ENFORCEMENT_LIFECYCLE_STATES,
    )) {
      if (state.kind !== 'ready') continue;
      const sequences = state.view.journal.map((record) => record.sequence);
      expect(sequences, stateName).toEqual(
        [...sequences].sort((left, right) => left - right),
      );
      expect(new Set(sequences).size, stateName).toBe(sequences.length);

      for (const record of state.view.journal) {
        if (record.terminalResultId) {
          expect(record.terminalResultDigest, stateName).toBe(
            state.view.resultDigests[record.terminalResultId],
          );
        } else {
          expect(record.terminalResultDigest, stateName).toBeNull();
        }
      }
    }
  });

  it('binds every displayed result digest to canonical checked fixture bytes', async () => {
    for (const [stateName, state] of Object.entries(
      MOCK_ENFORCEMENT_LIFECYCLE_STATES,
    )) {
      if (state.kind !== 'ready') continue;
      for (const operation of state.view.lifecycle.operations) {
        if (!operation.result) continue;
        const bytes = new TextEncoder().encode(
          canonicalFixtureJson(operation.result),
        );
        const hash = await globalThis.crypto.subtle.digest('SHA-256', bytes);
        const actual = `sha256:${Array.from(new Uint8Array(hash), (byte) =>
          byte.toString(16).padStart(2, '0'),
        ).join('')}`;
        expect(
          state.view.resultDigests[operation.result.result_id],
          stateName,
        ).toBe(actual);
      }
    }
  });

  it('models inspect and recovery as read-only without re-add or TTL refresh', () => {
    const recovered = MOCK_ENFORCEMENT_LIFECYCLE_STATES['recovered-active'];
    expect(recovered.kind).toBe('ready');
    if (recovered.kind !== 'ready') return;

    const inspect = recovered.view.lifecycle.operations.find(
      (entry) => entry.operation === 'inspect',
    );
    expect(inspect).toMatchObject({
      operation: 'inspect',
      signature_verification: 'verified',
      result: {
        operation: 'inspect',
        classification: 'inspect_active',
        nft_exit_class: 'success',
      },
    });
    expect(recovered.view.recovery).toMatchObject({
      mode: 'read-only-inspect',
      automaticReadd: false,
      ttlRefresh: false,
    });
  });

  it('fails closed for torn, corrupt, and indeterminate recovery fixtures', () => {
    for (const stateName of [
      'indeterminate',
      'torn-journal',
      'corrupt-journal',
    ] as const) {
      const state = MOCK_ENFORCEMENT_LIFECYCLE_STATES[stateName];
      expect(state.kind).toBe('ready');
      if (state.kind !== 'ready') continue;
      expect(state.view.lifecycle.state).toBe('indeterminate');
      expect(state.view.recovery).toMatchObject({
        mode: 'halted',
        automaticReadd: false,
        ttlRefresh: false,
      });
    }
  });

  it('preserves every required audit provenance layer', () => {
    const active = MOCK_ENFORCEMENT_LIFECYCLE_STATES.active;
    expect(active.kind).toBe('ready');
    if (active.kind !== 'ready') return;
    const kinds = new Set(
      active.view.auditTrail.map((entry) => entry.provenance),
    );
    for (const kind of AUDIT_PROVENANCE_KINDS) {
      expect(kinds.has(kind), kind).toBe(true);
    }
  });

  it('contains no signature bytes, keys, or serialized capability authority', () => {
    const serialized = JSON.stringify(MOCK_ENFORCEMENT_LIFECYCLE_STATES);
    for (const forbiddenKey of [
      'signature_b64url',
      'private_key',
      'secret_key',
      'capability_jcs_b64url',
      'result_jcs_b64url',
      'signed_request',
    ]) {
      expect(serialized).not.toContain(`"${forbiddenKey}"`);
    }
  });
});
