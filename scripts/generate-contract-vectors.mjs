#!/usr/bin/env node

import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = resolve(fileURLToPath(new URL(".", import.meta.url)));
const repoRoot = resolve(scriptDir, "..");
const contractsRoot = join(repoRoot, "contracts");
const vectorPath = join(contractsRoot, "vectors", "contract_vectors_v1.json");
const demoManifestPath = join(
  contractsRoot,
  "fixtures",
  "demo_history_manifest_v1.json",
);
const analysisSummarySchemaPath = join(
  contractsRoot,
  "api",
  "analysis_summary_v1.schema.json",
);
const demoHistoryPublicAssertionsSchemaPath = join(
  contractsRoot,
  "enforcement",
  "demo_history_public_assertions_v1.schema.json",
);

const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
const utf8 = (value) => Buffer.from(value, "utf8");
const b64url = (value) => Buffer.from(value).toString("base64url");
const sha256Bytes = (value) => createHash("sha256").update(value).digest();
const sha256 = (value) => `sha256:${sha256Bytes(value).toString("hex")}`;

function canonicalize(value) {
  if (value === null || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      throw new Error(`Fixture JCS permits only safe non-negative/positive integers, got ${value}`);
    }
    return String(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
      .join(",")}}`;
  }
  throw new Error(`Unsupported JCS value type: ${typeof value}`);
}

function jcsBytes(value) {
  return utf8(canonicalize(value));
}

function ed25519Key(seedHex) {
  const seed = Buffer.from(seedHex, "hex");
  if (seed.length !== 32) {
    throw new Error("Ed25519 fixture seed must be exactly 32 bytes");
  }
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const privateKey = createPrivateKey({
    key: Buffer.concat([pkcs8Prefix, seed]),
    format: "der",
    type: "pkcs8",
  });
  const publicDer = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const publicKey = createPublicKey(privateKey);
  return {
    privateKey,
    publicKey,
    publicKeyRaw: publicDer.subarray(-32),
  };
}

const fixtureSeeds = {
  dispatcher:
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  executorResult:
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  demoHistory:
    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
};

const dispatcherKey = ed25519Key(fixtureSeeds.dispatcher);
const executorResultKey = ed25519Key(fixtureSeeds.executorResult);
const demoHistoryKey = ed25519Key(fixtureSeeds.demoHistory);

function signedVector(vectorName, payload, domain, key) {
  const canonicalBytes = jcsBytes(payload);
  const digestBytes = sha256Bytes(canonicalBytes);
  const signingInput = Buffer.concat([utf8(`${domain}\n`), digestBytes]);
  const signature = sign(null, signingInput, key.privateKey);
  const negativeSigningInput = Buffer.from(signingInput);
  negativeSigningInput[negativeSigningInput.length - 1] ^= 1;
  if (!verify(null, signingInput, key.publicKey, signature)) {
    throw new Error(`${vectorName}: generated Ed25519 signature did not verify`);
  }
  if (verify(null, negativeSigningInput, key.publicKey, signature)) {
    throw new Error(`${vectorName}: mutated Ed25519 signing input unexpectedly verified`);
  }
  return {
    vector_name: vectorName,
    payload,
    jcs_b64url: b64url(canonicalBytes),
    digest: `sha256:${digestBytes.toString("hex")}`,
    signing_input_b64url: b64url(signingInput),
    signature_b64url: b64url(signature),
    expected_valid: true,
    negative_verification: {
      mutation: "xor final signing-input byte with 0x01",
      signing_input_b64url: b64url(negativeSigningInput),
      signature_b64url: b64url(signature),
      expected_valid: false,
    },
  };
}

function digestLabel(label) {
  return sha256(utf8(`sentinelflow fixture ${label}\n`));
}

function uuid(suffix) {
  return `019b0000-0000-7000-8000-${suffix.padStart(12, "0")}`;
}

function lengthPrefixedFrame(payloadBytes) {
  if (payloadBytes.length > 16384) {
    throw new Error(`UDS fixture payload exceeds 16 KiB: ${payloadBytes.length}`);
  }
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(payloadBytes.length, 0);
  return Buffer.concat([prefix, payloadBytes]);
}

function listFiles(directory) {
  return readdirSync(directory)
    .sort()
    .flatMap((name) => {
      const path = join(directory, name);
      return statSync(path).isDirectory() ? listFiles(path) : [path];
    });
}

function assertStrictSchemaNode(node, path) {
  if (Array.isArray(node)) {
    node.forEach((item, index) => assertStrictSchemaNode(item, `${path}[${index}]`));
    return;
  }
  if (node === null || typeof node !== "object") {
    return;
  }
  if (node.uniqueItems !== undefined) {
    throw new Error(`${path}: uniqueItems is forbidden in the contract pack`);
  }
  if (node.type === "object") {
    if (node.additionalProperties !== false) {
      throw new Error(`${path}: object schema must set additionalProperties=false`);
    }
    const propertyNames = Object.keys(node.properties ?? {}).sort();
    const requiredNames = [...(node.required ?? [])].sort();
    if (JSON.stringify(propertyNames) !== JSON.stringify(requiredNames)) {
      throw new Error(`${path}: required must contain every and only declared property`);
    }
  }
  for (const [key, value] of Object.entries(node)) {
    assertStrictSchemaNode(value, `${path}.${key}`);
  }
}

function verifyContractJson() {
  for (const path of listFiles(contractsRoot).filter((item) => item.endsWith(".json"))) {
    const parsed = readJson(path);
    if (path.endsWith(".schema.json")) {
      assertStrictSchemaNode(parsed, relative(repoRoot, path));
    }
  }
}

function buildSchemaBundle() {
  const schemas = listFiles(contractsRoot)
    .filter((path) => path.endsWith(".schema.json"))
    .map((path) => {
      const raw = readFileSync(path);
      const parsed = JSON.parse(raw.toString("utf8"));
      return {
        path: relative(repoRoot, path),
        raw_sha256: sha256(raw),
        jcs_sha256: sha256(jcsBytes(parsed)),
      };
    });
  const content = {
    schema_version: "sentinelflow-contract-schema-bundle-v1",
    schemas,
  };
  return {
    ...content,
    bundle_digest: sha256(jcsBytes(content)),
  };
}

function validationCase(caseId, payload, expectedValid, expectedError = "none", extra = {}) {
  const canonicalBytes = jcsBytes(payload);
  return {
    case_id: caseId,
    payload,
    payload_jcs_b64url: b64url(canonicalBytes),
    payload_digest: sha256(canonicalBytes),
    expected_valid: expectedValid,
    expected_error: expectedError,
    ...extra,
  };
}

function signatureVerificationDigest(runScope, publicKey, manifestDigest, signature) {
  return sha256(jcsBytes({
    domain: "sentinelflow demo-history-v1",
    manifest_digest: manifestDigest,
    public_key_digest: sha256(publicKey),
    run_scope_digest: sha256(utf8(runScope)),
    schema_version: "demo-history-signature-verification-v1",
    signature_digest: sha256(signature),
  }));
}

function buildBundle() {
  verifyContractJson();

  const nftBaseRaw = readFileSync(
    join(contractsRoot, "enforcement", "nft_base_chain_v1.nft"),
  );
  const nftBaseLive = readJson(
    join(contractsRoot, "enforcement", "nft_base_chain_v1.live.json"),
  );
  const protectedIpv4 = readJson(
    join(contractsRoot, "enforcement", "protected_ipv4_v1.json"),
  );
  const demoDataset = readJson(
    join(contractsRoot, "fixtures", "demo_history_dataset_v1.json"),
  );

  if (protectedIpv4.entries.length !== 26) {
    throw new Error("protected_ipv4_v1.json must retain all 26 registry/policy entries");
  }
  const demoExceptions = protectedIpv4.entries.filter(
    (entry) => entry.demo_exception_allowed,
  );
  if (
    JSON.stringify(demoExceptions.map((entry) => entry.entry_id)) !==
    JSON.stringify(["test_net_1", "test_net_2", "test_net_3"])
  ) {
    throw new Error("Only the three RFC 5737 entries may permit the demo exception");
  }
  if (demoDataset.records.some((record) => "path" in record || "query" in record)) {
    throw new Error("Demo history records may not contain exact paths or queries");
  }
  if (
    Date.parse(demoDataset.coverage_end) - Date.parse(demoDataset.coverage_start) !==
    24 * 60 * 60 * 1000
  ) {
    throw new Error("Demo history coverage must be exactly 24 hours");
  }

  const nftBaseLiveJcs = jcsBytes(nftBaseLive);
  const protectedIpv4Jcs = jcsBytes(protectedIpv4);
  const datasetJcs = jcsBytes(demoDataset);
  const sourceHealthJcs = jcsBytes(demoDataset.source_health);
  const ownedSchemaDigest = sha256(nftBaseLiveJcs);

  const addArtifact = utf8(
    "add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }\n",
  );
  const revokeArtifact = utf8(
    "delete element inet sentinelflow blacklist_ipv4 { 203.0.113.20 }\n",
  );
  const addArtifactDigest = sha256(addArtifact);
  const revokeArtifactDigest = sha256(revokeArtifact);
  const inspectArtifactObject = {
    schema_version: "nft-inspect-v1",
    operation: "inspect",
    action_id: uuid("200"),
    target_ipv4: "203.0.113.20",
    original_add_digest: addArtifactDigest,
    owned_schema_digest: ownedSchemaDigest,
    purpose: "reconciliation",
  };
  const inspectArtifact = jcsBytes(inspectArtifactObject);
  const addAuthorizationDigest = digestLabel("add authorization");
  const inspectionAuthorization = {
    schema_version: "inspection-authorization-v1",
    authorization_id: uuid("232"),
    purpose: "reconciliation",
    action_id: uuid("200"),
    policy_id: uuid("201"),
    policy_version: 1,
    target_ipv4: "203.0.113.20",
    original_add_digest: addArtifactDigest,
    original_authorization_digest: addAuthorizationDigest,
    evidence_snapshot_digest: digestLabel("evidence snapshot"),
    validation_snapshot_digest: digestLabel("validation snapshot"),
    artifact_digest: sha256(inspectArtifact),
    owned_schema_digest: ownedSchemaDigest,
    scheduler_id: "reconciler",
    requested_at: "2026-07-18T02:20:00.000Z",
    valid_until: "2026-07-18T02:21:00.000Z",
    idempotency_key_digest: digestLabel("inspect idempotency"),
  };
  const inspectionAuthorizationJcs = jcsBytes(inspectionAuthorization);
  const inspectionAuthorizationDigest = sha256(inspectionAuthorizationJcs);

  const commonCapability = {
    schema_version: "execution-capability-v1",
    action_id: uuid("200"),
    policy_id: uuid("201"),
    policy_version: 1,
    target_ipv4: "203.0.113.20",
    evidence_snapshot_digest: digestLabel("evidence snapshot"),
    validation_snapshot_digest: digestLabel("validation snapshot"),
    owned_schema_digest: ownedSchemaDigest,
  };
  const capabilities = {
    add: {
      ...commonCapability,
      capability_id: uuid("210"),
      operation: "add",
      job_id: uuid("211"),
      artifact_digest: addArtifactDigest,
      original_add_digest: null,
      authorization_digest: addAuthorizationDigest,
      actor_id: "admin-demo",
      reason_digest: digestLabel("threat confirmed"),
      issued_at: "2026-07-18T02:00:05.000Z",
      not_before: "2026-07-18T02:00:05.000Z",
      expires_at: "2026-07-18T02:01:05.000Z",
      nonce: "AAECAwQFBgcICQoLDA0ODw",
    },
    revoke: {
      ...commonCapability,
      capability_id: uuid("220"),
      operation: "revoke",
      job_id: uuid("221"),
      artifact_digest: revokeArtifactDigest,
      original_add_digest: addArtifactDigest,
      authorization_digest: digestLabel("revoke authorization"),
      actor_id: "admin-demo",
      reason_digest: digestLabel("operator revoke"),
      issued_at: "2026-07-18T02:10:00.000Z",
      not_before: "2026-07-18T02:10:00.000Z",
      expires_at: "2026-07-18T02:11:00.000Z",
      nonce: "EBESExQVFhcYGRobHB0eHw",
    },
    inspect: {
      ...commonCapability,
      capability_id: uuid("230"),
      operation: "inspect",
      job_id: uuid("231"),
      artifact_digest: sha256(inspectArtifact),
      original_add_digest: addArtifactDigest,
      authorization_digest: inspectionAuthorizationDigest,
      actor_id: "reconciler",
      reason_digest: digestLabel("reconciliation"),
      issued_at: "2026-07-18T02:20:00.000Z",
      not_before: "2026-07-18T02:20:00.000Z",
      expires_at: "2026-07-18T02:21:00.000Z",
      nonce: "ICEiIyQlJicoKSorLC0uLw",
    },
  };

  const capabilityVectors = {
    add: signedVector(
      "capability-add-v1",
      capabilities.add,
      "sentinelflow execution-capability-v1",
      dispatcherKey,
    ),
    revoke: signedVector(
      "capability-revoke-v1",
      capabilities.revoke,
      "sentinelflow execution-capability-v1",
      dispatcherKey,
    ),
    inspect: signedVector(
      "capability-inspect-v1",
      capabilities.inspect,
      "sentinelflow execution-capability-v1",
      dispatcherKey,
    ),
  };

  const resultPayload = ({
    suffix,
    capability,
    capabilityVector,
    operation,
    artifactDigest,
    classification,
    nftExitClass,
    readbackState,
    elementHandle,
    remainingTtlSeconds,
    startedAt,
    completedAt,
    journalSequence,
  }) => ({
    schema_version: "execution-result-v1",
    result_id: uuid(suffix),
    capability_id: capability.capability_id,
    capability_digest: capabilityVector.digest,
    operation,
    action_id: capability.action_id,
    artifact_digest: artifactDigest,
    target_ipv4: capability.target_ipv4,
    classification,
    nft_exit_class: nftExitClass,
    readback_state: readbackState,
    element_handle: elementHandle,
    remaining_ttl_seconds: remainingTtlSeconds,
    owned_schema_digest: ownedSchemaDigest,
    started_at: startedAt,
    completed_at: completedAt,
    journal_sequence: journalSequence,
    error_code: "none",
  });

  const results = {
    applied: signedVector(
      "execution-result-applied-v1",
      resultPayload({
        suffix: "310",
        capability: capabilities.add,
        capabilityVector: capabilityVectors.add,
        operation: "add",
        artifactDigest: addArtifactDigest,
        classification: "applied",
        nftExitClass: "success",
        readbackState: "active",
        elementHandle: null,
        remainingTtlSeconds: 1799,
        startedAt: "2026-07-18T02:00:06.000Z",
        completedAt: "2026-07-18T02:00:06.050Z",
        journalSequence: 2,
      }),
      "sentinelflow execution-result-v1",
      executorResultKey,
    ),
    recoveredActive: signedVector(
      "execution-result-recovered-active-v1",
      resultPayload({
        suffix: "311",
        capability: capabilities.add,
        capabilityVector: capabilityVectors.add,
        operation: "add",
        artifactDigest: addArtifactDigest,
        classification: "recovered_active",
        nftExitClass: "not_invoked",
        readbackState: "active",
        elementHandle: null,
        remainingTtlSeconds: 1700,
        startedAt: "2026-07-18T02:01:45.000Z",
        completedAt: "2026-07-18T02:01:45.020Z",
        journalSequence: 3,
      }),
      "sentinelflow execution-result-v1",
      executorResultKey,
    ),
    revoked: signedVector(
      "execution-result-revoked-v1",
      resultPayload({
        suffix: "320",
        capability: capabilities.revoke,
        capabilityVector: capabilityVectors.revoke,
        operation: "revoke",
        artifactDigest: revokeArtifactDigest,
        classification: "revoked",
        nftExitClass: "success",
        readbackState: "absent",
        elementHandle: null,
        remainingTtlSeconds: null,
        startedAt: "2026-07-18T02:10:01.000Z",
        completedAt: "2026-07-18T02:10:01.040Z",
        journalSequence: 5,
      }),
      "sentinelflow execution-result-v1",
      executorResultKey,
    ),
    inspectAbsent: signedVector(
      "execution-result-inspect-absent-v1",
      resultPayload({
        suffix: "330",
        capability: capabilities.inspect,
        capabilityVector: capabilityVectors.inspect,
        operation: "inspect",
        artifactDigest: sha256(inspectArtifact),
        classification: "inspect_absent",
        nftExitClass: "success",
        readbackState: "absent",
        elementHandle: null,
        remainingTtlSeconds: null,
        startedAt: "2026-07-18T02:20:01.000Z",
        completedAt: "2026-07-18T02:20:01.010Z",
        journalSequence: 7,
      }),
      "sentinelflow execution-result-v1",
      executorResultKey,
    ),
  };

  const gatewayEventBatch = {
    schema_version: "event-batch-v1",
    sender_id: "gateway-demo",
    sender_epoch: "IiIiIiIiIiIiIiIiIiIiIg",
    batch_id: uuid("400"),
    sequence: 1,
    sent_at: "2026-07-17T03:00:00.010Z",
    records: [demoDataset.records[0]],
  };
  const authEventBatch = {
    schema_version: "event-batch-v1",
    sender_id: "auth-demo",
    sender_epoch: "EREREREREREREREREREREQ",
    batch_id: uuid("401"),
    sequence: 1,
    sent_at: "2026-07-17T03:00:00.010Z",
    records: [demoDataset.records[1]],
  };
  const gatewayHmacKey = Buffer.from(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "hex",
  );
  const authHmacKey = Buffer.from(
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    "hex",
  );
  const buildEventHmacCase = ({
    caseId,
    endpointPath,
    batch,
    timestamp,
    nonce,
    key,
  }) => {
    const rawBody = jcsBytes(batch);
    const rawBodyHashHex = sha256Bytes(rawBody).toString("hex");
    const hmacInput = utf8(
      `${endpointPath}\n${batch.sender_id}\n${timestamp}\n${nonce}\n${rawBodyHashHex}`,
    );
    const signatureHex = createHmac("sha256", key)
      .update(hmacInput)
      .digest("hex");
    return {
      case_id: caseId,
      endpoint_path: endpointPath,
      key_base64: key.toString("base64"),
      headers: {
        "X-Sentinel-Sender-ID": batch.sender_id,
        "X-Sentinel-Timestamp": timestamp,
        "X-Sentinel-Nonce": nonce,
        "X-Sentinel-Signature": signatureHex,
      },
      raw_body_b64url: b64url(rawBody),
      raw_body_sha256: `sha256:${rawBodyHashHex}`,
      hmac_input_b64url: b64url(hmacInput),
      signature_hex: signatureHex,
      expected_valid: true,
    };
  };
  const gatewayHmacCase = buildEventHmacCase({
    caseId: "gateway-endpoint-positive",
    endpointPath: "/internal/v1/gateway-events",
    batch: gatewayEventBatch,
    timestamp: "1784257200",
    nonce: "AAECAwQFBgcICQoLDA0ODw",
    key: gatewayHmacKey,
  });
  const authHmacCase = buildEventHmacCase({
    caseId: "auth-endpoint-positive",
    endpointPath: "/internal/v1/auth-events",
    batch: authEventBatch,
    timestamp: "1784257200",
    nonce: "EBESExQVFhcYGRobHB0eHw",
    key: authHmacKey,
  });
  const buildWrongEndpointCase = ({ caseId, sourceCase, presentedEndpointPath }) => {
    const rawBodyHashHex = sourceCase.raw_body_sha256.slice("sha256:".length);
    const presentedInput = utf8(
      `${presentedEndpointPath}\n${sourceCase.headers["X-Sentinel-Sender-ID"]}\n${sourceCase.headers["X-Sentinel-Timestamp"]}\n${sourceCase.headers["X-Sentinel-Nonce"]}\n${rawBodyHashHex}`,
    );
    const correctSignatureForPresentedEndpoint = createHmac(
      "sha256",
      Buffer.from(sourceCase.key_base64, "base64"),
    )
      .update(presentedInput)
      .digest("hex");
    if (correctSignatureForPresentedEndpoint === sourceCase.signature_hex) {
      throw new Error("Endpoint-path HMAC negative vector unexpectedly verifies");
    }
    return {
      case_id: caseId,
      source_case_id: sourceCase.case_id,
      presented_endpoint_path: presentedEndpointPath,
      presented_sender_id: sourceCase.headers["X-Sentinel-Sender-ID"],
      presented_hmac_input_b64url: b64url(presentedInput),
      presented_signature_hex: sourceCase.signature_hex,
      correct_signature_for_presented_endpoint_hex:
        correctSignatureForPresentedEndpoint,
      expected_valid: false,
      expected_error: "signature_mismatch",
    };
  };
  const eventHmac = {
    vector_name: "event-batch-hmac-v1",
    fixture_only: true,
    hmac_input_contract:
      "endpoint_path + LF + sender_id + LF + timestamp + LF + nonce + LF + hex(SHA256(raw_body))",
    positive_cases: [gatewayHmacCase, authHmacCase],
    negative_cases: [
      buildWrongEndpointCase({
        caseId: "gateway-signature-on-auth-endpoint-negative",
        sourceCase: gatewayHmacCase,
        presentedEndpointPath: "/internal/v1/auth-events",
      }),
      buildWrongEndpointCase({
        caseId: "auth-signature-on-gateway-endpoint-negative",
        sourceCase: authHmacCase,
        presentedEndpointPath: "/internal/v1/gateway-events",
      }),
    ],
  };

  const demoManifest = {
    schema_version: "demo-history-v1",
    manifest_id: uuid("500"),
    profile: "isolated-demo",
    clock_at: demoDataset.coverage_end,
    dataset_id: demoDataset.dataset_id,
    dataset_schema_version: demoDataset.schema_version,
    dataset_digest: sha256(datasetJcs),
    dataset_record_count: demoDataset.records.length,
    import_id: uuid("501"),
    coverage_start: demoDataset.coverage_start,
    coverage_end: demoDataset.coverage_end,
    path_catalog_version: demoDataset.path_catalog_version,
    source_health_digest: sha256(sourceHealthJcs),
    issued_at: "2026-07-18T02:00:00.000Z",
  };
  const demoHistoryVector = signedVector(
    "demo-history-v1",
    demoManifest,
    "sentinelflow demo-history-v1",
    demoHistoryKey,
  );

  const analysisOpenAI = {
    analysis_id: uuid("600"),
    incident_version: 3,
    provider_kind: "openai_responses",
    adapter_id: "openai-responses-v1",
    model: "gpt-5.6-sol",
    reasoning_effort: "medium",
    rate_card_version: "operator-v1",
    result_state: "succeeded",
    output_digest: digestLabel("OpenAI analysis output"),
    summary: "Synthetic public-test analysis summary.",
    classification: "path_scan",
    confidence: "0.95000",
    uncertainty: "Synthetic fixture; no deployment traffic is represented.",
    started_at: "2026-07-18T02:30:00.000Z",
    completed_at: "2026-07-18T02:30:01.000Z",
    false_positive_factors: ["Synthetic public-test fixture."],
  };
  const analysisStub = {
    analysis_id: uuid("601"),
    incident_version: 3,
    provider_kind: "deterministic_stub",
    adapter_id: "sentinelflow-deterministic-ai-stub-v1",
    model: null,
    reasoning_effort: null,
    rate_card_version: null,
    result_state: "succeeded",
    output_digest: digestLabel("deterministic stub analysis output"),
    summary: "Synthetic deterministic public-test analysis summary.",
    classification: "path_scan",
    confidence: "0.90000",
    uncertainty: "Deterministic stub output; no provider call occurred.",
    started_at: "2026-07-18T02:31:00.000Z",
    completed_at: "2026-07-18T02:31:00.010Z",
    false_positive_factors: [],
  };
  const analysisStarted = {
    analysis_id: uuid("602"),
    incident_version: 4,
    provider_kind: "openai_responses",
    adapter_id: "openai-responses-v1",
    model: "gpt-5.6-sol",
    reasoning_effort: "medium",
    rate_card_version: "operator-v1",
    result_state: "started",
    started_at: "2026-07-18T02:32:00.000Z",
    false_positive_factors: [],
  };
  const analysisFailed = {
    analysis_id: uuid("603"),
    incident_version: 5,
    provider_kind: "openai_responses",
    adapter_id: "openai-responses-v1",
    model: "gpt-5.6-sol",
    reasoning_effort: "medium",
    rate_card_version: "operator-v1",
    result_state: "failed",
    failure_code: "timeout",
    started_at: "2026-07-18T02:33:00.000Z",
    completed_at: "2026-07-18T02:33:30.000Z",
    false_positive_factors: [],
  };
  const { model: ignoredRequiredNullable, ...analysisStubMissingModel } = analysisStub;
  void ignoredRequiredNullable;
  const analysisSummaryVectors = {
    vector_name: "analysis-summary-v1",
    fixture_only: true,
    fixture_warning:
      "PUBLIC TEST FIXTURES ONLY. Provider provenance values describe synthetic results, not live provider calls.",
    schema_path: relative(repoRoot, analysisSummarySchemaPath),
    no_call_semantics:
      "A no-call attempt does not emit latest_analysis; the incident analysis failure fields carry that outcome.",
    valid_cases: [
      validationCase("openai-succeeded", analysisOpenAI, true),
      validationCase("deterministic-stub-succeeded", analysisStub, true),
      validationCase("openai-started", analysisStarted, true),
      validationCase("openai-failed", analysisFailed, true),
    ],
    negative_cases: [
      validationCase(
        "unknown-provider",
        { ...analysisOpenAI, provider_kind: "openai" },
        false,
        "provider_kind_invalid",
      ),
      validationCase(
        "wrong-openai-model",
        { ...analysisOpenAI, model: "gpt-5.6-terra" },
        false,
        "provider_model_mismatch",
      ),
      validationCase(
        "empty-openai-rate-card",
        { ...analysisOpenAI, rate_card_version: "" },
        false,
        "provider_rate_card_invalid",
      ),
      validationCase(
        "stub-empty-string-nullability",
        { ...analysisStub, model: "", reasoning_effort: "", rate_card_version: "" },
        false,
        "stub_provenance_must_be_null",
      ),
      validationCase(
        "missing-required-nullable-model",
        analysisStubMissingModel,
        false,
        "required_nullable_field_missing",
      ),
      validationCase(
        "no-call-is-not-analysis-summary",
        { ...analysisFailed, result_state: "no_call", failure_code: "input_too_large" },
        false,
        "no_call_not_exposed_as_analysis_summary",
      ),
      validationCase(
        "failed-summary-cannot-carry-output",
        { ...analysisFailed, output_digest: digestLabel("impossible failed output") },
        false,
        "failure_output_forbidden",
      ),
    ],
  };

  // The key exists only to make this deterministic public-test fixture
  // cryptographically coherent. Neither its seed nor private key is emitted.
  const publicAssertionsFixtureKey = ed25519Key(
    sha256Bytes(utf8("sentinelflow public assertions fixture key v1\n")).toString("hex"),
  );
  const publicAssertionsRunScope =
    "sentinelflow-demo-run:019b0000-0000-4000-8000-000000000604";
  const publicAssertionsManifest = {
    schema_version: "demo-history-v1",
    manifest_id: "019b0000-0000-4000-8000-000000000605",
    profile: "isolated-demo",
    clock_at: demoDataset.coverage_end,
    dataset_id: demoDataset.dataset_id,
    dataset_schema_version: demoDataset.schema_version,
    dataset_digest: sha256(datasetJcs),
    dataset_record_count: demoDataset.records.length,
    import_id: "019b0000-0000-4000-8000-000000000606",
    coverage_start: demoDataset.coverage_start,
    coverage_end: demoDataset.coverage_end,
    path_catalog_version: demoDataset.path_catalog_version,
    source_health_digest: sha256(sourceHealthJcs),
    issued_at: "2026-07-18T03:00:00.000Z",
  };
  const publicAssertionsManifestJCS = jcsBytes(publicAssertionsManifest);
  const publicAssertionsManifestDigest = sha256(publicAssertionsManifestJCS);
  const publicAssertionsSignature = sign(
    null,
    Buffer.concat([
      utf8("sentinelflow demo-history-v1\n"),
      sha256Bytes(publicAssertionsManifestJCS),
    ]),
    publicAssertionsFixtureKey.privateKey,
  );
  const demoHistoryPublicAssertions = {
    clock_at: publicAssertionsManifest.clock_at,
    impact_source_health_digest:
      "sha256:e2493dd1befd0d0a8ed321b6ff6ee3c0078a91692197c6b90c65d728e17cb1e3",
    import_id: publicAssertionsManifest.import_id,
    issued_at: publicAssertionsManifest.issued_at,
    manifest_digest: publicAssertionsManifestDigest,
    manifest_id: publicAssertionsManifest.manifest_id,
    public_key_b64url: b64url(publicAssertionsFixtureKey.publicKeyRaw),
    run_scope: publicAssertionsRunScope,
    schema_version: "demo-history-public-assertions-v1",
    signature_verification_digest: signatureVerificationDigest(
      publicAssertionsRunScope,
      publicAssertionsFixtureKey.publicKeyRaw,
      publicAssertionsManifestDigest,
      publicAssertionsSignature,
    ),
  };
  const demoHistoryPublicAssertionVectors = {
    vector_name: "demo-history-public-assertions-v1",
    fixture_only: true,
    authority_scope:
      "PUBLIC TEST FIXTURE ONLY. A real demo run must seal a fresh run-scoped key and must not trust this golden identity.",
    schema_path: relative(repoRoot, demoHistoryPublicAssertionsSchemaPath),
    validation_layers:
      "Schema validity plus exact signed-envelope run/import/manifest/key/clock/issued/impact/signature-proof binding.",
    valid_cases: [
      validationCase(
        "public-test-run-scoped-assertion",
        demoHistoryPublicAssertions,
        true,
        "none",
        { expected_schema_valid: true, expected_binding_valid: true },
      ),
    ],
    negative_cases: [
      validationCase(
        "pinned-public-fixture-key-forbidden",
        {
          ...demoHistoryPublicAssertions,
          public_key_b64url: b64url(demoHistoryKey.publicKeyRaw),
        },
        false,
        "public_fixture_key_forbidden",
        { expected_schema_valid: false, expected_binding_valid: false },
      ),
      validationCase(
        "wrong-run-scope-binding",
        {
          ...demoHistoryPublicAssertions,
          run_scope: "sentinelflow-demo-run:019b0000-0000-4000-8000-000000000607",
        },
        false,
        "run_scope_mismatch",
        { expected_schema_valid: true, expected_binding_valid: false },
      ),
      validationCase(
        "wrong-import-binding",
        {
          ...demoHistoryPublicAssertions,
          import_id: "019b0000-0000-4000-8000-000000000608",
        },
        false,
        "import_id_mismatch",
        { expected_schema_valid: true, expected_binding_valid: false },
      ),
      validationCase(
        "wrong-manifest-digest-binding",
        {
          ...demoHistoryPublicAssertions,
          manifest_digest: digestLabel("wrong demo history manifest"),
        },
        false,
        "manifest_digest_mismatch",
        { expected_schema_valid: true, expected_binding_valid: false },
      ),
      validationCase(
        "wrong-impact-digest",
        {
          ...demoHistoryPublicAssertions,
          impact_source_health_digest: digestLabel("wrong impact projection"),
        },
        false,
        "impact_digest_mismatch",
        { expected_schema_valid: false, expected_binding_valid: false },
      ),
      validationCase(
        "wrong-clock-binding",
        {
          ...demoHistoryPublicAssertions,
          clock_at: "2026-07-18T02:00:01.000Z",
        },
        false,
        "clock_at_mismatch",
        { expected_schema_valid: true, expected_binding_valid: false },
      ),
      validationCase(
        "issued-before-clock",
        {
          ...demoHistoryPublicAssertions,
          issued_at: "2026-07-18T01:59:59.000Z",
        },
        false,
        "issued_at_before_clock",
        { expected_schema_valid: true, expected_binding_valid: false },
      ),
      validationCase(
        "wrong-signature-proof-binding",
        {
          ...demoHistoryPublicAssertions,
          signature_verification_digest: digestLabel("wrong signature proof"),
        },
        false,
        "signature_proof_mismatch",
        { expected_schema_valid: true, expected_binding_valid: false },
      ),
      validationCase(
        "non-millisecond-clock",
        {
          ...demoHistoryPublicAssertions,
          clock_at: "2026-07-18T02:00:00Z",
        },
        false,
        "clock_encoding_invalid",
        { expected_schema_valid: false, expected_binding_valid: false },
      ),
    ],
  };

  const requestEnvelope = {
    schema_version: "executor-request-envelope-v1",
    capability_jcs_b64url: capabilityVectors.add.jcs_b64url,
    capability_signature_b64url: capabilityVectors.add.signature_b64url,
    artifact_b64url: b64url(addArtifact),
  };
  const requestEnvelopeBytes = jcsBytes(requestEnvelope);
  const responseEnvelope = {
    schema_version: "executor-response-envelope-v1",
    result_jcs_b64url: results.applied.jcs_b64url,
    result_signature_b64url: results.applied.signature_b64url,
  };
  const responseEnvelopeBytes = jcsBytes(responseEnvelope);

  const journalRecord = (payloadWithoutChecksum) => ({
    ...payloadWithoutChecksum,
    record_checksum: sha256(jcsBytes(payloadWithoutChecksum)),
  });
  const journalStarted = journalRecord({
    schema_version: "executor-journal-record-v1",
    journal_sequence: 1,
    phase: "started",
    operation: capabilities.add.operation,
    capability_id: capabilities.add.capability_id,
    capability_jcs_b64url: capabilityVectors.add.jcs_b64url,
    capability_signature_b64url: capabilityVectors.add.signature_b64url,
    capability_digest: capabilityVectors.add.digest,
    artifact_b64url: b64url(addArtifact),
    artifact_digest: addArtifactDigest,
    target_ipv4: capabilities.add.target_ipv4,
    owned_schema_digest: ownedSchemaDigest,
    received_at: "2026-07-18T02:00:06.000Z",
    deadline: "2026-07-18T02:00:08.000Z",
    terminal_result_jcs_b64url: null,
    terminal_result_signature_b64url: null,
    terminal_result_digest: null,
    previous_record_digest: null,
  });
  const { record_checksum: ignoredStartedChecksum, ...journalStartedPayload } =
    journalStarted;
  const journalTerminal = journalRecord({
    ...journalStartedPayload,
    journal_sequence: 2,
    phase: "terminal",
    terminal_result_jcs_b64url: results.applied.jcs_b64url,
    terminal_result_signature_b64url: results.applied.signature_b64url,
    terminal_result_digest: results.applied.digest,
    previous_record_digest: sha256(jcsBytes(journalStarted)),
  });
  void ignoredStartedChecksum;

  return {
    schema_version: "sentinelflow-contract-vectors-v1",
    fixture_only: true,
    fixture_warning:
      "PUBLIC TEST SEEDS AND KEYS ONLY. NEVER LOAD THESE VALUES IN A DEPLOYMENT.",
    canonicalization: "RFC8785/JCS-compatible for the ASCII-key, safe-integer fixture domain",
    byte_encoding: "UTF-8; binary fields use RFC4648 unpadded base64url",
    digest_encoding: "sha256: followed by 64 lowercase hexadecimal characters",
    owned_schema_digest_semantics:
      "capability/result/journal owned_schema_digest equals nft_base_chain_live_jcs_sha256, never nft_base_chain_raw_sha256",
    schema_bundle: buildSchemaBundle(),
    artifact_digests: {
      nft_base_chain_raw_sha256: sha256(nftBaseRaw),
      nft_base_chain_live_jcs_sha256: sha256(nftBaseLiveJcs),
      protected_ipv4_jcs_sha256: sha256(protectedIpv4Jcs),
      demo_history_dataset_jcs_sha256: sha256(datasetJcs),
      demo_history_source_health_jcs_sha256: sha256(sourceHealthJcs),
      nft_add_artifact_sha256: addArtifactDigest,
      nft_revoke_artifact_sha256: revokeArtifactDigest,
      nft_inspect_artifact_sha256: sha256(inspectArtifact),
    },
    test_keys: {
      dispatcher_ed25519: {
        fixture_only: true,
        private_seed_hex: fixtureSeeds.dispatcher,
        public_key_b64url: b64url(dispatcherKey.publicKeyRaw),
      },
      executor_result_ed25519: {
        fixture_only: true,
        private_seed_hex: fixtureSeeds.executorResult,
        public_key_b64url: b64url(executorResultKey.publicKeyRaw),
      },
      demo_history_ed25519: {
        fixture_only: true,
        private_seed_hex: fixtureSeeds.demoHistory,
        public_key_b64url: b64url(demoHistoryKey.publicKeyRaw),
      },
      event_hmac_sha256: {
        fixture_only: true,
        gateway_key_base64: gatewayHmacKey.toString("base64"),
        auth_key_base64: authHmacKey.toString("base64"),
      },
    },
    vectors: {
      event_batch_hmac_v1: eventHmac,
      capability_add_v1: capabilityVectors.add,
      capability_revoke_v1: capabilityVectors.revoke,
      capability_inspect_v1: capabilityVectors.inspect,
      inspection_authorization_v1: {
        vector_name: "inspection-authorization-v1",
        payload: inspectionAuthorization,
        jcs_b64url: b64url(inspectionAuthorizationJcs),
        digest: inspectionAuthorizationDigest,
        authority_class: "read-only-system-non-hil",
        forbidden_authority: [
          "add",
          "revoke",
          "ttl_refresh",
          "hil_decision_nonce",
        ],
      },
      execution_result_applied_v1: results.applied,
      execution_result_recovered_active_v1: results.recoveredActive,
      execution_result_revoked_v1: results.revoked,
      execution_result_inspect_absent_v1: results.inspectAbsent,
      executor_journal_started_add_v1: {
        vector_name: "executor-journal-started-add-v1",
        payload: journalStarted,
        jcs_b64url: b64url(jcsBytes(journalStarted)),
        digest: sha256(jcsBytes(journalStarted)),
      },
      executor_journal_terminal_add_v1: {
        vector_name: "executor-journal-terminal-add-v1",
        payload: journalTerminal,
        jcs_b64url: b64url(jcsBytes(journalTerminal)),
        digest: sha256(jcsBytes(journalTerminal)),
      },
      demo_history_v1: demoHistoryVector,
      analysis_summary_v1: analysisSummaryVectors,
      demo_history_public_assertions_v1: demoHistoryPublicAssertionVectors,
      ttl_canonical_v1: {
        vector_name: "ttl-canonical-v1",
        accepted: [
          { input: "60s", seconds: 60, canonical: "1m" },
          { input: "61s", seconds: 61, canonical: "61s" },
          { input: "1800s", seconds: 1800, canonical: "30m" },
          { input: "30m", seconds: 1800, canonical: "30m" },
          { input: "3600s", seconds: 3600, canonical: "1h" },
          { input: "24h", seconds: 86400, canonical: "24h" },
        ],
        rejected: [
          "0s",
          "59s",
          "1441m",
          "25h",
          "01m",
          "1M",
          "1.5h",
          "1 m",
          "86401s",
        ],
      },
      uds_request_frame_v1: {
        vector_name: "uds-request-frame-v1",
        framing: "uint32-big-endian length followed by one UTF-8 JSON payload",
        max_payload_bytes: 16384,
        payload_length: requestEnvelopeBytes.length,
        payload_jcs_b64url: b64url(requestEnvelopeBytes),
        frame_b64url: b64url(lengthPrefixedFrame(requestEnvelopeBytes)),
      },
      uds_response_frame_v1: {
        vector_name: "uds-response-frame-v1",
        framing: "uint32-big-endian length followed by one UTF-8 JSON payload",
        max_payload_bytes: 16384,
        payload_length: responseEnvelopeBytes.length,
        payload_jcs_b64url: b64url(responseEnvelopeBytes),
        frame_b64url: b64url(lengthPrefixedFrame(responseEnvelopeBytes)),
      },
    },
  };
}

const bundle = buildBundle();
const demoVector = bundle.vectors.demo_history_v1;
const signedDemoManifestFixture = {
  schema_version: "demo-history-signed-manifest-v1",
  fixture_only: true,
  key_scope:
    "public-test-only; actual demo runs must generate a run-scoped key and manifest",
  manifest: demoVector.payload,
  manifest_jcs_b64url: demoVector.jcs_b64url,
  manifest_digest: demoVector.digest,
  signature_b64url: demoVector.signature_b64url,
  public_key_b64url: bundle.test_keys.demo_history_ed25519.public_key_b64url,
};
const expectedVectorText = `${JSON.stringify(bundle, null, 2)}\n`;
const expectedDemoManifestText = `${JSON.stringify(signedDemoManifestFixture, null, 2)}\n`;

if (process.argv.length === 2) {
  process.stdout.write(expectedVectorText);
} else if (process.argv.length === 3 && process.argv[2] === "--manifest") {
  process.stdout.write(expectedDemoManifestText);
} else if (process.argv.length === 3 && process.argv[2] === "--check") {
  const actualVectorText = readFileSync(vectorPath, "utf8");
  const actualDemoManifestText = readFileSync(demoManifestPath, "utf8");
  let failed = false;
  if (actualVectorText !== expectedVectorText) {
    process.stderr.write(
      `${relative(repoRoot, vectorPath)} is stale; regenerate from scripts/generate-contract-vectors.mjs\n`,
    );
    failed = true;
  }
  if (actualDemoManifestText !== expectedDemoManifestText) {
    process.stderr.write(
      `${relative(repoRoot, demoManifestPath)} is stale; regenerate with --manifest\n`,
    );
    failed = true;
  }
  if (failed) {
    process.exitCode = 1;
  } else {
    process.stdout.write(
      `PASS: ${relative(repoRoot, vectorPath)} and ${relative(repoRoot, demoManifestPath)} match all deterministic contract inputs\n`,
    );
  }
} else if (process.argv.length === 3 && process.argv[2] === "--write") {
  writeFileSync(vectorPath, expectedVectorText, { encoding: "utf8", mode: 0o644 });
  writeFileSync(demoManifestPath, expectedDemoManifestText, { encoding: "utf8", mode: 0o644 });
  process.stdout.write(
    `WROTE: ${relative(repoRoot, vectorPath)} and ${relative(repoRoot, demoManifestPath)}\n`,
  );
} else {
  process.stderr.write(
    "usage: node scripts/generate-contract-vectors.mjs [--manifest|--check|--write]\n",
  );
  process.exitCode = 2;
}
