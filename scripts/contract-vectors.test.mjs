import assert from "node:assert/strict";
import {
  createHash,
  createHmac,
  createPublicKey,
  verify,
} from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const scriptDir = resolve(fileURLToPath(new URL(".", import.meta.url)));
const repoRoot = resolve(scriptDir, "..");
const contractsRoot = join(repoRoot, "contracts");
const bundlePath = join(contractsRoot, "vectors", "contract_vectors_v1.json");
const analysisSchemaPath = join(
  contractsRoot,
  "api",
  "analysis_summary_v1.schema.json",
);
const assertionsSchemaPath = join(
  contractsRoot,
  "enforcement",
  "demo_history_public_assertions_v1.schema.json",
);
const executionResultV2SchemaPath = join(
  contractsRoot,
  "enforcement",
  "execution_result_v2.schema.json",
);

const readJSON = (path) => JSON.parse(readFileSync(path, "utf8"));
const sha256 = (bytes) =>
  `sha256:${createHash("sha256").update(bytes).digest("hex")}`;

// This implementation is deliberately independent of the generator. It is a
// second canonical-byte parser/checker, not an import of generator internals.
function canonical(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    assert.ok(Number.isSafeInteger(value) && !Object.is(value, -0));
    return String(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonical(item)).join(",")}]`;
  }
  assert.equal(typeof value, "object");
  return `{${Object.entries(value)
    .sort(([left], [right]) => Buffer.from(left).compare(Buffer.from(right)))
    .map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`)
    .join(",")}}`;
}

const jcs = (value) => Buffer.from(canonical(value), "utf8");

function listFiles(directory) {
  return readdirSync(directory)
    .sort()
    .flatMap((name) => {
      const path = join(directory, name);
      return statSync(path).isDirectory() ? listFiles(path) : [path];
    });
}

function resolveLocalRef(root, ref) {
  assert.match(ref, /^#\//);
  return ref
    .slice(2)
    .split("/")
    .map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~"))
    .reduce((node, part) => node?.[part], root);
}

function hasType(value, type) {
  switch (type) {
    case "null":
      return value === null;
    case "object":
      return value !== null && typeof value === "object" && !Array.isArray(value);
    case "array":
      return Array.isArray(value);
    case "string":
      return typeof value === "string";
    case "integer":
      return Number.isSafeInteger(value);
    case "number":
      return typeof value === "number" && Number.isFinite(value);
    case "boolean":
      return typeof value === "boolean";
    default:
      throw new Error(`unsupported schema type ${type}`);
  }
}

function schemaMatches(value, schema, root = schema) {
  if (typeof schema === "boolean") {
    return schema;
  }
  if (schema.$ref !== undefined) {
    const referenced = resolveLocalRef(root, schema.$ref);
    if (referenced === undefined || !schemaMatches(value, referenced, root)) {
      return false;
    }
  }
  if (schema.allOf && !schema.allOf.every((item) => schemaMatches(value, item, root))) {
    return false;
  }
  if (schema.anyOf && !schema.anyOf.some((item) => schemaMatches(value, item, root))) {
    return false;
  }
  if (schema.oneOf) {
    const matches = schema.oneOf.filter((item) => schemaMatches(value, item, root));
    if (matches.length !== 1) {
      return false;
    }
  }
  if (schema.not && schemaMatches(value, schema.not, root)) {
    return false;
  }
  if (schema.if) {
    const branch = schemaMatches(value, schema.if, root) ? schema.then : schema.else;
    if (branch && !schemaMatches(value, branch, root)) {
      return false;
    }
  }
  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!types.some((type) => hasType(value, type))) {
      return false;
    }
  }
  if (schema.const !== undefined && canonical(value) !== canonical(schema.const)) {
    return false;
  }
  if (schema.enum && !schema.enum.some((item) => canonical(item) === canonical(value))) {
    return false;
  }
  if (typeof value === "string") {
    const length = [...value].length;
    if (schema.minLength !== undefined && length < schema.minLength) {
      return false;
    }
    if (schema.maxLength !== undefined && length > schema.maxLength) {
      return false;
    }
    if (schema.pattern && !new RegExp(schema.pattern, "u").test(value)) {
      return false;
    }
    if (schema.format === "date-time" && Number.isNaN(Date.parse(value))) {
      return false;
    }
  }
  if (typeof value === "number") {
    if (schema.minimum !== undefined && value < schema.minimum) {
      return false;
    }
    if (schema.maximum !== undefined && value > schema.maximum) {
      return false;
    }
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      return false;
    }
    if (schema.maxItems !== undefined && value.length > schema.maxItems) {
      return false;
    }
    if (schema.items && !value.every((item) => schemaMatches(item, schema.items, root))) {
      return false;
    }
  }
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    const properties = schema.properties ?? {};
    if (schema.required && !schema.required.every((name) => Object.hasOwn(value, name))) {
      return false;
    }
    for (const [name, child] of Object.entries(properties)) {
      if (Object.hasOwn(value, name) && !schemaMatches(value[name], child, root)) {
        return false;
      }
    }
    if (
      schema.additionalProperties === false &&
      Object.keys(value).some((name) => !Object.hasOwn(properties, name))
    ) {
      return false;
    }
  }
  return true;
}

function checkStrictObjectSchemas(node, path) {
  if (Array.isArray(node)) {
    node.forEach((item, index) => checkStrictObjectSchemas(item, `${path}[${index}]`));
    return;
  }
  if (node === null || typeof node !== "object") {
    return;
  }
  if (node.type === "object") {
    assert.equal(node.additionalProperties, false, `${path} additionalProperties`);
    assert.deepEqual(
      [...(node.required ?? [])].sort(),
      Object.keys(node.properties ?? {}).sort(),
      `${path} required/properties`,
    );
  }
  for (const [name, child] of Object.entries(node)) {
    checkStrictObjectSchemas(child, `${path}.${name}`);
  }
}

function checkVectorCaseBytes(item) {
  const canonicalBytes = jcs(item.payload);
  const encoded = Buffer.from(item.payload_jcs_b64url, "base64url");
  assert.equal(encoded.toString("base64url"), item.payload_jcs_b64url);
  assert.deepEqual(encoded, canonicalBytes, `${item.case_id} canonical bytes`);
  assert.equal(item.payload_digest, sha256(canonicalBytes), `${item.case_id} digest`);
}

test("all contract schemas remain closed and the schema bundle is byte-exact", () => {
  const bundle = readJSON(bundlePath);
  const schemaPaths = listFiles(contractsRoot).filter((path) => path.endsWith(".schema.json"));
  const schemas = schemaPaths.map((path) => {
    const raw = readFileSync(path);
    const parsed = JSON.parse(raw.toString("utf8"));
    checkStrictObjectSchemas(parsed, relative(repoRoot, path));
    return {
      path: relative(repoRoot, path),
      raw_sha256: sha256(raw),
      jcs_sha256: sha256(jcs(parsed)),
    };
  });
  const content = {
    schema_version: "sentinelflow-contract-schema-bundle-v1",
    schemas,
  };
  assert.deepEqual(bundle.schema_bundle.schemas, schemas);
  assert.equal(bundle.schema_bundle.schema_version, content.schema_version);
  assert.equal(bundle.schema_bundle.bundle_digest, sha256(jcs(content)));
  assert.ok(
    schemas.some(({ path }) => path === "contracts/api/analysis_summary_v1.schema.json"),
  );
  assert.ok(
    schemas.some(
      ({ path }) =>
        path === "contracts/enforcement/demo_history_public_assertions_v1.schema.json",
    ),
  );
});

test("analysis-summary-v1 vectors enforce truthful provider and state provenance", () => {
  const bundle = readJSON(bundlePath);
  const schema = readJSON(analysisSchemaPath);
  const vector = bundle.vectors.analysis_summary_v1;
  assert.equal(vector.schema_path, "contracts/api/analysis_summary_v1.schema.json");
  for (const item of [...vector.valid_cases, ...vector.negative_cases]) {
    checkVectorCaseBytes(item);
    assert.equal(schemaMatches(item.payload, schema), item.expected_valid, item.case_id);
    if (item.expected_valid && Object.hasOwn(item.payload, "completed_at")) {
      assert.ok(Date.parse(item.payload.completed_at) >= Date.parse(item.payload.started_at));
    }
  }
  assert.deepEqual(
    vector.valid_cases.map(({ case_id }) => case_id),
    [
      "openai-succeeded",
      "deterministic-stub-succeeded",
      "openai-started",
      "openai-failed",
    ],
  );
  assert.match(vector.no_call_semantics, /does not emit latest_analysis/);
});

test("execution-result-v2 vectors bind a signed read-back observation interval", () => {
  const bundle = readJSON(bundlePath);
  const schema = readJSON(executionResultV2SchemaPath);
  const names = [
    "execution_result_applied_v2",
    "execution_result_recovered_active_v2",
    "execution_result_revoked_v2",
    "execution_result_inspect_absent_v2",
  ];
  for (const name of names) {
    const vector = bundle.vectors[name];
    assert.equal(vector.vector_name, name.replaceAll("_", "-"));
    assert.equal(schemaMatches(vector.payload, schema), true, name);
    const payload = vector.payload;
    assert.equal(payload.schema_version, "execution-result-v2");
    assert.ok(Date.parse(payload.started_at) <= Date.parse(payload.readback_started_at), name);
    assert.ok(
      Date.parse(payload.readback_started_at) <= Date.parse(payload.readback_completed_at),
      name,
    );
    assert.ok(
      Date.parse(payload.readback_completed_at) <= Date.parse(payload.completed_at),
      name,
    );
    const signingInput = Buffer.from(vector.signing_input_b64url, "base64url");
    assert.ok(
      signingInput.subarray(0, signingInput.indexOf(0x0a)).equals(
        Buffer.from("sentinelflow execution-result-v2", "utf8"),
      ),
      `${name} signing domain`,
    );
    const v1Input = Buffer.concat([
      Buffer.from("sentinelflow execution-result-v1\\n", "utf8"),
      Buffer.from(vector.digest.slice("sha256:".length), "hex"),
    ]);
    assert.notDeepEqual(signingInput, v1Input, `${name} must not use the v1 domain`);
  }
});

test("public demo-history assertions bind exact public proof and forbid authority fields", () => {
  const bundle = readJSON(bundlePath);
  const schema = readJSON(assertionsSchemaPath);
  const vector = bundle.vectors.demo_history_public_assertions_v1;
  const reference = vector.valid_cases[0].payload;
  const exactFields = [
    "clock_at",
    "impact_source_health_digest",
    "import_id",
    "issued_at",
    "manifest_digest",
    "manifest_id",
    "public_key_b64url",
    "run_scope",
    "schema_version",
    "signature_verification_digest",
  ];
  assert.deepEqual(Object.keys(reference).sort(), [...exactFields].sort());
  const bindingValid = (payload) =>
    schemaMatches(payload, schema) &&
    Date.parse(payload.issued_at) >= Date.parse(payload.clock_at) &&
    canonical(payload) === canonical(reference);
  for (const item of [...vector.valid_cases, ...vector.negative_cases]) {
    checkVectorCaseBytes(item);
    assert.equal(
      schemaMatches(item.payload, schema),
      item.expected_schema_valid,
      `${item.case_id} schema outcome`,
    );
    assert.equal(
      bindingValid(item.payload),
      item.expected_binding_valid,
      `${item.case_id} binding outcome`,
    );
    assert.equal(item.expected_valid, item.expected_binding_valid, item.case_id);
  }
  for (const forbidden of ["private_key_b64url", "signature_b64url", "raw_dataset"]) {
    assert.equal(schemaMatches({ ...reference, [forbidden]: "forbidden" }, schema), false);
    assert.equal(Object.hasOwn(schema.properties, forbidden), false);
  }
  assert.equal(Object.hasOwn(reference, "fixture_only"), false);
  assert.match(vector.authority_scope, /PUBLIC TEST FIXTURE ONLY/);
});

test("pre-existing signed, HMAC, journal, TTL, and UDS vector subtrees are unchanged", () => {
  const bundle = readJSON(bundlePath);
  const expected = {
    event_batch_hmac_v1: "97b6bba1d2ac5a6f555e7b4fb1f609267ecc3aa963357b43f1a517041d46f5a3",
    capability_add_v1: "681b52e8459cb32a88fbca80482b85b579917babc9533de995d78c90d93c2b71",
    capability_revoke_v1: "2302d70d2c6a1fc5dc1d66d53bf0ffc49cd526aaef3800c9351f14185e4ebc3f",
    capability_inspect_v1: "b05b6542cca6c5042d07aeaf8f8f448d753dc6f4b5fa1d5ad4492417b572e105",
    inspection_authorization_v1: "091ef39a6c6fe26f30babc42e61400bb79eecc45d2429a1854c73a842fbe7fe1",
    execution_result_applied_v1: "9d2cade2a0dbeb013b6c23a30bfd94fc118d7f5573a9a95ab3970f4b8b5c707d",
    execution_result_recovered_active_v1: "a04b028df7803e72dcb08eae3ff4670a58861353a39813b9d4ce267c4134054b",
    execution_result_revoked_v1: "9c7af9608f2a86a8f193f5e4776ce2d5687b3cd5b89d13971fe997bcca9dee76",
    execution_result_inspect_absent_v1: "d7da4fce25e75f454bf23fcf4bd0f2d384b1d7cdc37b7205c969f5b959b376e6",
    executor_journal_started_add_v1: "a52426a81e74252e217397026096b80368b255472d5f6d2489e80523349f534a",
    executor_journal_terminal_add_v1: "6fa1fd83cde992ac56f360e21ffd1079acfa6e193ad0eea859e927b76d426cc1",
    demo_history_v1: "3020612d3ce331548289d0dc57d97df8b5a82e9ed44d6b4e1e516c277b49957a",
    ttl_canonical_v1: "d155aa97df9290390590df5427e63ec01666da26a2516d237e304a1750901257",
    uds_request_frame_v1: "f870e979020148ccc16082abe8aa65aa34dbc9391ac14a118d12df287e2e8018",
    uds_response_frame_v1: "abb2f0d06926f5405005e2ea95b3dc1d4eb35a10c3fe2e71e2aa38e774c69e36",
  };
  for (const [name, digest] of Object.entries(expected)) {
    assert.equal(
      createHash("sha256").update(JSON.stringify(bundle.vectors[name])).digest("hex"),
      digest,
      name,
    );
  }
});

test("independent crypto and frame checks reproduce existing vector bytes", () => {
  const bundle = readJSON(bundlePath);
  const publicKey = (raw) =>
    createPublicKey({
      key: Buffer.concat([
        Buffer.from("302a300506032b6570032100", "hex"),
        Buffer.from(raw, "base64url"),
      ]),
      format: "der",
      type: "spki",
    });
  const signedGroups = [
    {
      key: publicKey(bundle.test_keys.dispatcher_ed25519.public_key_b64url),
      names: ["capability_add_v1", "capability_revoke_v1", "capability_inspect_v1"],
    },
    {
      key: publicKey(bundle.test_keys.executor_result_ed25519.public_key_b64url),
      names: [
        "execution_result_applied_v1",
        "execution_result_recovered_active_v1",
        "execution_result_revoked_v1",
        "execution_result_inspect_absent_v1",
        "execution_result_applied_v2",
        "execution_result_recovered_active_v2",
        "execution_result_revoked_v2",
        "execution_result_inspect_absent_v2",
      ],
    },
    {
      key: publicKey(bundle.test_keys.demo_history_ed25519.public_key_b64url),
      names: ["demo_history_v1"],
    },
  ];
  for (const group of signedGroups) {
    for (const name of group.names) {
      const vector = bundle.vectors[name];
      const payloadBytes = jcs(vector.payload);
      assert.deepEqual(Buffer.from(vector.jcs_b64url, "base64url"), payloadBytes);
      assert.equal(vector.digest, sha256(payloadBytes));
      assert.equal(
        verify(
          null,
          Buffer.from(vector.signing_input_b64url, "base64url"),
          group.key,
          Buffer.from(vector.signature_b64url, "base64url"),
        ),
        true,
        name,
      );
    }
  }

  for (const item of bundle.vectors.event_batch_hmac_v1.positive_cases) {
    const key = Buffer.from(item.key_base64, "base64");
    const input = Buffer.from(item.hmac_input_b64url, "base64url");
    assert.equal(createHmac("sha256", key).update(input).digest("hex"), item.signature_hex);
  }
  for (const name of ["uds_request_frame_v1", "uds_response_frame_v1"]) {
    const item = bundle.vectors[name];
    const frame = Buffer.from(item.frame_b64url, "base64url");
    assert.equal(frame.readUInt32BE(0), item.payload_length);
    assert.deepEqual(frame.subarray(4), Buffer.from(item.payload_jcs_b64url, "base64url"));
  }
});
