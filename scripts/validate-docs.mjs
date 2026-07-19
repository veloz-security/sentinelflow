#!/usr/bin/env node

import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import process from "node:process";

const root = path.resolve(
  path.dirname(new URL(import.meta.url).pathname),
  "..",
);
const markdownFiles = [
  "README.md",
  "AGENTS.md",
  "docs/PRD.md",
  "docs/PRD.ko.md",
  "docs/ADR.md",
  "docs/ADR.ko.md",
  "docs/TDD.md",
  "docs/TDD.ko.md",
  "docs/TASKLIST.md",
  "docs/TASKLIST.ko.md",
  "docs/WBS.md",
  "docs/WBS.ko.md",
  "docs/IMPLEMENTATION_READINESS.md",
  "docs/IMPLEMENTATION_READINESS.ko.md",
];
const pairs = [
  ["docs/PRD.md", "docs/PRD.ko.md"],
  ["docs/ADR.md", "docs/ADR.ko.md"],
  ["docs/TDD.md", "docs/TDD.ko.md"],
  ["docs/TASKLIST.md", "docs/TASKLIST.ko.md"],
  ["docs/WBS.md", "docs/WBS.ko.md"],
  ["docs/IMPLEMENTATION_READINESS.md", "docs/IMPLEMENTATION_READINESS.ko.md"],
];

function walkFiles(relativeDirectory) {
  const absoluteDirectory = path.join(root, relativeDirectory);
  return fs
    .readdirSync(absoluteDirectory, { withFileTypes: true })
    .sort((left, right) => left.name.localeCompare(right.name))
    .flatMap((entry) => {
      const relative = path.posix.join(relativeDirectory, entry.name);
      return entry.isDirectory() ? walkFiles(relative) : [relative];
    });
}

const contractFiles = walkFiles("contracts");
const contractJsonFiles = contractFiles.filter((relative) =>
  relative.endsWith(".json"),
);
const contractSchemaFiles = contractFiles.filter((relative) =>
  relative.endsWith(".schema.json"),
);
const errors = [];

function read(relative) {
  return fs.readFileSync(path.join(root, relative), "utf8");
}

function fail(message) {
  errors.push(message);
}

function githubSlug(value) {
  return value
    .trim()
    .toLowerCase()
    .replace(/<[^>]+>/g, "")
    .replace(/!\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/\[([^\]]+)\]\([^)]*\)/g, "$1")
    .replace(/[`*_~]/g, "")
    .replace(/[^\p{L}\p{N}\s_-]/gu, "")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-");
}

function anchors(markdown) {
  const result = new Set();
  const counts = new Map();
  for (const line of markdown.split("\n")) {
    const match = /^(#{1,6})\s+(.+?)\s*$/.exec(line);
    if (!match) continue;
    const base = githubSlug(match[2]);
    const count = counts.get(base) ?? 0;
    counts.set(base, count + 1);
    result.add(count === 0 ? base : `${base}-${count}`);
  }
  return result;
}

function validateLinks() {
  for (const relative of markdownFiles) {
    const content = read(relative);
    const linkPattern = /\[[^\]]*\]\((<?[^)\s>]+>?)(?:\s+"[^"]*")?\)/g;
    for (const match of content.matchAll(linkPattern)) {
      let target = match[1].replace(/^<|>$/g, "");
      if (/^(?:https?:|mailto:)/.test(target)) continue;
      const [filePart, rawAnchor] = target.split("#", 2);
      const targetRelative = filePart
        ? path.relative(
            root,
            path.resolve(
              path.dirname(path.join(root, relative)),
              decodeURIComponent(filePart),
            ),
          )
        : relative;
      const absolute = path.join(root, targetRelative);
      if (!fs.existsSync(absolute)) {
        fail(`${relative}: missing local link target ${target}`);
        continue;
      }
      if (rawAnchor && absolute.endsWith(".md")) {
        const wanted = decodeURIComponent(rawAnchor).toLowerCase();
        if (!anchors(fs.readFileSync(absolute, "utf8")).has(wanted)) {
          fail(
            `${relative}: missing anchor #${rawAnchor} in ${targetRelative}`,
          );
        }
      }
    }
  }
}

function headingLevels(markdown) {
  return markdown
    .split("\n")
    .map((line) => /^(#{1,6})\s+/.exec(line)?.[1].length)
    .filter(Boolean);
}

function fenceLanguages(markdown) {
  return markdown
    .split("\n")
    .map((line) => /^```([^\s`]*)/.exec(line)?.[1] ?? null)
    .filter((value) => value !== null);
}

function identifierSet(markdown) {
  const pattern =
    /\b(?:FR|NFR|ADR|UT|CT|IT|E2E|SEC|REC)-\d{3}\b|\bM\d+-\d{3}\b|\bA\d{3}\b/g;
  return [...new Set(markdown.match(pattern) ?? [])].sort();
}

function tableRows(markdown) {
  return markdown.split("\n").filter((line) => /^\|.*\|\s*$/.test(line)).length;
}

function parseCells(line) {
  const trimmed = line.trim();
  if (!trimmed.startsWith("|") || !trimmed.endsWith("|")) return [];
  return trimmed
    .slice(1, -1)
    .split("|")
    .map((cell) => cell.trim());
}

function parseTasks(markdown) {
  const tasks = new Map();
  for (const line of markdown.split("\n")) {
    const cells = parseCells(line);
    const id = /`(M\d+-\d{3})`/.exec(cells[1] ?? "")?.[1];
    if (!id) continue;
    tasks.set(id, {
      done: cells[0],
      priority: /\*\*(P\d)\*\*/.exec(cells[1])?.[1] ?? "",
      prerequisites: cells[3] ?? "",
    });
  }
  return tasks;
}

function parseRequirements(markdown) {
  const requirements = new Map();
  for (const line of markdown.split("\n")) {
    const cells = parseCells(line);
    if (/^(?:FR|NFR)-\d{3}$/.test(cells[0] ?? "")) {
      requirements.set(cells[0], cells[1]);
    }
  }
  return requirements;
}

function normalizedAdrStatus(value) {
  const lower = value.toLowerCase();
  const states = [];
  if (/accepted|승인/.test(lower)) states.push("accepted");
  if (/proposed|제안/.test(lower)) states.push("proposed");
  if (/open|미결/.test(lower)) states.push("open");
  if (/superseded|대체/.test(lower)) states.push("superseded");
  return states.sort().join("+");
}

function parseAdrIndex(markdown) {
  const decisions = new Map();
  for (const line of markdown.split("\n")) {
    const cells = parseCells(line);
    const id = /ADR-\d{3}/.exec(cells[0] ?? "")?.[0];
    if (id) decisions.set(id, normalizedAdrStatus(cells[2] ?? ""));
  }
  return decisions;
}

function compareMaps(
  label,
  left,
  right,
  projection = (value) => JSON.stringify(value),
) {
  const keys = [...new Set([...left.keys(), ...right.keys()])].sort();
  for (const key of keys) {
    if (!left.has(key) || !right.has(key)) {
      fail(`${label}: ${key} is missing from one language`);
    } else if (projection(left.get(key)) !== projection(right.get(key))) {
      fail(`${label}: ${key} metadata differs between languages`);
    }
  }
}

function validatePairs() {
  for (const [english, korean] of pairs) {
    const en = read(english);
    const ko = read(korean);
    if (
      JSON.stringify(headingLevels(en)) !== JSON.stringify(headingLevels(ko))
    ) {
      fail(`${english}/${korean}: heading-level structure differs`);
    }
    if (
      JSON.stringify(fenceLanguages(en)) !== JSON.stringify(fenceLanguages(ko))
    ) {
      fail(`${english}/${korean}: code-fence sequence differs`);
    }
    if (
      JSON.stringify(identifierSet(en)) !== JSON.stringify(identifierSet(ko))
    ) {
      fail(`${english}/${korean}: identifier sets differ`);
    }
    if (tableRows(en) !== tableRows(ko)) {
      fail(`${english}/${korean}: table row counts differ`);
    }
  }

  compareMaps(
    "Tasklist",
    parseTasks(read("docs/TASKLIST.md")),
    parseTasks(read("docs/TASKLIST.ko.md")),
    (value) => JSON.stringify(value),
  );
  compareMaps(
    "PRD requirements",
    parseRequirements(read("docs/PRD.md")),
    parseRequirements(read("docs/PRD.ko.md")),
  );
  compareMaps(
    "ADR index",
    parseAdrIndex(read("docs/ADR.md")),
    parseAdrIndex(read("docs/ADR.ko.md")),
  );
}

function expandTaskIds(value) {
  const ids = new Set();
  let remaining = value;
  const rangePattern = /M(\d+)-(\d{3})~(?:M\1-)?(\d{3})/g;
  for (const match of value.matchAll(rangePattern)) {
    const milestone = match[1];
    const start = Number(match[2]);
    const end = Number(match[3]);
    for (let number = start; number <= end; number += 1) {
      ids.add(`M${milestone}-${String(number).padStart(3, "0")}`);
    }
    remaining = remaining.replace(match[0], " ");
  }
  for (const match of remaining.matchAll(/M\d+-\d{3}/g)) ids.add(match[0]);
  return ids;
}

function expandTaskIdsOrdered(value) {
  const ids = [];
  const seen = new Set();
  const pattern = /M(\d+)-(\d{3})(?:~(?:M\1-)?(\d{3}))?/g;
  for (const match of value.matchAll(pattern)) {
    const milestone = match[1];
    const start = Number(match[2]);
    const end = Number(match[3] ?? match[2]);
    for (let number = start; number <= end; number += 1) {
      const id = `M${milestone}-${String(number).padStart(3, "0")}`;
      if (!seen.has(id)) {
        ids.push(id);
        seen.add(id);
      }
    }
  }
  return ids;
}

function parseWaveSchedule(markdown) {
  const leaves = new Map();
  for (const line of markdown.split("\n")) {
    const cells = parseCells(line);
    const waveMatch = /^`?D(\d+)-W(\d+)`?$/.exec(cells[0] ?? "");
    if (!waveMatch) continue;
    const wave = (Number(waveMatch[1]) - 1) * 6 + Number(waveMatch[2]);
    for (const cell of cells.slice(1)) {
      const leaf = /`(A\d{3})`/.exec(cell)?.[1];
      if (!leaf) continue;
      if (leaves.has(leaf)) fail(`WBS: duplicate leaf schedule ${leaf}`);
      leaves.set(leaf, { wave, tasks: expandTaskIdsOrdered(cell) });
    }
  }
  return leaves;
}

function validateWaveDependencies() {
  const tasks = parseTasks(read("docs/TASKLIST.md"));
  const en = parseWaveSchedule(read("docs/WBS.md"));
  const ko = parseWaveSchedule(read("docs/WBS.ko.md"));

  const leafIds = [...new Set([...en.keys(), ...ko.keys()])].sort();
  for (const leaf of leafIds) {
    if (!en.has(leaf) || !ko.has(leaf)) continue;
    if (JSON.stringify(en.get(leaf)) !== JSON.stringify(ko.get(leaf))) {
      fail(
        `WBS: ${leaf} wave or ordered Tasklist mapping differs between languages`,
      );
    }
  }

  const occurrence = new Map();
  for (const [leaf, entry] of en) {
    entry.tasks.forEach((task, position) => {
      const items = occurrence.get(task) ?? [];
      items.push({ leaf, wave: entry.wave, position });
      occurrence.set(task, items);
    });
  }

  for (const [id, task] of tasks) {
    const items = occurrence.get(id) ?? [];
    if (task.priority === "P0" && items.length !== 1) {
      fail(
        `WBS: P0 task ${id} must be scheduled exactly once (found ${items.length})`,
      );
    }
    if (items.length !== 1) continue;
    const current = items[0];
    for (const dependency of expandTaskIds(task.prerequisites)) {
      const prerequisites = occurrence.get(dependency) ?? [];
      if (prerequisites.length !== 1) continue;
      const prior = prerequisites[0];
      const sameLeafEarlier =
        prior.leaf === current.leaf &&
        prior.wave === current.wave &&
        prior.position < current.position;
      if (!(prior.wave < current.wave || sameLeafEarlier)) {
        fail(
          `WBS: ${id} in ${current.leaf}/wave ${current.wave} depends on ${dependency} ` +
            `in ${prior.leaf}/wave ${prior.wave}; prerequisite must be an earlier wave or earlier in the same leaf`,
        );
      }
    }
  }
}

function validateTaskDagAndCoverage() {
  const tasks = parseTasks(read("docs/TASKLIST.md"));
  for (const [id, task] of tasks) {
    for (const dependency of expandTaskIds(task.prerequisites)) {
      if (!tasks.has(dependency))
        fail(`Tasklist: ${id} has unknown dependency ${dependency}`);
    }
  }

  const visiting = new Set();
  const visited = new Set();
  function visit(id, trail) {
    if (visiting.has(id)) {
      fail(`Tasklist: dependency cycle ${[...trail, id].join(" -> ")}`);
      return;
    }
    if (visited.has(id)) return;
    visiting.add(id);
    for (const dependency of expandTaskIds(
      tasks.get(id)?.prerequisites ?? "",
    )) {
      visit(dependency, [...trail, id]);
    }
    visiting.delete(id);
    visited.add(id);
  }
  for (const id of tasks.keys()) visit(id, []);

  const leafMappings = parseLeafMappings(read("docs/WBS.md"));
  const mapped = new Set([...leafMappings.values()].flat());
  for (const [id, task] of tasks) {
    if (task.priority === "P0" && !mapped.has(id))
      fail(`WBS: P0 task ${id} is not mapped`);
  }
  for (const id of mapped) {
    if (!tasks.has(id)) fail(`WBS: leaf maps unknown task ${id}`);
    else if (tasks.get(id).priority !== "P0")
      fail(`WBS: release leaf maps non-P0 task ${id}`);
  }
}

function parseLeafMappings(markdown) {
  const leaves = new Map();
  for (const line of markdown.split("\n")) {
    for (const cell of parseCells(line)) {
      const leaf = /`(A\d{3})`/.exec(cell)?.[1];
      if (!leaf) continue;
      leaves.set(leaf, [...expandTaskIds(cell)].sort());
    }
  }
  return leaves;
}

function validateLeaves() {
  const en = parseLeafMappings(read("docs/WBS.md"));
  const ko = parseLeafMappings(read("docs/WBS.ko.md"));
  for (let number = 1; number <= 90; number += 1) {
    const id = `A${String(number).padStart(3, "0")}`;
    if (!en.has(id)) fail(`WBS: missing leaf ${id}`);
    if (!ko.has(id)) fail(`WBS.ko: missing leaf ${id}`);
    if (JSON.stringify(en.get(id)) !== JSON.stringify(ko.get(id))) {
      fail(`WBS: ${id} Tasklist mapping differs between languages`);
    }
  }
}

function validateReadmeQuotes() {
  const readme = read("README.md");
  for (const relative of [
    "docs/PRD.md",
    "docs/ADR.md",
    "docs/TDD.md",
    "docs/TASKLIST.md",
  ]) {
    const lines = read(relative).split("\n");
    for (let index = 0; index < lines.length; index += 1) {
      const quote = /^>\s+"([^"]+)"/.exec(lines[index])?.[1];
      if (!quote) continue;
      const attribution = lines.slice(index, index + 6).join("\n");
      if (/README/.test(attribution) && !readme.includes(quote)) {
        fail(`${relative}:${index + 1}: README quote is not exact`);
      }
    }
  }
}

function validateWhitespace() {
  for (const relative of [
    ...markdownFiles,
    ...contractFiles,
    ".env.example",
    ".gitignore",
    "scripts/validate-docs.mjs",
    "scripts/generate-contract-vectors.mjs",
    "scripts/preflight-nft-namespace.sh",
  ]) {
    const lines = read(relative).split("\n");
    lines.forEach((line, index) => {
      if (/[ \t]+$/.test(line))
        fail(`${relative}:${index + 1}: trailing whitespace`);
    });
  }
}

function validateContractSchemas() {
  for (const relative of contractJsonFiles) {
    let schema;
    try {
      schema = JSON.parse(read(relative));
    } catch (error) {
      fail(`${relative}: invalid JSON (${error.message})`);
      continue;
    }

    if (!relative.endsWith(".schema.json")) continue;

    function visit(node, pointer) {
      if (!node || typeof node !== "object") return;
      if (Array.isArray(node)) {
        node.forEach((child, index) => visit(child, `${pointer}/${index}`));
        return;
      }
      if (Object.hasOwn(node, "uniqueItems")) {
        fail(
          `${relative}:${pointer}: uniqueItems is forbidden in the contract pack`,
        );
      }
      if (node.type === "object") {
        if (node.additionalProperties !== false) {
          fail(
            `${relative}:${pointer}: object must set additionalProperties=false`,
          );
        }
        const properties = Object.keys(node.properties ?? {}).sort();
        const required = [...(node.required ?? [])].sort();
        if (JSON.stringify(properties) !== JSON.stringify(required)) {
          fail(
            `${relative}:${pointer}: every object property must be required`,
          );
        }
      }
      if (
        typeof node.$ref === "string" &&
        !node.$ref.startsWith("#") &&
        !/^https?:/.test(node.$ref)
      ) {
        const target = node.$ref.split("#", 1)[0];
        const absolute = path.resolve(
          path.dirname(path.join(root, relative)),
          target,
        );
        if (!fs.existsSync(absolute)) {
          fail(
            `${relative}:${pointer}: missing local schema reference ${node.$ref}`,
          );
        }
      }
      for (const [key, child] of Object.entries(node)) {
        visit(child, `${pointer}/${key}`);
      }
    }

    visit(schema, "#");
  }
}

function canonicalJson(value) {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string"
  ) {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      throw new Error(`contract data uses unsupported JCS number ${value}`);
    }
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  throw new Error(`contract data uses unsupported JCS type ${typeof value}`);
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function validateContractPack() {
  const bundle = JSON.parse(read("contracts/vectors/contract_vectors_v1.json"));
  const live = JSON.parse(
    read("contracts/enforcement/nft_base_chain_v1.live.json"),
  );
  const protectedIpv4 = JSON.parse(
    read("contracts/enforcement/protected_ipv4_v1.json"),
  );
  const dataset = JSON.parse(
    read("contracts/fixtures/demo_history_dataset_v1.json"),
  );
  const signedManifest = JSON.parse(
    read("contracts/fixtures/demo_history_manifest_v1.json"),
  );
  const artifactDigests = bundle.artifact_digests ?? {};

  const expectedDigests = new Map([
    [
      "nft_base_chain_raw_sha256",
      `sha256:${sha256Hex(read("contracts/enforcement/nft_base_chain_v1.nft"))}`,
    ],
    [
      "nft_base_chain_live_jcs_sha256",
      `sha256:${sha256Hex(canonicalJson(live))}`,
    ],
    [
      "protected_ipv4_jcs_sha256",
      `sha256:${sha256Hex(canonicalJson(protectedIpv4))}`,
    ],
    [
      "demo_history_dataset_jcs_sha256",
      `sha256:${sha256Hex(canonicalJson(dataset))}`,
    ],
    [
      "demo_history_source_health_jcs_sha256",
      `sha256:${sha256Hex(canonicalJson(dataset.source_health))}`,
    ],
  ]);
  for (const [name, expected] of expectedDigests) {
    if (artifactDigests[name] !== expected) {
      fail(
        `contracts/vectors/contract_vectors_v1.json: ${name} must equal ${expected}`,
      );
    }
  }

  const demoCidrs = protectedIpv4.entries
    .filter((entry) => entry.demo_exception_allowed)
    .flatMap((entry) => entry.cidrs)
    .sort();
  const expectedDemoCidrs = [
    "192.0.2.0/24",
    "198.51.100.0/24",
    "203.0.113.0/24",
  ];
  if (JSON.stringify(demoCidrs) !== JSON.stringify(expectedDemoCidrs)) {
    fail(
      "contracts/enforcement/protected_ipv4_v1.json: only the three RFC 5737 ranges may be demo-removable",
    );
  }
  if (
    protectedIpv4.authoritative_registry_url !==
    "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml"
  ) {
    fail(
      "contracts/enforcement/protected_ipv4_v1.json: authoritative IANA registry URL is not pinned",
    );
  }

  function inspectFixture(node, pointer = "#") {
    if (Array.isArray(node)) {
      node.forEach((child, index) =>
        inspectFixture(child, `${pointer}/${index}`),
      );
      return;
    }
    if (!node || typeof node !== "object") return;
    for (const [key, value] of Object.entries(node)) {
      if (
        [
          "path",
          "query",
          "raw_path",
          "raw_url",
          "authorization",
          "cookie",
        ].includes(key)
      ) {
        fail(
          `contracts/fixtures/demo_history_dataset_v1.json:${pointer}: forbidden field ${key}`,
        );
      }
      inspectFixture(value, `${pointer}/${key}`);
    }
  }
  inspectFixture(dataset);
  if (dataset.records.some((record) => record.service_label !== "demo-app")) {
    fail(
      "contracts/fixtures/demo_history_dataset_v1.json: every record service_label must be demo-app",
    );
  }
  if (
    Date.parse(dataset.coverage_end) - Date.parse(dataset.coverage_start) !==
    86400000
  ) {
    fail(
      "contracts/fixtures/demo_history_dataset_v1.json: coverage must be exactly 24 hours",
    );
  }
  const manifest = signedManifest.manifest ?? {};
  if (
    manifest.dataset_id !== dataset.dataset_id ||
    manifest.dataset_schema_version !== dataset.schema_version ||
    manifest.dataset_record_count !== dataset.records.length ||
    manifest.dataset_digest !==
      artifactDigests.demo_history_dataset_jcs_sha256 ||
    manifest.source_health_digest !==
      artifactDigests.demo_history_source_health_jcs_sha256 ||
    manifest.coverage_start !== dataset.coverage_start ||
    manifest.coverage_end !== dataset.coverage_end
  ) {
    fail(
      "contracts/fixtures/demo_history_manifest_v1.json: manifest does not bind the exact dataset and coverage",
    );
  }

  const hmacVector = bundle.vectors?.event_batch_hmac_v1;
  if (
    hmacVector?.hmac_input_contract !==
    "endpoint_path + LF + sender_id + LF + timestamp + LF + nonce + LF + hex(SHA256(raw_body))"
  ) {
    fail(
      "contracts/vectors/contract_vectors_v1.json: event HMAC input contract is not endpoint-bound",
    );
  }
  const endpoints = (hmacVector?.positive_cases ?? [])
    .map((item) => item.endpoint_path)
    .sort();
  if (
    JSON.stringify(endpoints) !==
    JSON.stringify(["/internal/v1/auth-events", "/internal/v1/gateway-events"])
  ) {
    fail(
      "contracts/vectors/contract_vectors_v1.json: both event endpoints need positive HMAC vectors",
    );
  }
  for (const item of hmacVector?.positive_cases ?? []) {
    const body = Buffer.from(item.raw_body_b64url, "base64url");
    const bodyDigest = sha256Hex(body);
    const sender = item.headers?.["X-Sentinel-Sender-ID"];
    const timestamp = item.headers?.["X-Sentinel-Timestamp"];
    const nonce = item.headers?.["X-Sentinel-Nonce"];
    const input = `${item.endpoint_path}\n${sender}\n${timestamp}\n${nonce}\n${bodyDigest}`;
    const signature = crypto
      .createHmac("sha256", Buffer.from(item.key_base64, "base64"))
      .update(input)
      .digest("hex");
    if (
      signature !== item.signature_hex ||
      Buffer.from(item.hmac_input_b64url, "base64url").toString("utf8") !==
        input
    ) {
      fail(
        `contracts/vectors/contract_vectors_v1.json: invalid HMAC vector ${item.case_id}`,
      );
    }
    if (JSON.parse(body).sender_id !== sender) {
      fail(
        `contracts/vectors/contract_vectors_v1.json: header/body sender mismatch in ${item.case_id}`,
      );
    }
  }

  const vectorNames = new Set();
  function collectVectorNames(node) {
    if (Array.isArray(node)) return node.forEach(collectVectorNames);
    if (!node || typeof node !== "object") return;
    if (typeof node.vector_name === "string") vectorNames.add(node.vector_name);
    Object.values(node).forEach(collectVectorNames);
  }
  collectVectorNames(bundle);
  for (const name of [
    "event-batch-hmac-v1",
    "capability-add-v1",
    "capability-revoke-v1",
    "capability-inspect-v1",
    "execution-result-applied-v1",
    "execution-result-recovered-active-v1",
    "execution-result-revoked-v1",
    "execution-result-inspect-absent-v1",
    "demo-history-v1",
    "ttl-canonical-v1",
  ]) {
    if (!vectorNames.has(name))
      fail(`contracts/vectors/contract_vectors_v1.json: missing ${name}`);
  }
}

function validateConfigurationBaseline() {
  const baseChainDigest = crypto
    .createHash("sha256")
    .update(read("contracts/enforcement/nft_base_chain_v1.nft"))
    .digest("hex");
  const liveSchemaDigest = sha256Hex(
    canonicalJson(
      JSON.parse(read("contracts/enforcement/nft_base_chain_v1.live.json")),
    ),
  );
  const protectedIpv4Digest = sha256Hex(
    canonicalJson(
      JSON.parse(read("contracts/enforcement/protected_ipv4_v1.json")),
    ),
  );
  const values = new Map();
  read(".env.example")
    .split("\n")
    .forEach((line, index) => {
      if (!line || line.startsWith("#")) return;
      const match = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line);
      if (!match) {
        fail(`.env.example:${index + 1}: invalid configuration line`);
        return;
      }
      if (values.has(match[1]))
        fail(`.env.example:${index + 1}: duplicate key ${match[1]}`);
      values.set(match[1], match[2]);
    });

  const expected = new Map([
    ["SENTINELFLOW_SERVICE_LABEL", "demo-app"],
    ["GATEWAY_PUBLIC_HOST", "localhost:8080"],
    ["DEMO_ORIGIN_HTTP_LISTEN_ADDR", "172.30.0.10:8081"],
    ["INTERNAL_API_INGEST_LISTEN_ADDR", "172.31.0.10:8082"],
    ["API_MANAGEMENT_LISTEN_ADDR", ":8083"],
    ["API_MANAGEMENT_PUBLISHED_HOST", "127.0.0.1"],
    ["GATEWAY_MAX_HEADER_BYTES", "32768"],
    ["GATEWAY_MAX_REQUEST_TARGET_BYTES", "4096"],
    ["GATEWAY_MAX_CLASSIFICATION_PATH_BYTES", "2048"],
    ["GATEWAY_MAX_BODY_BYTES", "10485760"],
    ["GATEWAY_EVENT_QUEUE_CAPACITY", "10000"],
    ["GATEWAY_EVENT_BATCH_SIZE", "100"],
    ["GATEWAY_EVENT_MAX_BATCH_BYTES", "262144"],
    [
      "AUTH_EVENT_SENDER_CHECKPOINT_FILE",
      "/var/lib/sentinelflow-auth-adapter/sender-state.json",
    ],
    ["EVENT_MAX_FUTURE_SKEW", "60s"],
    ["EVENT_MAX_PAST_SKEW", "5m"],
    ["PATH_CATALOG_VERSION", "path-catalog-v1"],
    [
      "DETECT_SUSPICIOUS_PATH_IDS",
      "admin_console,env_file,git_config,wp_admin,phpmyadmin,server_status,actuator_env,backup_archive",
    ],
    ["OPENAI_MODEL", "gpt-5.6-sol"],
    ["OPENAI_REASONING_EFFORT", "medium"],
    ["OPENAI_STORE", "false"],
    [
      "OPENAI_INPUT_SCHEMA_FILE",
      "contracts/ai/sentinelflow_analysis_input_v1.schema.json",
    ],
    [
      "OPENAI_SYSTEM_PROMPT_FILE",
      "contracts/ai/sentinelflow_system_prompt_v1.txt",
    ],
    [
      "OPENAI_OUTPUT_SCHEMA_FILE",
      "contracts/ai/sentinelflow_analysis_v1.schema.json",
    ],
    ["OPENAI_MAX_EVIDENCE_REFS", "50"],
    ["OPENAI_MAX_INPUT_BYTES", "12288"],
    ["OPENAI_MAX_OUTPUT_TOKENS", "2048"],
    ["OPENAI_DAILY_BUDGET_USD", "10"],
    ["NFT_FAMILY", "inet"],
    ["NFT_TABLE", "sentinelflow"],
    ["NFT_BLACKLIST_SET", "blacklist_ipv4"],
    ["NFT_INPUT_CHAIN", "gateway_input"],
    ["NFT_INPUT_PRIORITY", "0"],
    ["NFT_BASE_CHAIN_SCHEMA_VERSION", "nft-base-chain-v1"],
    ["NFT_BASE_CHAIN_EXPECTED_SHA256", baseChainDigest],
    [
      "NFT_BASE_CHAIN_LIVE_CONTRACT",
      "contracts/enforcement/nft_base_chain_v1.live.json",
    ],
    ["NFT_BASE_CHAIN_LIVE_EXPECTED_SHA256", liveSchemaDigest],
    ["PROTECTED_IPV4_CONTRACT", "contracts/enforcement/protected_ipv4_v1.json"],
    ["PROTECTED_IPV4_EXPECTED_SHA256", protectedIpv4Digest],
    ["EXECUTOR_MAX_FRAME_BYTES", "16384"],
    ["EXECUTOR_IO_TIMEOUT", "2s"],
    ["HIL_CHALLENGE_TTL", "5m"],
    ["BLOCK_TTL_MIN", "1m"],
    ["BLOCK_TTL_DEFAULT", "30m"],
    ["BLOCK_TTL_MAX", "24h"],
    ["VALIDATION_TTL", "5m"],
    ["APPROVAL_TTL", "5m"],
    ["HISTORICAL_IMPACT_LOOKBACK", "24h"],
    ["LIFECYCLE_SCHEDULER_ID", "lifecycle-scheduler-v1"],
    ["LIFECYCLE_LEASE_OWNER", "lifecycleworker-01"],
    ["LIFECYCLE_LEASE_DURATION", "10s"],
    ["LIFECYCLE_RETRY_BACKOFF", "1s"],
    ["LIFECYCLE_POLL_INTERVAL", "250ms"],
    ["LIFECYCLE_CLEANUP_TIMEOUT", "1s"],
    ["DEMO_TEST_CLOCK", "2026-07-18T02:00:00Z"],
    [
      "DEMO_HISTORY_FIXTURE_DATASET",
      "/app/contracts/fixtures/demo_history_dataset_v1.json",
    ],
    [
      "DEMO_HISTORY_SIGNED_ENVELOPE_FILE",
      "/run/sentinelflow-demo-history/signed-manifest.json",
    ],
    ["CONTRACT_VECTOR_BUNDLE", "contracts/vectors/contract_vectors_v1.json"],
    ["EVENT_EVIDENCE_RETENTION", "168h"],
    ["INCIDENT_AI_POLICY_RETENTION", "720h"],
    ["AUDIT_RETENTION", "2160h"],
  ]);
  for (const [key, wanted] of expected) {
    if (values.get(key) !== wanted) {
      fail(`.env.example: ${key} must equal ${JSON.stringify(wanted)}`);
    }
  }

  const secretOrLocalInputs = [
    "GATEWAY_TLS_CERT_FILE",
    "GATEWAY_TLS_KEY_FILE",
    "GATEWAY_EVENT_HMAC_KEY",
    "AUTH_EVENT_HMAC_KEY",
    "AUTH_ACCOUNT_HASH_KEY",
    "DATABASE_MIGRATION_URL",
    "DATABASE_API_URL",
    "DATABASE_WORKER_URL",
    "DATABASE_READ_URL",
    "DATABASE_DISPATCHER_URL",
    "DATABASE_RETENTION_URL",
    "DATABASE_LIFECYCLE_URL",
    "DATABASE_METRICS_URL",
    "OPENAI_API_KEY",
    "OPENAI_RATE_CARD_VERSION",
    "OPENAI_INPUT_USD_PER_1M_TOKENS",
    "OPENAI_CACHED_INPUT_USD_PER_1M_TOKENS",
    "OPENAI_OUTPUT_USD_PER_1M_TOKENS",
    "ADMIN_PASSWORD_ARGON2ID_HASH",
    "SESSION_HMAC_KEY",
    "DISPATCHER_SIGNING_PRIVATE_KEY_FILE",
    "EXECUTOR_DISPATCH_PUBLIC_KEY_FILE",
    "EXECUTOR_RESULT_PRIVATE_KEY_FILE",
    "DISPATCHER_RESULT_PUBLIC_KEY_FILE",
  ];
  for (const key of secretOrLocalInputs) {
    if (!values.has(key))
      fail(`.env.example: missing required local-input key ${key}`);
    else if (values.get(key) !== "")
      fail(`.env.example: ${key} must not contain a repository default`);
  }

  const generatedDemoPublicInputs = [
    "DEMO_HISTORY_PUBLIC_KEY_B64URL",
    "DEMO_HISTORY_RUN_SCOPE",
    "DEMO_HISTORY_IMPORT_ID",
    "DEMO_HISTORY_CLOCK_AT",
    "DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST",
  ];
  for (const key of generatedDemoPublicInputs) {
    if (!values.has(key))
      fail(`.env.example: missing generated demo public input ${key}`);
    else if (values.get(key) !== "")
      fail(`.env.example: ${key} must be generated per run`);
  }

  for (const key of [
    "DEMO_HISTORY_DATASET_EXPECTED_SHA256",
    "DEMO_HISTORY_FIXTURE_MANIFEST",
    "DEMO_HISTORY_PUBLIC_KEY_FILE",
    "DEMO_HISTORY_SIMULATOR_PRIVATE_KEY_FILE",
  ]) {
    if (values.has(key))
      fail(
        `.env.example: obsolete static demo-history authority ${key} is forbidden`,
      );
  }
}

validateLinks();
validatePairs();
validateTaskDagAndCoverage();
validateLeaves();
validateWaveDependencies();
validateReadmeQuotes();
validateWhitespace();
validateContractSchemas();
validateContractPack();
validateConfigurationBaseline();

if (errors.length > 0) {
  for (const error of errors) console.error(`ERROR: ${error}`);
  console.error(`FAILED: ${errors.length} documentation validation error(s)`);
  process.exit(1);
}

const tasks = parseTasks(read("docs/TASKLIST.md"));
const p0 = [...tasks.values()].filter((task) => task.priority === "P0").length;
console.log(
  `OK: ${markdownFiles.length} Markdown files, ${contractSchemaFiles.length} strict schemas, ${contractFiles.length} contract files, ${tasks.size} tasks (${p0} P0), 90 leaves; links, anchors, bilingual structure/IDs/metadata, DAG, WBS coverage/wave order, quotes, schemas/vectors/digests, config baseline, and whitespace`,
);
