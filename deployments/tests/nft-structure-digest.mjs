#!/usr/bin/env node

import { createHash } from "node:crypto";

const chunks = [];
let size = 0;
const maximumBytes = 16 * 1024 * 1024;

for await (const chunk of process.stdin) {
  size += chunk.length;
  if (size > maximumBytes) {
    throw new Error("nft ruleset input exceeds the diagnostic bound");
  }
  chunks.push(chunk);
}

const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
const normalized = normalize(parsed);
const digest = createHash("sha256")
  .update(JSON.stringify(normalized), "utf8")
  .digest("hex");
process.stdout.write(`sha256:${digest}\n`);

function normalize(value, parent = "") {
  if (Array.isArray(value)) {
    return value.map((item) => normalize(item, parent));
  }
  if (value === null || typeof value !== "object") {
    return value;
  }

  const result = {};
  for (const key of Object.keys(value).sort()) {
    if (
      key === "handle" ||
      key === "expires" ||
      key === "last" ||
      key === "used" ||
      (parent === "counter" && (key === "packets" || key === "bytes"))
    ) {
      continue;
    }
    result[key] = normalize(value[key], key);
  }
  return result;
}
