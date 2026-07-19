import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(new URL("./nft-structure-digest.mjs", import.meta.url));
const base = {
  nftables: [
    { table: { family: "inet", name: "example", handle: 1 } },
    {
      rule: {
        family: "inet",
        table: "example",
        chain: "input",
        handle: 2,
        expr: [{ counter: { packets: 1, bytes: 100 } }, { accept: null }],
      },
    },
  ],
};

const dynamic = structuredClone(base);
dynamic.nftables[0].table.handle = 90;
dynamic.nftables[1].rule.handle = 91;
dynamic.nftables[1].rule.expr[0].counter = { packets: 99, bytes: 9999 };

const changed = structuredClone(dynamic);
changed.nftables[1].rule.expr[1] = { drop: null };

const first = digest(base);
assert.equal(digest(dynamic), first, "dynamic handles and counters changed the structure digest");
assert.notEqual(digest(changed), first, "a semantic verdict change did not change the structure digest");

function digest(value) {
  const result = spawnSync(process.execPath, [script], {
    input: JSON.stringify(value),
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^sha256:[0-9a-f]{64}\n$/);
  return result.stdout;
}
