#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const workspace = fs.realpathSync(process.cwd());
const target = path.join(workspace, ".env.local");
const envName = "OPENAI_API_KEY";

function fail(message) {
  process.stderr.write(`\n${message}\n`);
  process.exitCode = 1;
}

function assertSafeTarget() {
  const parent = fs.realpathSync(path.dirname(target));
  if (parent !== workspace) {
    throw new Error("refusing to write outside the workspace root");
  }

  try {
    const stat = fs.lstatSync(target);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
      throw new Error("refusing unsafe .env.local target");
    }
  } catch (error) {
    if (error?.code !== "ENOENT") {
      throw error;
    }
  }
}

function validateKey(value) {
  if (!value.startsWith("sk-") || value.length < 20 || /\s/u.test(value)) {
    throw new Error("the value does not look like an OpenAI API key");
  }
}

function upsertKey(value) {
  assertSafeTarget();

  let existing = "";
  try {
    existing = fs.readFileSync(target, "utf8");
  } catch (error) {
    if (error?.code !== "ENOENT") {
      throw error;
    }
  }

  const replacement = `${envName}=${value}`;
  const lines = existing.length === 0 ? [] : existing.replace(/\r\n/gu, "\n").split("\n");
  let replaced = false;
  const next = lines
    .filter((line, index) => index < lines.length - 1 || line.length > 0)
    .map((line) => {
      if (line.startsWith(`${envName}=`)) {
        if (replaced) {
          return null;
        }
        replaced = true;
        return replacement;
      }
      return line;
    })
    .filter((line) => line !== null);

  if (!replaced) {
    next.push(replacement);
  }

  const temp = path.join(workspace, `.env.local.${process.pid}.tmp`);
  const fd = fs.openSync(temp, "wx", 0o600);
  try {
    fs.writeFileSync(fd, `${next.join("\n")}\n`, "utf8");
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }

  try {
    assertSafeTarget();
    fs.renameSync(temp, target);
    fs.chmodSync(target, 0o600);
  } catch (error) {
    try {
      fs.unlinkSync(temp);
    } catch {
      // Best-effort cleanup only.
    }
    throw error;
  }
}

function checkSavedKey() {
  assertSafeTarget();
  const stat = fs.statSync(target);
  if ((stat.mode & 0o777) !== 0o600) {
    throw new Error(".env.local must have mode 0600");
  }
  const entries = fs
    .readFileSync(target, "utf8")
    .replace(/\r\n/gu, "\n")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
  if (entries.length !== 1 || !entries[0].startsWith(`${envName}=`)) {
    throw new Error(".env.local must contain exactly one OPENAI_API_KEY entry");
  }
  const value = entries[0].slice(`${envName}=`.length);
  validateKey(value);
}

if (process.argv.includes("--check")) {
  try {
    checkSavedKey();
    process.stdout.write("Verified local OPENAI_API_KEY storage without exposing its value.\n");
  } catch (error) {
    fail(error instanceof Error ? error.message : "failed to verify local key storage");
  }
} else if (process.argv.includes("--dialog")) {
  const appleScript = [
    'set response to display dialog "Enter the existing OpenAI API key. It will be saved only to .env.local as OPENAI_API_KEY." default answer "" with hidden answer buttons {"Cancel", "Save"} default button "Save" cancel button "Cancel" with title "SentinelFlow OpenAI API Key"',
    "return text returned of response",
  ].join("\n");
  const result = spawnSync("/usr/bin/osascript", ["-e", appleScript], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });

  if (result.status !== 0) {
    fail("Canceled without writing a key.");
  } else {
    const value = result.stdout.replace(/[\r\n]+$/u, "");
    try {
      validateKey(value);
      upsertKey(value);
      process.stdout.write("Saved OPENAI_API_KEY to .env.local with mode 0600.\n");
    } catch (error) {
      fail(error instanceof Error ? error.message : "failed to save key");
    }
  }
} else if (!process.stdin.isTTY || typeof process.stdin.setRawMode !== "function") {
  fail("Run this helper in an interactive Terminal.");
} else {
  process.stdout.write("OpenAI API key (hidden input, Enter to save, Ctrl-C to cancel): ");
  process.stdin.setEncoding("utf8");
  process.stdin.setRawMode(true);
  process.stdin.resume();

  let value = "";
  const restore = () => {
    if (process.stdin.isRaw) {
      process.stdin.setRawMode(false);
    }
    process.stdin.pause();
  };

  process.stdin.on("data", (chunk) => {
    for (const character of chunk) {
      if (character === "\u0003") {
        restore();
        fail("Canceled without writing a key.");
        return;
      }
      if (character === "\r" || character === "\n") {
        restore();
        try {
          validateKey(value);
          upsertKey(value);
          value = "";
          process.stdout.write("\nSaved OPENAI_API_KEY to .env.local with mode 0600.\n");
        } catch (error) {
          value = "";
          fail(error instanceof Error ? error.message : "failed to save key");
        }
        return;
      }
      if (character === "\u007f" || character === "\b") {
        value = value.slice(0, -1);
        continue;
      }
      if (character >= " " && character <= "~") {
        value += character;
      }
    }
  });
}
