#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

import {
  approvedPrometheusImage,
  approvedTrivyDatabaseChecksums,
  buildSpdxDocument,
  inspectDockerfileText,
  inspectWorkflowText,
  inspectYamlImages,
  isExactNpmVersion,
  reviewedComposeCommands,
  reviewedComposeDependencies,
  reviewedComposeHealthchecks,
  reviewedComposeMounts,
  reviewedComposeVolumeNames,
  reviewedSensitiveEnvironmentFixedValues,
  reviewedSensitiveEnvironmentOwners,
  validateActionReference,
  validateComposeRuntimePolicy,
  validateComposeSourceBindPolicy,
  validateImageArchiveBinding,
  validateImageGateText,
  validateImageInspection,
  validateImageSpdxDocument,
  validateImageReference,
  validateObservabilityVerificationText,
  validatePrometheusImage,
  validateScannerDatabaseChecksums,
  validateScannerDatabaseMetadata,
  validateScannerVersionOutput,
  validateSpdxDocument,
  validateTrivyReport,
} from "./supply-chain-policy.mjs";

const actionSha = "34e114876b0b11c390a56381ad16ebd13914f8d5";
const imageDigest = `sha256:${"a".repeat(64)}`;
const imageID = `sha256:${"b".repeat(64)}`;
const analysisActivationPath =
  "/run/secrets/sentinelflow-demo-history-analysis/activation-capability";
const validationActivationPath =
  "/run/secrets/sentinelflow-demo-history-validation/activation-capability";

function volumeMount(source, target, readOnly) {
  const mount = {
    type: "volume",
    source,
    target,
    volume: {},
  };
  if (readOnly) {
    mount.read_only = true;
  }
  return mount;
}

function bindMount(source, target, readOnly) {
  const mount = {
    type: "bind",
    source,
    target,
    bind: {},
  };
  if (readOnly) {
    mount.read_only = true;
  }
  return mount;
}

function runtimeService(name, image, networks, extra = {}) {
  const command = reviewedComposeCommands[name];
  return {
    image,
    read_only: true,
    cap_drop: ["ALL"],
    security_opt: ["no-new-privileges:true"],
    entrypoint: null,
    ...(networks
      ? {
          networks: Object.fromEntries(
            networks.map((network) => [network, {}]),
          ),
        }
      : {}),
    ...(command === null ? {} : { command: [...command] }),
    ...extra,
  };
}

function demoHistoryProofEnvironment() {
  return {
    DEMO_HISTORY_SIGNED_ENVELOPE_FILE:
      "/run/sentinelflow-demo-history/signed-manifest.json",
    DEMO_HISTORY_PUBLIC_KEY_B64URL: "c".repeat(43),
    DEMO_HISTORY_RUN_SCOPE:
      "sentinelflow-demo-run:019b0000-0000-7000-8000-000000000901",
    DEMO_HISTORY_IMPORT_ID: "019b0000-0000-7000-8000-000000000902",
    DEMO_HISTORY_CLOCK_AT: "2026-07-18T02:00:00.000Z",
    DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST: `sha256:${"d".repeat(64)}`,
  };
}

function materializeReviewedMounts(services) {
  const sourceGroups = {
    "demo-history": "/tmp/sentinelflow-demo-history",
    "demo-secrets": "/tmp/sentinelflow-demo-secrets",
  };
  for (const [service, expectedMounts] of Object.entries(
    reviewedComposeMounts,
  )) {
    if (expectedMounts.length === 0) {
      continue;
    }
    services[service].volumes = expectedMounts.map((expected) => {
      const mount = {
        type: expected.type,
        source: expected.source ?? sourceGroups[expected.sourceGroup],
        target: expected.target,
        [expected.type]: structuredClone(expected[expected.type] || {}),
      };
      if (expected.readOnly) {
        mount.read_only = true;
      }
      return mount;
    });
  }
}

function materializeReviewedDependencies(services) {
  for (const [service, expectedDependencies] of Object.entries(
    reviewedComposeDependencies,
  )) {
    services[service].depends_on = Object.fromEntries(
      Object.entries(expectedDependencies).map(([dependency, edge]) => [
        dependency,
        structuredClone(edge),
      ]),
    );
  }
}

function materializeReviewedHealthchecks(services) {
  for (const [service, healthcheck] of Object.entries(
    reviewedComposeHealthchecks,
  )) {
    if (healthcheck !== null) {
      services[service].healthcheck = structuredClone(healthcheck);
    }
  }
}

function mergeServiceEnvironment(services, service, values) {
  services[service].environment = {
    ...(services[service].environment || {}),
    ...values,
  };
}

function materializeReviewedSensitiveEnvironment(services) {
  for (const [key, owners] of Object.entries(
    reviewedSensitiveEnvironmentOwners,
  )) {
    const value =
      reviewedSensitiveEnvironmentFixedValues[key] ??
      `synthetic-${key.toLowerCase().replaceAll("_", "-")}`;
    for (const owner of owners) {
      mergeServiceEnvironment(services, owner, { [key]: value });
    }
  }
}

function serviceMount(document, service, target) {
  const mount = document.services[service].volumes.find(
    (candidate) => candidate.target === target,
  );
  assert.ok(mount, `missing ${service} test mount at ${target}`);
  return mount;
}

function validComposeRuntime() {
  const backend = "sentinelflow/backend:demo";
  const postgres = "sentinelflow/postgres:demo";
  const web = "sentinelflow/web:demo";
  const document = {
    name: "sentinelflow",
    services: {
      api: runtimeService("api", backend, ["control", "ingest", "management"], {
        build: { dockerfile: "deployments/Dockerfile.backend" },
      }),
      controlmetricsexporter: runtimeService(
        "controlmetricsexporter",
        backend,
        ["control", "observability"],
      ),
      "demo-activation-handoff": runtimeService(
        "demo-activation-handoff",
        postgres,
        ["control"],
        { user: "70:70" },
      ),
      "demo-activator": runtimeService("demo-activator", backend, ["control"]),
      "demo-app": runtimeService("demo-app", backend, ["ingest", "origin"]),
      detector: runtimeService("detector", backend, ["control"]),
      dispatcher: runtimeService("dispatcher", backend, ["control"]),
      executor: runtimeService("executor", backend, null, {
        user: "0:65532",
        cap_add: ["NET_ADMIN"],
        network_mode: "service:gateway",
      }),
      gateway: runtimeService("gateway", backend, [
        "edge",
        "ingest",
        "observability",
        "origin",
      ]),
      "history-importer": runtimeService("history-importer", backend, [
        "control",
      ]),
      lifecycleworker: runtimeService("lifecycleworker", backend, ["control"]),
      migrate: runtimeService("migrate", postgres, ["control"], {
        user: "70:70",
      }),
      postgres: runtimeService("postgres", postgres, ["control"], {
        build: { dockerfile: "deployments/Dockerfile.postgres" },
        user: "70:70",
        tmpfs: [
          "/tmp:rw,noexec,nosuid,nodev,size=8m,mode=1777,uid=70,gid=70",
          "/var/run/postgresql:rw,noexec,nosuid,nodev,size=4m,mode=0750,uid=70,gid=70",
        ],
      }),
      prometheus: runtimeService(
        "prometheus",
        approvedPrometheusImage,
        ["observability"],
        { user: "65532:65532" },
      ),
      retentionworker: runtimeService("retentionworker", backend, ["control"]),
      "secret-init": runtimeService("secret-init", backend, null, {
        user: "0:0",
        cap_add: ["CHOWN", "DAC_OVERRIDE", "FOWNER"],
        network_mode: "none",
      }),
      simulator: runtimeService("simulator", backend, ["edge"]),
      stubworker: runtimeService("stubworker", backend, ["control"]),
      validationworker: runtimeService("validationworker", backend, [
        "control",
      ]),
      validator: runtimeService("validator", backend, null, {
        user: "0:65532",
        cap_add: ["NET_ADMIN"],
        network_mode: "none",
      }),
      web: runtimeService("web", web, ["management"], {
        build: { dockerfile: "deployments/Dockerfile.web" },
      }),
      worker: runtimeService("worker", backend, ["ai-egress", "control"]),
    },
    volumes: Object.fromEntries(
      Object.entries(reviewedComposeVolumeNames).map(([logicalName, name]) => [
        logicalName,
        { name },
      ]),
    ),
  };
  const services = document.services;
  materializeReviewedMounts(services);
  materializeReviewedDependencies(services);
  materializeReviewedHealthchecks(services);
  materializeReviewedSensitiveEnvironment(services);
  mergeServiceEnvironment(services, "migrate", {
    DATABASE_DEMO_IMPORTER_PASSWORD: "synthetic-demo-importer-password",
    PGPASSWORD: "synthetic-postgres-password",
  });
  mergeServiceEnvironment(services, "demo-activation-handoff", {
    DATABASE_DEMO_ACTIVATOR_PASSWORD: "synthetic-demo-activator-password",
    PGPASSWORD: "synthetic-postgres-password",
  });
  mergeServiceEnvironment(services, "history-importer", {
    DATABASE_DEMO_IMPORTER_URL:
      "postgresql://demo-importer.invalid/sentinelflow",
    DEMO_HISTORY_FIXTURE_DATASET:
      "/app/contracts/fixtures/demo_history_dataset_v1.json",
    ...demoHistoryProofEnvironment(),
  });
  mergeServiceEnvironment(services, "demo-activator", {
    DATABASE_DEMO_ACTIVATOR_URL:
      "postgresql://demo-activator.invalid/sentinelflow",
    ...demoHistoryProofEnvironment(),
    DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE: analysisActivationPath,
    DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE: validationActivationPath,
  });
  mergeServiceEnvironment(services, "stubworker", {
    ...demoHistoryProofEnvironment(),
    DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE: analysisActivationPath,
  });
  mergeServiceEnvironment(services, "worker", {
    ...demoHistoryProofEnvironment(),
    DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE: analysisActivationPath,
  });
  mergeServiceEnvironment(services, "validationworker", {
    ...demoHistoryProofEnvironment(),
    DEMO_HISTORY_VALIDATION_ACTIVATION_SECRET_FILE: validationActivationPath,
  });
  return document;
}

test("remote actions require a full commit SHA", () => {
  assert.doesNotThrow(() =>
    validateActionReference(`actions/checkout@${actionSha}`),
  );
  assert.doesNotThrow(() =>
    validateActionReference("./.github/actions/local-check"),
  );
  assert.throws(
    () => validateActionReference("actions/checkout@v4"),
    /full lowercase commit SHA/u,
  );
  assert.throws(
    () => validateActionReference("actions/checkout@main"),
    /full lowercase commit SHA/u,
  );
  assert.throws(
    () => validateActionReference("./../outside"),
    /escapes the repository/u,
  );
});

test("Docker actions and external images require sha256 digests", () => {
  assert.doesNotThrow(() =>
    validateActionReference(`docker://alpine:3.24@${imageDigest}`),
  );
  assert.throws(
    () => validateActionReference("docker://alpine:latest"),
    /sha256 digest/u,
  );
  assert.doesNotThrow(() =>
    validateImageReference(`postgres:17-alpine@${imageDigest}`),
  );
  assert.throws(
    () => validateImageReference("postgres:17-alpine"),
    /sha256 digest/u,
  );
  assert.doesNotThrow(() =>
    validateImageReference("sentinelflow/backend:demo", { locallyBuilt: true }),
  );
  assert.throws(
    () =>
      validateImageReference("${REGISTRY}/sentinelflow/backend:demo", {
        locallyBuilt: true,
      }),
    /dynamically selected/u,
  );
});

test("Prometheus requires the reviewed distroless release and digest", () => {
  const approved =
    "prom/prometheus:v3.13.1-distroless@sha256:214f8427c8fba80c327bb94a75feb802ae12f2d6ca30812aa6e7d22f09bbea80";
  assert.doesNotThrow(() => validatePrometheusImage(approved));
  assert.throws(
    () =>
      validatePrometheusImage(
        "prom/prometheus:v3.13.1@sha256:214f8427c8fba80c327bb94a75feb802ae12f2d6ca30812aa6e7d22f09bbea80",
      ),
    /distroless/u,
  );
  assert.throws(
    () =>
      validatePrometheusImage(
        `prom/prometheus:v3.13.1-distroless@${imageDigest}`,
      ),
    /distroless/u,
  );
});

test("observability verification pulls the exact digest before inspection", () => {
  const approved =
    "prom/prometheus:v3.13.1-distroless@sha256:214f8427c8fba80c327bb94a75feb802ae12f2d6ca30812aa6e7d22f09bbea80";
  assert.doesNotThrow(() =>
    validateObservabilityVerificationText(
      `image="${approved}"\ndocker pull "$image"\ndocker image inspect "$image"\n`,
      "verify.sh",
    ),
  );
  assert.throws(
    () =>
      validateObservabilityVerificationText(
        `image="${approved}"\ndocker image inspect "$image"\ndocker pull "$image"\n`,
        "verify.sh",
      ),
    /pull the exact Prometheus digest before inspection/u,
  );
});

test("image gate pins scanner, database, and networkless scan authority", () => {
  const text = [
    'buildkit_builder_image="moby/buildkit:v0.23.2@sha256:ddd1ca44b21eda906e81ab14a3d467fa6c39cd73b9a39df1196210edcb8db59e"',
    `scanner_image="aquasec/trivy:0.70.0@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e"`,
    `scanner_database="ghcr.io/aquasecurity/trivy-db:2@sha256:dfb24f192c02d06a1c467c87177b61e67bfb816d86b6d8d55d52e29329f83035"`,
    `prometheus_image="${approvedPrometheusImage}"`,
    "images: reproducible no-cache application builds",
    "images: unprivileged read-only runtime dependency probes",
    "find /app/contracts -type d",
    '"555:0:0"',
    "find /app/contracts -type f",
    '"444:0:0"',
    "/etc/nginx/conf.d/default.conf",
    '"101:101"',
    "find /usr/share/nginx/html -type d",
    "find /usr/share/nginx/html -type f",
    'docker pull "$scanner_image"',
    "docker buildx create --driver-opt image=$buildkit_builder_image",
    "verify-scanner-version",
    "verify-scanner-db",
    "verify-image-archive",
    "--severity CRITICAL",
    "verify-vulnerability-report",
    "verify-image-sbom",
    "nft --version",
    "/etc/ssl/certs/ca-certificates.crt",
    "--read-only",
    "--cap-drop ALL",
    "--network none",
    "--network none",
    "--network none",
    "--network none",
    'demo_analysis_receipt="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"',
    'demo_validation_receipt="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"',
    'demo_receipt_volume="sentinelflow-postgres-demo-receipts-$run_id"',
    '--env "ANALYSIS_RECEIPT=$demo_analysis_receipt"',
    '--env "VALIDATION_RECEIPT=$demo_validation_receipt"',
    'chown 0:70 /receipts /receipts/analysis.sha256 /receipts/validation.sha256',
    'chmod 0440 /receipts/analysis.sha256 /receipts/validation.sha256',
    'find /receipts -mindepth 1 -maxdepth 1 | wc -l',
    'type=volume,source=$demo_receipt_volume,target=/run/sentinelflow-demo-history-capability-receipts,readonly',
  ].join("\n");
  assert.doesNotThrow(() => validateImageGateText(text));
  assert.throws(
    () => validateImageGateText(text.replace("0.70.0@", "latest@")),
    /does not pin the reviewed scanner_image/u,
  );
  assert.throws(
    () => validateImageGateText(`${text}\n--ignore-unfixed`),
    /weakens scanner coverage/u,
  );
  assert.throws(
    () =>
      validateImageGateText(
        text.replace(
          "images: unprivileged read-only runtime dependency probes",
          "runtime dependency probes",
        ),
      ),
    /fail fast on runtime probes/u,
  );
  assert.throws(
    () => validateImageGateText(text.replace('"555:0:0"', '"755:0:0"')),
    /reviewed isolation/u,
  );
  assert.throws(
    () =>
      validateImageGateText(
        text.replace("find /usr/share/nginx/html -type f", "static files"),
      ),
    /reviewed isolation/u,
  );
  assert.throws(
    () => validateImageGateText(text.replace('chmod 0440 /receipts/analysis.sha256 /receipts/validation.sha256', 'chmod 0644 /receipts/analysis.sha256 /receipts/validation.sha256')),
    /synthetic demo capability receipts/u,
  );
});

test("workflow scanner rejects mutable refs with the exact file and line", () => {
  assert.equal(
    inspectWorkflowText(
      `steps:\n  - uses: actions/checkout@${actionSha} # v4\n`,
      "ci.yml",
    ),
    1,
  );
  assert.throws(
    () =>
      inspectWorkflowText("steps:\n  - uses: actions/checkout@v4\n", "ci.yml"),
    /ci\.yml:2/u,
  );
});

test("YAML image scanner permits only local build tags or external digests", () => {
  const valid = `services:\n  local:\n    image: sentinelflow/backend:demo\n    build:\n      context: .\n  db:\n    image: postgres:17-alpine@${imageDigest}\n`;
  assert.equal(inspectYamlImages(valid, "compose.yaml"), 2);
  assert.throws(
    () =>
      inspectYamlImages(
        "services:\n  db:\n    image: postgres:17-alpine\n",
        "compose.yaml",
      ),
    /compose\.yaml:3/u,
  );
});

test("Dockerfile scanner rejects a mutable base image", () => {
  assert.equal(
    inspectDockerfileText(
      `# syntax=docker/dockerfile:1.12@${imageDigest}\nFROM golang:1.25.12@${imageDigest} AS build\nFROM scratch\n`,
    ),
    2,
  );
  assert.throws(
    () =>
      inspectDockerfileText(
        `# syntax=docker/dockerfile:1.12@${imageDigest}\nFROM alpine:latest\n`,
      ),
    /sha256 digest/u,
  );
  assert.throws(
    () =>
      inspectDockerfileText(
        `# syntax=docker/dockerfile:1.12\nFROM alpine:3.24@${imageDigest}\n`,
      ),
    /Dockerfile>:1.*sha256 digest/u,
  );
});

test("backend Dockerfile normalizes copied contract ownership and modes", () => {
  const backendDockerfile = `# syntax=docker/dockerfile:1.12@${imageDigest}
FROM alpine:3.24@${imageDigest}
WORKDIR /app
COPY --chown=0:0 contracts ./contracts
RUN find /app/contracts -type d -exec chmod 0555 {} + \\
    && find /app/contracts -type f -exec chmod 0444 {} +
`;
  assert.equal(
    inspectDockerfileText(backendDockerfile, "deployments/Dockerfile.backend"),
    1,
  );
  assert.throws(
    () =>
      inspectDockerfileText(
        backendDockerfile.replace("--chown=0:0 ", ""),
        "deployments/Dockerfile.backend",
      ),
    /copied as root:root/u,
  );
  assert.throws(
    () =>
      inspectDockerfileText(
        backendDockerfile.replace("chmod 0555", "chmod 0755"),
        "deployments/Dockerfile.backend",
      ),
    /directories must be normalized to 0555/u,
  );
  assert.throws(
    () =>
      inspectDockerfileText(
        backendDockerfile.replace("chmod 0444", "chmod 0644"),
        "deployments/Dockerfile.backend",
      ),
    /regular files must be normalized to 0444/u,
  );
});

test("web Dockerfile normalizes nginx configuration and static asset modes", () => {
  const webDockerfile = `# syntax=docker/dockerfile:1.12@${imageDigest}
FROM node:24.13.0@${imageDigest} AS build
FROM nginx:1.29.5@${imageDigest}
USER 0:0
COPY --chown=0:0 deployments/nginx.conf /etc/nginx/conf.d/default.conf
COPY --chown=0:0 --from=build /src/web/dist/ /usr/share/nginx/html/
RUN chmod 0444 /etc/nginx/conf.d/default.conf \\
    && find /usr/share/nginx/html -type d -exec chmod 0555 {} + \\
    && find /usr/share/nginx/html -type f -exec chmod 0444 {} +
USER 101:101
`;
  assert.equal(
    inspectDockerfileText(webDockerfile, "deployments/Dockerfile.web"),
    2,
  );
  assert.throws(
    () =>
      inspectDockerfileText(
        webDockerfile.replace(
          "COPY --chown=0:0 deployments/nginx.conf",
          "COPY deployments/nginx.conf",
        ),
        "deployments/Dockerfile.web",
      ),
    /configuration must be copied as root:root/u,
  );
  assert.throws(
    () =>
      inspectDockerfileText(
        webDockerfile.replace(
          "COPY --chown=0:0 --from=build",
          "COPY --from=build",
        ),
        "deployments/Dockerfile.web",
      ),
    /static files must be copied as root:root/u,
  );
  assert.throws(
    () =>
      inspectDockerfileText(
        webDockerfile.replace("USER 0:0\n", ""),
        "deployments/Dockerfile.web",
      ),
    /normalization must run as build-time root/u,
  );
  assert.throws(
    () =>
      inspectDockerfileText(
        webDockerfile.replace("chmod 0444 /etc/nginx", "chmod 0644 /etc/nginx"),
        "deployments/Dockerfile.web",
      ),
    /configuration must be normalized to 0444/u,
  );
  assert.throws(
    () =>
      inspectDockerfileText(
        webDockerfile.replace("chmod 0555", "chmod 0755"),
        "deployments/Dockerfile.web",
      ),
    /directories must be normalized to 0555/u,
  );
  assert.throws(
    () =>
      inspectDockerfileText(
        webDockerfile.replace("chmod 0444 {} +", "chmod 0644 {} +"),
        "deployments/Dockerfile.web",
      ),
    /regular files must be normalized to 0444/u,
  );
  assert.throws(
    () =>
      inspectDockerfileText(
        webDockerfile.replace("USER 101:101\n", ""),
        "deployments/Dockerfile.web",
      ),
    /restore runtime user 101:101/u,
  );
});

test("npm dependency requirements must use exact versions", () => {
  assert.equal(isExactNpmVersion("1.2.3"), true);
  assert.equal(isExactNpmVersion("1.2.3-rc.1"), true);
  for (const version of [
    "^1.2.3",
    "~1.2.3",
    "latest",
    "git+https://example.invalid/repo.git",
    "file:../pkg",
  ]) {
    assert.equal(isExactNpmVersion(version), false, version);
  }
});

test("SPDX builder is deterministic and validator rejects duplicate IDs", () => {
  const input = {
    goModules: [
      {
        modulePath: "example.invalid/module",
        version: "v1.2.3",
        sum: `h1:${Buffer.alloc(32, 1).toString("base64")}`,
      },
    ],
    npmLock: {
      name: "example-web",
      version: "0.1.0",
      packages: {
        "": { name: "example-web", version: "0.1.0" },
        "node_modules/example-package": {
          version: "2.3.4",
          resolved:
            "https://registry.npmjs.org/example-package/-/example-package-2.3.4.tgz",
          integrity: `sha512-${Buffer.alloc(64, 2).toString("base64")}`,
          license: "MIT",
        },
        "node_modules/@example/scoped-package": {
          version: "3.4.5",
          resolved:
            "https://registry.npmjs.org/@example/scoped-package/-/scoped-package-3.4.5.tgz",
          integrity: `sha512-${Buffer.alloc(64, 3).toString("base64")}`,
          license: "MIT",
        },
      },
    },
    inputDigest: "b".repeat(64),
    created: "1970-01-01T00:00:00Z",
  };
  const first = buildSpdxDocument(input);
  const second = buildSpdxDocument(input);
  assert.deepEqual(first, second);
  assert.doesNotThrow(() => validateSpdxDocument(first));
  assert.ok(
    first.packages.some((packageEntry) =>
      packageEntry.externalRefs?.some(
        (reference) =>
          reference.referenceLocator ===
          "pkg:npm/%40example/scoped-package@3.4.5",
      ),
    ),
  );

  const duplicate = structuredClone(first);
  duplicate.packages[1].SPDXID = duplicate.packages[0].SPDXID;
  assert.throws(() => validateSpdxDocument(duplicate), /duplicate SPDXID/u);
});

test("scanner and frozen database verification fail closed", () => {
  assert.doesNotThrow(() => validateScannerVersionOutput("Version: 0.70.0\n"));
  for (const output of ["", "Version: 0.70.1\n", "scanner unavailable\n"]) {
    assert.throws(
      () => validateScannerVersionOutput(output),
      /exact version 0\.70\.0/u,
    );
  }
  assert.doesNotThrow(() =>
    validateScannerDatabaseChecksums({ ...approvedTrivyDatabaseChecksums }),
  );
  assert.throws(
    () =>
      validateScannerDatabaseChecksums({
        ...approvedTrivyDatabaseChecksums,
        "trivy.db": "0".repeat(64),
      }),
    /checksum mismatch/u,
  );
  assert.throws(
    () =>
      validateScannerDatabaseChecksums({
        ...approvedTrivyDatabaseChecksums,
        "unexpected.db": "0".repeat(64),
      }),
    /files differ/u,
  );
  assert.doesNotThrow(() =>
    validateScannerDatabaseMetadata(
      {
        Version: 2,
        NextUpdate: "2026-07-19T18:43:59.213935938Z",
        UpdatedAt: "2026-07-18T18:43:59.213936274Z",
        DownloadedAt: "2026-07-18T20:00:00Z",
      },
      new Date("2026-07-18T20:00:01Z"),
    ),
  );
  assert.throws(
    () =>
      validateScannerDatabaseMetadata(
        {
          Version: 2,
          NextUpdate: "2026-07-19T18:43:59.213935938Z",
          UpdatedAt: "2026-07-18T18:43:59.213936274Z",
          DownloadedAt: "2026-07-18T20:00:00Z",
        },
        new Date("2026-07-18T19:00:00Z"),
      ),
    /acquisition window/u,
  );
});

test("image inspection requires the reviewed non-root user and entrypoint", () => {
  const inspection = [
    {
      Id: imageID,
      Os: "linux",
      Architecture: "amd64",
      Config: {
        User: "65532:65532",
        Entrypoint: null,
        Cmd: ["/usr/local/bin/api"],
        ExposedPorts: null,
      },
    },
  ];
  assert.doesNotThrow(() => validateImageInspection("backend", inspection));
  inspection[0].Config.User = "";
  assert.throws(
    () => validateImageInspection("backend", inspection),
    /wrong non-root user/u,
  );
});

test("image archive binds the inspected manifest and scanner config IDs", () => {
  const manifestID = `sha256:${"c".repeat(64)}`;
  const configDigest = "d".repeat(64);
  const layerDigest = "e".repeat(64);
  const indexDocument = {
    schemaVersion: 2,
    manifests: [{ digest: manifestID }],
  };
  const dockerManifest = [
    {
      Config: `blobs/sha256/${configDigest}`,
      Layers: [`blobs/sha256/${layerDigest}`],
    },
  ];
  assert.deepEqual(
    validateImageArchiveBinding(indexDocument, dockerManifest, manifestID),
    {
      imageConfigID: `sha256:${configDigest}`,
      configPath: `blobs/sha256/${configDigest}`,
    },
  );
  assert.throws(
    () =>
      validateImageArchiveBinding(
        indexDocument,
        dockerManifest,
        `sha256:${"f".repeat(64)}`,
      ),
    /manifest ID does not match/u,
  );
  const duplicateLayer = structuredClone(dockerManifest);
  duplicateLayer[0].Layers.push(duplicateLayer[0].Layers[0]);
  assert.throws(
    () =>
      validateImageArchiveBinding(indexDocument, duplicateLayer, manifestID),
    /duplicate layers/u,
  );
});

test("Compose runtime policy rejects wrong capability and network authority", () => {
  const baseline = validComposeRuntime();
  assert.doesNotThrow(() => validateComposeRuntimePolicy(baseline));

  const wrongCapability = structuredClone(baseline);
  wrongCapability.services.gateway.cap_add = ["NET_ADMIN"];
  assert.throws(
    () => validateComposeRuntimePolicy(wrongCapability),
    /gateway capability add set differs/u,
  );

  const wrongNetwork = structuredClone(baseline);
  wrongNetwork.services.gateway.networks.control = {};
  assert.throws(
    () => validateComposeRuntimePolicy(wrongNetwork),
    /gateway network attachment differs/u,
  );

  const missingActivator = structuredClone(baseline);
  delete missingActivator.services["demo-activator"];
  assert.throws(
    () => validateComposeRuntimePolicy(missingActivator),
    /Compose service inventory differs/u,
  );

  const activatorEgress = structuredClone(baseline);
  activatorEgress.services["demo-activator"].networks["ai-egress"] = {};
  assert.throws(
    () => validateComposeRuntimePolicy(activatorEgress),
    /demo-activator network attachment differs/u,
  );

  const wrongActivatorCommand = structuredClone(baseline);
  wrongActivatorCommand.services["demo-activator"].command = [
    "/usr/local/bin/worker",
  ];
  assert.throws(
    () => validateComposeRuntimePolicy(wrongActivatorCommand),
    /demo-activator has an unexpected command/u,
  );
});

test("Compose runtime policy freezes every normalized command argument and shell byte", () => {
  assert.doesNotThrow(() =>
    validateComposeRuntimePolicy(validComposeRuntime()),
  );

  const changedShellArgv = validComposeRuntime();
  changedShellArgv.services.executor.command[1] = "-e";
  assert.throws(
    () => validateComposeRuntimePolicy(changedShellArgv),
    /executor has an unexpected command/u,
  );

  const changedExecutorScript = validComposeRuntime();
  changedExecutorScript.services.executor.command[3] = `printf unreviewed-side-effect\n${changedExecutorScript.services.executor.command[3]}`;
  assert.throws(
    () => validateComposeRuntimePolicy(changedExecutorScript),
    /executor has an unexpected command/u,
  );

  const changedSecretInitScript = validComposeRuntime();
  changedSecretInitScript.services["secret-init"].command[3] +=
    "printf leaked-capability\n";
  assert.throws(
    () => validateComposeRuntimePolicy(changedSecretInitScript),
    /secret-init has an unexpected command/u,
  );

  const changedDirectArgument = validComposeRuntime();
  changedDirectArgument.services.simulator.command[
    changedDirectArgument.services.simulator.command.length - 1
  ] = "path-scan";
  assert.throws(
    () => validateComposeRuntimePolicy(changedDirectArgument),
    /simulator has an unexpected command/u,
  );

  const appendedDirectArgument = validComposeRuntime();
  appendedDirectArgument.services.worker.command.push("--unreviewed");
  assert.throws(
    () => validateComposeRuntimePolicy(appendedDirectArgument),
    /worker has an unexpected command/u,
  );

  const changedHandoffCommand = validComposeRuntime();
  changedHandoffCommand.services["demo-activation-handoff"].command = [
    "/bin/sh",
    "-c",
    "printf unreviewed-handoff",
  ];
  assert.throws(
    () => validateComposeRuntimePolicy(changedHandoffCommand),
    /demo-activation-handoff has an unexpected command/u,
  );
});

test("Compose runtime policy freezes healthcheck commands and lifecycle command channels", () => {
  assert.doesNotThrow(() =>
    validateComposeRuntimePolicy(validComposeRuntime()),
  );

  const executorHealthcheckBypass = validComposeRuntime();
  executorHealthcheckBypass.services.executor.healthcheck.test = [
    "CMD-SHELL",
    "nft flush ruleset; test -S /run/sentinelflow-executor/executor.sock",
  ];
  assert.throws(
    () => validateComposeRuntimePolicy(executorHealthcheckBypass),
    /executor healthcheck command differs/u,
  );

  const extendedHealthcheck = validComposeRuntime();
  extendedHealthcheck.services.prometheus.healthcheck.test.push("--unreviewed");
  assert.throws(
    () => validateComposeRuntimePolicy(extendedHealthcheck),
    /prometheus healthcheck command differs/u,
  );

  for (const [field, value] of [
    ["interval", "1s"],
    ["timeout", "30s"],
    ["retries", 1],
    ["start_period", "30s"],
  ]) {
    const changedTiming = validComposeRuntime();
    changedTiming.services.executor.healthcheck[field] = value;
    assert.throws(
      () => validateComposeRuntimePolicy(changedTiming),
      new RegExp(`executor healthcheck ${field} differs`, "u"),
    );
  }

  const addedHealthcheck = validComposeRuntime();
  addedHealthcheck.services.dispatcher.healthcheck = {
    test: ["CMD-SHELL", "nft flush ruleset"],
    interval: "1s",
    timeout: "1s",
    retries: 1,
    start_period: "0s",
  };
  assert.throws(
    () => validateComposeRuntimePolicy(addedHealthcheck),
    /dispatcher must not define a healthcheck/u,
  );

  const addedHandoffHealthcheck = validComposeRuntime();
  addedHandoffHealthcheck.services["demo-activation-handoff"].healthcheck = {
    test: ["CMD-SHELL", "printf unreviewed-handoff-healthcheck"],
    interval: "1s",
    timeout: "1s",
    retries: 1,
    start_period: "0s",
  };
  assert.throws(
    () => validateComposeRuntimePolicy(addedHandoffHealthcheck),
    /demo-activation-handoff must not define a healthcheck/u,
  );

  const removedHealthcheck = validComposeRuntime();
  delete removedHealthcheck.services.api.healthcheck;
  assert.throws(
    () => validateComposeRuntimePolicy(removedHealthcheck),
    /api healthcheck is unavailable or invalid/u,
  );

  const extraHealthcheckField = validComposeRuntime();
  extraHealthcheckField.services.web.healthcheck.start_interval = "1s";
  assert.throws(
    () => validateComposeRuntimePolicy(extraHealthcheckField),
    /web healthcheck fields differ/u,
  );

  for (const [service, hook] of [
    ["executor", "post_start"],
    ["secret-init", "pre_stop"],
    ["dispatcher", "lifecycle"],
    ["validator", "lifecycle_hooks"],
  ]) {
    const alternateHook = validComposeRuntime();
    alternateHook.services[service][hook] = [
      { command: ["/bin/sh", "-c", "nft flush ruleset"] },
    ];
    assert.throws(
      () => validateComposeRuntimePolicy(alternateHook),
      new RegExp(`${service} must not define the ${hook} lifecycle hook`, "u"),
    );
  }
});

test("Compose runtime policy freezes sensitive environment owners and paths", () => {
  assert.doesNotThrow(() =>
    validateComposeRuntimePolicy(validComposeRuntime()),
  );

  for (const [service, key, value] of [
    ["api", "DATABASE_DISPATCHER_URL", "postgresql://crossed.invalid/db"],
    ["worker", "DATABASE_API_PASSWORD", "crossed-password"],
    [
      "api",
      "DISPATCHER_SIGNING_PRIVATE_KEY_FILE",
      "/run/secrets/sentinelflow/dispatcher-capability-private.pem",
    ],
    ["api", "EXECUTOR_SOCKET", "/run/sentinelflow-executor/executor.sock"],
    ["dispatcher", "OPENAI_API_KEY", "crossed-openai-key"],
  ]) {
    const crossedOwner = validComposeRuntime();
    mergeServiceEnvironment(crossedOwner.services, service, { [key]: value });
    assert.throws(
      () => validateComposeRuntimePolicy(crossedOwner),
      new RegExp(`sensitive environment ownership differs for ${key}`, "u"),
    );
  }

  const missingDatabasePassword = validComposeRuntime();
  delete missingDatabasePassword.services.migrate.environment
    .DATABASE_READ_PASSWORD;
  assert.throws(
    () => validateComposeRuntimePolicy(missingDatabasePassword),
    /sensitive environment ownership differs for DATABASE_READ_PASSWORD/u,
  );

  const wrongSigningKeyPath = validComposeRuntime();
  wrongSigningKeyPath.services.dispatcher.environment.DISPATCHER_SIGNING_PRIVATE_KEY_FILE =
    "/tmp/unreviewed-private.pem";
  assert.throws(
    () => validateComposeRuntimePolicy(wrongSigningKeyPath),
    /dispatcher sensitive environment fixed value differs for DISPATCHER_SIGNING_PRIVATE_KEY_FILE/u,
  );

  const wrongExecutorSocket = validComposeRuntime();
  wrongExecutorSocket.services.executor.environment.EXECUTOR_SOCKET =
    "/tmp/unreviewed-executor.sock";
  assert.throws(
    () => validateComposeRuntimePolicy(wrongExecutorSocket),
    /executor sensitive environment fixed value differs for EXECUTOR_SOCKET/u,
  );

  const wrongPrivateKeyPath = validComposeRuntime();
  wrongPrivateKeyPath.services.executor.environment.EXECUTOR_RESULT_PRIVATE_KEY_FILE =
    "/tmp/unreviewed-result-private.pem";
  assert.throws(
    () => validateComposeRuntimePolicy(wrongPrivateKeyPath),
    /executor sensitive environment fixed value differs for EXECUTOR_RESULT_PRIVATE_KEY_FILE/u,
  );

  const crossedHandoffPassword = validComposeRuntime();
  mergeServiceEnvironment(crossedHandoffPassword.services, "migrate", {
    DATABASE_DEMO_ACTIVATOR_PASSWORD: "crossed-activator-password",
  });
  assert.throws(
    () => validateComposeRuntimePolicy(crossedHandoffPassword),
    /demo activation environment ownership differs for DATABASE_DEMO_ACTIVATOR_PASSWORD/u,
  );

  const missingHandoffPassword = validComposeRuntime();
  delete missingHandoffPassword.services["demo-activation-handoff"].environment
    .DATABASE_DEMO_ACTIVATOR_PASSWORD;
  assert.throws(
    () => validateComposeRuntimePolicy(missingHandoffPassword),
    /demo activation environment ownership differs for DATABASE_DEMO_ACTIVATOR_PASSWORD/u,
  );

  for (const [key, value] of [
    ["DATABASE_UNREVIEWED_URL", "postgresql://unreviewed.invalid/db"],
    ["DATABASE_UNREVIEWED_PASSWORD", "unreviewed-password"],
    ["UNREVIEWED_PRIVATE_KEY_FILE", "/tmp/unreviewed-private.pem"],
    ["UNREVIEWED_SOCKET", "/tmp/unreviewed.sock"],
    ["UNREVIEWED_CAPABILITY_FILE", "/tmp/unreviewed.capability"],
    ["UNREVIEWED_ACTIVATION_SECRET_FILE", "/tmp/unreviewed-activation"],
  ]) {
    const unreviewedAuthority = validComposeRuntime();
    mergeServiceEnvironment(unreviewedAuthority.services, "api", {
      [key]: value,
    });
    assert.throws(
      () => validateComposeRuntimePolicy(unreviewedAuthority),
      new RegExp(
        `api has an unreviewed authority-bearing environment field ${key}`,
        "u",
      ),
    );
  }
});

test("Compose runtime policy freezes complete mount and top-level volume inventories", () => {
  assert.doesNotThrow(() =>
    validateComposeRuntimePolicy(validComposeRuntime()),
  );

  for (const source of [
    "demo-history-capability-receipts",
    "executor-secrets",
    "dispatcher-secrets",
    "executor-socket",
    "validator-socket",
    "executor-readiness",
    "executor-state",
  ]) {
    const leakedAuthority = validComposeRuntime();
    leakedAuthority.services.api.volumes = [
      volumeMount(source, `/run/unreviewed-${source}`, true),
    ];
    assert.throws(
      () => validateComposeRuntimePolicy(leakedAuthority),
      /api mount inventory differs/u,
    );
  }

  const rawSecretReuse = validComposeRuntime();
  const secretSource = serviceMount(
    rawSecretReuse,
    "secret-init",
    "/source",
  ).source;
  rawSecretReuse.services.api.volumes = [
    bindMount(secretSource, "/run/unreviewed-demo-secrets", true),
  ];
  assert.throws(
    () => validateComposeRuntimePolicy(rawSecretReuse),
    /api mount inventory differs/u,
  );

  const alternateSecretMount = validComposeRuntime();
  alternateSecretMount.services.api.secrets = [
    { source: "unreviewed", target: "/run/secrets/unreviewed" },
  ];
  alternateSecretMount.secrets = {
    unreviewed: { file: "/tmp/unreviewed-secret" },
  };
  assert.throws(
    () => validateComposeRuntimePolicy(alternateSecretMount),
    /api must not receive unreviewed Compose secrets/u,
  );

  const duplicateMount = validComposeRuntime();
  duplicateMount.services.executor.volumes.push(
    structuredClone(duplicateMount.services.executor.volumes[0]),
  );
  assert.throws(
    () => validateComposeRuntimePolicy(duplicateMount),
    /executor mount inventory differs/u,
  );

  const wrongType = validComposeRuntime();
  const executorSecret = serviceMount(
    wrongType,
    "executor",
    "/run/secrets/sentinelflow",
  );
  executorSecret.type = "bind";
  executorSecret.bind = {};
  delete executorSecret.volume;
  assert.throws(
    () => validateComposeRuntimePolicy(wrongType),
    /executor mount fields differ/u,
  );

  const crossedSource = validComposeRuntime();
  serviceMount(crossedSource, "executor", "/run/secrets/sentinelflow").source =
    "dispatcher-secrets";
  assert.throws(
    () => validateComposeRuntimePolicy(crossedSource),
    /executor mount source differs/u,
  );

  const writableDispatcherSecret = validComposeRuntime();
  serviceMount(
    writableDispatcherSecret,
    "dispatcher",
    "/run/secrets/sentinelflow",
  ).read_only = false;
  assert.throws(
    () => validateComposeRuntimePolicy(writableDispatcherSecret),
    /dispatcher mount contract differs/u,
  );

  const writableHandoffReceipt = validComposeRuntime();
  serviceMount(
    writableHandoffReceipt,
    "demo-activation-handoff",
    "/run/sentinelflow-demo-history-capability-receipts",
  ).read_only = false;
  assert.throws(
    () => validateComposeRuntimePolicy(writableHandoffReceipt),
    /demo-activation-handoff mount contract differs/u,
  );

  const hostCreatingHandoffBind = validComposeRuntime();
  serviceMount(
    hostCreatingHandoffBind,
    "demo-activation-handoff",
    "/opt/sentinelflow/demo-activation-handoff.sh",
  ).bind.create_host_path = true;
  assert.throws(
    () => validateComposeRuntimePolicy(hostCreatingHandoffBind),
    /demo-activation-handoff mount options differ/u,
  );

  const composeNormalizerOmittingFalse = validComposeRuntime();
  delete serviceMount(
    composeNormalizerOmittingFalse,
    "demo-activation-handoff",
    "/opt/sentinelflow/demo-activation-handoff.sh",
  ).bind.create_host_path;
  assert.doesNotThrow(() =>
    validateComposeRuntimePolicy(composeNormalizerOmittingFalse),
  );

  const crossedHandoffReceipt = validComposeRuntime();
  serviceMount(
    crossedHandoffReceipt,
    "demo-activation-handoff",
    "/run/sentinelflow-demo-history-capability-receipts",
  ).source = "executor-secrets";
  assert.throws(
    () => validateComposeRuntimePolicy(crossedHandoffReceipt),
    /demo-activation-handoff mount source differs/u,
  );

  const writableMigrationReceipt = validComposeRuntime();
  serviceMount(
    writableMigrationReceipt,
    "migrate",
    "/run/sentinelflow-demo-history-capability-receipts",
  ).read_only = false;
  assert.throws(
    () => validateComposeRuntimePolicy(writableMigrationReceipt),
    /migrate mount contract differs/u,
  );

  const volumeAlias = validComposeRuntime();
  volumeAlias.volumes["unreviewed-analysis-alias"] = {
    name: reviewedComposeVolumeNames["demo-history-analysis-activation"],
  };
  assert.throws(
    () => validateComposeRuntimePolicy(volumeAlias),
    /Compose top-level volume inventory differs/u,
  );

  const renamedVolume = validComposeRuntime();
  renamedVolume.volumes["executor-secrets"].name =
    "sentinelflow_unreviewed-executor-secrets";
  assert.throws(
    () => validateComposeRuntimePolicy(renamedVolume),
    /Compose volume executor-secrets explicit name differs/u,
  );

  const temporarySources = validComposeRuntime();
  for (const service of [
    "demo-activator",
    "history-importer",
    "stubworker",
    "validationworker",
    "worker",
  ]) {
    serviceMount(
      temporarySources,
      service,
      "/run/sentinelflow-demo-history",
    ).source = "/private/tmp/reviewed-demo-history";
  }
  serviceMount(temporarySources, "secret-init", "/source").source =
    "/private/tmp/reviewed-demo-secrets";
  assert.doesNotThrow(() => validateComposeRuntimePolicy(temporarySources));

  const splitHistorySource = structuredClone(temporarySources);
  serviceMount(
    splitHistorySource,
    "worker",
    "/run/sentinelflow-demo-history",
  ).source = "/private/tmp/unreviewed-demo-history";
  assert.throws(
    () => validateComposeRuntimePolicy(splitHistorySource),
    /worker dynamic bind source differs/u,
  );

  const namedVolumeBindAlias = validComposeRuntime();
  for (const service of [
    "demo-activator",
    "history-importer",
    "stubworker",
    "validationworker",
    "worker",
  ]) {
    serviceMount(
      namedVolumeBindAlias,
      service,
      "/run/sentinelflow-demo-history",
    ).source = "/var/lib/docker/volumes/sentinelflow_executor-secrets/_data";
  }
  assert.throws(
    () => validateComposeRuntimePolicy(namedVolumeBindAlias),
    /bind source aliases a reviewed named volume/u,
  );
});

test("Compose source policy requires reviewed fixed binds to disable host path creation", () => {
  const composeSource = fs.readFileSync(
    new URL("../deployments/compose.yaml", import.meta.url),
    "utf8",
  );
  assert.doesNotThrow(() => validateComposeSourceBindPolicy(composeSource));
  assert.throws(
    () =>
      validateComposeSourceBindPolicy(
        composeSource.replace("create_host_path: false", "create_host_path: true"),
      ),
    /must explicitly set bind\.create_host_path: false/u,
  );
  assert.throws(
    () =>
      validateComposeSourceBindPolicy(
        composeSource.replace(
          "source: ${DEMO_HISTORY_SOURCE:-../data/demo-history}\n        target: /run/sentinelflow-demo-history\n        read_only: true\n        bind:\n          create_host_path: false",
          "source: ${DEMO_HISTORY_SOURCE:-../data/demo-history}\n        target: /run/sentinelflow-demo-history\n        read_only: true\n        bind:\n          create_host_path: true",
        ),
      ),
    /must explicitly set bind\.create_host_path: false/u,
  );
});

test("Compose runtime policy freezes demo history proof owners and dependency objects", () => {
  assert.doesNotThrow(() =>
    validateComposeRuntimePolicy(validComposeRuntime()),
  );

  const missingProof = validComposeRuntime();
  delete missingProof.services.worker.environment.DEMO_HISTORY_RUN_SCOPE;
  assert.throws(
    () => validateComposeRuntimePolicy(missingProof),
    /demo activation environment ownership differs for DEMO_HISTORY_RUN_SCOPE/u,
  );

  const crossedProof = validComposeRuntime();
  crossedProof.services.api.environment = {
    DEMO_HISTORY_IMPORT_ID: "019b0000-0000-7000-8000-000000000902",
  };
  assert.throws(
    () => validateComposeRuntimePolicy(crossedProof),
    /demo activation environment ownership differs for DEMO_HISTORY_IMPORT_ID/u,
  );

  const missingDataset = validComposeRuntime();
  delete missingDataset.services["history-importer"].environment
    .DEMO_HISTORY_FIXTURE_DATASET;
  assert.throws(
    () => validateComposeRuntimePolicy(missingDataset),
    /demo activation environment ownership differs for DEMO_HISTORY_FIXTURE_DATASET/u,
  );

  const wrongDatasetPath = validComposeRuntime();
  wrongDatasetPath.services[
    "history-importer"
  ].environment.DEMO_HISTORY_FIXTURE_DATASET = "/tmp/unreviewed-dataset.json";
  assert.throws(
    () => validateComposeRuntimePolicy(wrongDatasetPath),
    /history-importer demo history fixed value differs for DEMO_HISTORY_FIXTURE_DATASET/u,
  );

  const wrongEnvelopePath = validComposeRuntime();
  wrongEnvelopePath.services.validationworker.environment.DEMO_HISTORY_SIGNED_ENVELOPE_FILE =
    "/tmp/unreviewed-envelope.json";
  assert.throws(
    () => validateComposeRuntimePolicy(wrongEnvelopePath),
    /validationworker demo history fixed value differs for DEMO_HISTORY_SIGNED_ENVELOPE_FILE/u,
  );

  const extraDependency = validComposeRuntime();
  extraDependency.services["demo-activator"].depends_on.api = {
    condition: "service_started",
    required: true,
  };
  assert.throws(
    () => validateComposeRuntimePolicy(extraDependency),
    /demo-activator Compose dependency inventory differs/u,
  );

  const missingExecutorNamespaceOwner = validComposeRuntime();
  delete missingExecutorNamespaceOwner.services.executor.depends_on.gateway;
  assert.throws(
    () => validateComposeRuntimePolicy(missingExecutorNamespaceOwner),
    /executor Compose dependency inventory differs/u,
  );

  const wrongExecutorNamespaceOwnerCondition = validComposeRuntime();
  wrongExecutorNamespaceOwnerCondition.services.executor.depends_on.gateway.condition =
    "service_healthy";
  assert.throws(
    () => validateComposeRuntimePolicy(wrongExecutorNamespaceOwnerCondition),
    /executor Compose dependency on gateway differs/u,
  );

  const missingExecutorNamespaceOwnerRestart = validComposeRuntime();
  delete missingExecutorNamespaceOwnerRestart.services.executor.depends_on
    .gateway.restart;
  assert.throws(
    () => validateComposeRuntimePolicy(missingExecutorNamespaceOwnerRestart),
    /executor Compose dependency on gateway fields differ/u,
  );

  const falseExecutorNamespaceOwnerRestart = validComposeRuntime();
  falseExecutorNamespaceOwnerRestart.services.executor.depends_on.gateway.restart = false;
  assert.throws(
    () => validateComposeRuntimePolicy(falseExecutorNamespaceOwnerRestart),
    /executor Compose dependency on gateway differs/u,
  );

  const restartDependency = validComposeRuntime();
  restartDependency.services.worker.depends_on["demo-activator"].restart = true;
  assert.throws(
    () => validateComposeRuntimePolicy(restartDependency),
    /worker Compose dependency on demo-activator fields differ/u,
  );

  const falseRestartDependency = validComposeRuntime();
  falseRestartDependency.services.worker.depends_on["demo-activator"].restart =
    false;
  assert.throws(
    () => validateComposeRuntimePolicy(falseRestartDependency),
    /worker Compose dependency on demo-activator fields differ/u,
  );

  const unexpectedDatabaseDependency = validComposeRuntime();
  unexpectedDatabaseDependency.services.postgres.depends_on.api = {
    condition: "service_started",
    required: true,
  };
  assert.throws(
    () => validateComposeRuntimePolicy(unexpectedDatabaseDependency),
    /postgres Compose dependency inventory differs/u,
  );

  const missingMigrationDependency = validComposeRuntime();
  delete missingMigrationDependency.services.migrate.depends_on["secret-init"];
  assert.throws(
    () => validateComposeRuntimePolicy(missingMigrationDependency),
    /migrate Compose dependency inventory differs/u,
  );

  const wrongHandoffDependency = validComposeRuntime();
  wrongHandoffDependency.services["demo-activation-handoff"].depends_on[
    "history-importer"
  ].condition = "service_started";
  assert.throws(
    () => validateComposeRuntimePolicy(wrongHandoffDependency),
    /demo-activation-handoff Compose dependency on history-importer differs/u,
  );
});

test("Compose runtime policy freezes demo activation authority edges", () => {
  assert.doesNotThrow(() =>
    validateComposeRuntimePolicy(validComposeRuntime()),
  );

  const leakedVolume = validComposeRuntime();
  leakedVolume.services.api.volumes = [
    volumeMount(
      "demo-history-analysis-activation",
      "/run/secrets/unreviewed-analysis-copy",
      true,
    ),
  ];
  assert.throws(
    () => validateComposeRuntimePolicy(leakedVolume),
    /api mount inventory differs/u,
  );

  const inheritedVolumes = validComposeRuntime();
  inheritedVolumes.services.api.volumes_from = ["demo-activator:ro"];
  assert.throws(
    () => validateComposeRuntimePolicy(inheritedVolumes),
    /api must not inherit another service's volumes/u,
  );

  const alternateDestination = validComposeRuntime();
  serviceMount(
    alternateDestination,
    "stubworker",
    "/run/secrets/sentinelflow-demo-history-analysis",
  ).target = "/run/secrets/unreviewed-analysis-copy";
  assert.throws(
    () => validateComposeRuntimePolicy(alternateDestination),
    /stubworker mount target differs/u,
  );

  const crossedSource = validComposeRuntime();
  serviceMount(
    crossedSource,
    "stubworker",
    "/run/secrets/sentinelflow-demo-history-analysis",
  ).source = "demo-history-validation-activation";
  assert.throws(
    () => validateComposeRuntimePolicy(crossedSource),
    /stubworker mount source differs/u,
  );

  const writableConsumer = validComposeRuntime();
  serviceMount(
    writableConsumer,
    "stubworker",
    "/run/secrets/sentinelflow-demo-history-analysis",
  ).read_only = false;
  assert.throws(
    () => validateComposeRuntimePolicy(writableConsumer),
    /stubworker mount contract differs/u,
  );

  const missingMount = validComposeRuntime();
  missingMount.services.validationworker.volumes =
    missingMount.services.validationworker.volumes.filter(
      (mount) =>
        mount.target !== "/run/secrets/sentinelflow-demo-history-validation",
    );
  assert.throws(
    () => validateComposeRuntimePolicy(missingMount),
    /validationworker mount inventory differs/u,
  );

  const crossedEnvironment = validComposeRuntime();
  crossedEnvironment.services.validationworker.environment.DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE =
    analysisActivationPath;
  assert.throws(
    () => validateComposeRuntimePolicy(crossedEnvironment),
    /demo activation environment ownership differs for DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE/u,
  );

  const wrongSecretPath = validComposeRuntime();
  wrongSecretPath.services.stubworker.environment.DEMO_HISTORY_ANALYSIS_ACTIVATION_SECRET_FILE =
    "/run/secrets/unreviewed-analysis-copy/activation-capability";
  assert.throws(
    () => validateComposeRuntimePolicy(wrongSecretPath),
    /stubworker demo history fixed value differs/u,
  );

  const missingDependency = validComposeRuntime();
  delete missingDependency.services.validationworker.depends_on[
    "demo-activator"
  ];
  assert.throws(
    () => validateComposeRuntimePolicy(missingDependency),
    /validationworker Compose dependency inventory differs/u,
  );

  const optionalDependency = validComposeRuntime();
  optionalDependency.services.worker.depends_on["demo-activator"].required =
    false;
  assert.throws(
    () => validateComposeRuntimePolicy(optionalDependency),
    /worker Compose dependency on demo-activator differs/u,
  );
});

test("Trivy report rejects malformed output and every unexcepted CRITICAL", () => {
  const imageReference = "sentinelflow/backend:verification";
  const report = {
    SchemaVersion: 2,
    ArtifactType: "container_image",
    Metadata: {
      ImageID: imageID,
      OS: { Family: "alpine", Name: "3.24.1" },
    },
    Results: [
      {
        Target: "verification (alpine 3.24.1)",
        Class: "os-pkgs",
        Type: "alpine",
        Packages: [{ Name: "musl", Version: "1.2.5" }],
      },
    ],
  };
  assert.doesNotThrow(() =>
    validateTrivyReport(report, { imageReference, imageID }),
  );
  assert.throws(
    () =>
      validateTrivyReport(
        { SchemaVersion: 2, ArtifactType: "container_image" },
        { imageReference, imageID },
      ),
    /image ID does not match/u,
  );

  const critical = structuredClone(report);
  critical.Results[0].Vulnerabilities = [
    {
      VulnerabilityID: "CVE-2026-12345",
      PkgName: "musl",
      InstalledVersion: "1.2.5",
      FixedVersion: "1.2.6",
      Severity: "CRITICAL",
    },
  ];
  assert.throws(
    () => validateTrivyReport(critical, { imageReference, imageID }),
    /unexcepted CRITICAL vulnerabilities.*CVE-2026-12345/u,
  );
});

test("container SPDX validation requires OS package inventory", () => {
  const sbom = {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    packages: [
      { SPDXID: "SPDXRef-Root", externalRefs: [] },
      {
        SPDXID: "SPDXRef-musl",
        externalRefs: [
          {
            referenceType: "purl",
            referenceLocator: "pkg:apk/alpine/musl@1.2.5?arch=amd64",
          },
        ],
      },
    ],
    relationships: [
      {
        spdxElementId: "SPDXRef-Root",
        relationshipType: "CONTAINS",
        relatedSpdxElement: "SPDXRef-musl",
      },
    ],
  };
  assert.doesNotThrow(() => validateImageSpdxDocument(sbom));
  sbom.packages[1].externalRefs[0].referenceLocator = "pkg:generic/musl@1.2.5";
  assert.throws(
    () => validateImageSpdxDocument(sbom),
    /no Alpine or Debian OS package URLs/u,
  );
});
