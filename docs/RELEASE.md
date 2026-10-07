# Experimental research release guide

[한국어](./RELEASE.ko.md)

## 1. Release classification

`v0.1.0-rc.1` is an **experimental research prerelease** of SentinelFlow, owned by Veloz (벨로즈). It packages source code and Linux command binaries for inspection and isolated evaluation. It is not a production support commitment, certification, or evidence that all implementation-qualified v0.1 release criteria are complete.

The [GitHub release record](https://github.com/devwooops/sentinelflow/releases) is authoritative for publication status, tag, commit, attached checksums, and verification notes. A package or tag alone does not close M9-008. All acceptance and safety gates in the [PRD](./PRD.md), [TDD](./TDD.md), [Tasklist](./TASKLIST.md), and [WBS](./WBS.md) remain in force. The [readiness ledger](./IMPLEMENTATION_READINESS.md) distinguishes historical evidence from outstanding qualification.

## 2. Artifacts and integrity

| Artifact | Contents |
| --- | --- |
| `sentinelflow-v0.1.0-rc.1-source.tar.gz` | Explicit committed source snapshot under `sentinelflow-v0.1.0-rc.1/` |
| `sentinelflow-v0.1.0-rc.1-linux-amd64.tar.gz` | Linux amd64 command binaries under `bin/`, license, `THIRD_PARTY_NOTICES.json`, `licenses/`, and release metadata |
| `sentinelflow-v0.1.0-rc.1-linux-arm64.tar.gz` | Linux arm64 command binaries under `bin/`, license, `THIRD_PARTY_NOTICES.json`, `licenses/`, and release metadata |
| `RELEASE-INFO.json` | Version, source revision, and build metadata |
| `SHA256SUMS` | SHA-256 checksums for the packaged artifacts |

Cross-compilation on macOS establishes that Linux binaries build; it does not establish that they execute correctly on Linux. Treat Linux binary runtime checks as unverified unless the release evidence explicitly records them.

Binary archives do not include container images, a prebuilt web UI, a database, or a configured deployment. Use the source-based Compose workflow below for the complete reference environment. Dependency and image requirements remain pinned in the repository.

Download all attached assets into one directory from the intended release, then verify on Linux before extraction:

```bash
sha256sum --check SHA256SUMS
```

Checksums detect corruption; they are not an independent publisher signature. Verify that the repository, tag, source revision, and release record are the ones you intended to use.

## 3. Isolated Linux evaluation

Use a disposable Linux environment with at least 4 GB RAM, Docker 24+, Docker Compose v2, Go `1.25.13`, Node.js, and npm. The repository CI pins Node.js `24.13.0`. Enforcement depends on Linux network namespaces and nftables. The default demo's management ports bind to loopback, and its executor shares the Gateway namespace rather than the host namespace.

From the published tag:

```bash
git clone --branch v0.1.0-rc.1 --depth 1 https://github.com/devwooops/sentinelflow.git
cd sentinelflow
./scripts/prepare-demo.sh
COMPOSE_DISABLE_ENV_FILE=1 OPENAI_API_KEY= docker compose \
  --env-file .env.demo \
  --file deployments/compose.yaml \
  --profile stub-ai up --build
```

The same startup commands work from the extracted source directory. `prepare-demo.sh` builds the backend image, verifies the nftables binary identity, and generates an ignored local bundle. It refuses to overwrite `.env.demo`, `secrets/demo`, or `data/demo-history`. Keep those generated secrets outside Git and public evidence.

With the default ports, open [the local administrator UI](http://localhost:4173). The generated administrator credentials are in the local `secrets/demo/admin-credentials.json`; read them privately, without including them in screenshots, logs, or reports. The Gateway listens on `localhost:8080`, and the management API binds to `127.0.0.1:8083`. The private demo application has no published host port.

The `stub-ai` profile uses deterministic synthetic analysis and needs no OpenAI key. It retains the validation, HIL, and isolated execution boundaries. Live analysis is a separate opt-in profile requiring operator credentials and a rate card; stub success must not be presented as live-provider verification.

To stop this Compose project while retaining its volumes:

```bash
COMPOSE_DISABLE_ENV_FILE=1 OPENAI_API_KEY= docker compose \
  --env-file .env.demo \
  --file deployments/compose.yaml \
  --profile stub-ai down
```

Signed demo-history activation expires after one hour and cannot be renewed in place. Expired demo authority requires a complete disposable profile/volume reset and a newly sealed run; stopping and restarting the project does not renew it. Follow the [technical deployment contract](./TDD.md) before resetting data.

## 4. Reproducible packaging

Packaging requires Git, Bash, Python 3.8+, tar, the Go toolchain pinned in `go.mod`, and network access or a populated module cache. Run from a clean committed checkout, including no untracked files, and select a new absolute output directory outside the checkout:

```bash
./scripts/build-release.sh v0.1.0-rc.1 /tmp/sentinelflow-v0.1.0-rc.1-artifacts
```

The output path must not already exist. The source archive comes from the selected Git commit; ignored and untracked local files are excluded. The script builds Linux amd64 and arm64 commands and creates deterministic archives, metadata, and checksums. If `SOURCE_DATE_EPOCH` is supplied, it must match the source commit timestamp. Packaging does not run services, apply a firewall policy, or publish a GitHub release.

Run the packaging regression separately:

```bash
./scripts/check-release.sh
```

It performs two builds from a disposable committed fixture, compares the resulting artifacts, and checks invalid inputs. The [release workflow](../.github/workflows/release.yml) produces downloadable CI artifacts on manual dispatch; a maintainer separately publishes the reviewed prerelease and its evidence.

## 5. Verification and qualification

Before publication, record the exact commit and successful applicable checks. The repository provides these gates:

```bash
make check
make check-integration
./scripts/check-release.sh
./scripts/check-demo-e2e.sh
make check-gateway-performance
```

`make check` covers backend, contracts, documentation, frontend, security, supply chain, and threshold tuning. `make check-integration` covers database, nftables namespace, image, observability, recovery, and export checks. The final two commands require the qualifying Linux environment: the E2E gate must prove real kernel expiry and host nftables invariance, and the default performance gate requires the five-minute 4 GB reference run. `--fast` E2E and performance smoke mode are development evidence only. Each test harness manages its own disposable resources; inspect its prerequisites before execution.

The supply-chain scanner uses the frozen Trivy database dated 2026-07-18. Re-running that check establishes consistency against that snapshot, not current October 2026 vulnerability assurance.

An experimental publication must state which checks ran for its exact source revision and which remain unverified. Historical local results and older CI runs are not automatically promoted to current-release evidence. Full v0.1 qualification additionally requires all acceptance, failure/recovery, real-browser, sanitized release-capture, dependency, and final-decision criteria in the canonical documents. Research packaging does not mark those tasks complete or claim that a Build Week submission occurred.

## 6. Limits and support

The reference implementation supports one fixed private upstream and HTTP/1.1, with Linux nftables temporary responses and one administrator. It has no production HA, payload inspection, raw-packet sensing, multi-tenant support, or general WAF equivalence. False positives and observable event loss are possible. Review the complete [known limitations](../README.md#known-limitations) and [security policy](../SECURITY.md).

Report ordinary reproducible defects in the repository, with the version and sanitized evidence. Report suspected vulnerabilities privately to [security@veloz.kr](mailto:security@veloz.kr). The company website is [sec.veloz.kr](https://sec.veloz.kr); no external program acceptance or certification is implied by this release.

## Company organization transfer

The owner selected `veloz-security` as the destination organization for SentinelFlow and the existing `devwooops/pktide` repository. Creation and transfer remain pending: the organization does not currently resolve through GitHub's API. `gh org` supports listing organizations, but GitHub.com does not provide a public organization-creation endpoint. An organization must first be created through GitHub's supported web flow; no repository has been transferred or recreated.

Once the organization exists and the authenticated user has the required owner/admin rights, transfer the existing repositories rather than creating conflicting empty repositories:

```bash
gh api --method POST repos/devwooops/sentinelflow/transfer -f new_owner=veloz-security
gh api --method POST repos/devwooops/pktide/transfer -f new_owner=veloz-security
```

Verify the final `full_name` and permissions for both repositories, then update local remotes and public repository/release links. Preserve the Go module import path through GitHub's redirect until a separately reviewed module migration; moving the repository does not authorize changing runtime contracts. Source history, tags, releases, issues, and pull requests must be checked after transfer. M9-013 tracks this external prerequisite and remains open.
