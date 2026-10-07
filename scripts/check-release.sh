#!/usr/bin/env bash
# Exercise candidate packaging without staging or changing the working repository.
set -euo pipefail
export LC_ALL=C TZ=UTC
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/sentinelflow-release-check.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$scratch/repo"
git -C "$repo_root" archive HEAD | tar -xf - -C "$scratch/repo"
# Only the owned packaging scripts are overlaid; unrelated uncommitted inputs
# and ignored credentials are never copied into the test repository.
cp "$repo_root/scripts/build-release.sh" "$scratch/repo/scripts/build-release.sh"
cd "$scratch/repo"
git init -q
git config user.name 'SentinelFlow packaging test'
git config user.email 'packaging-test@example.invalid'
git config commit.gpgsign false
git config core.hooksPath /dev/null
git add .
GIT_AUTHOR_DATE='2000-01-01T00:00:00Z' GIT_COMMITTER_DATE='2000-01-01T00:00:00Z' git commit -qm 'Synthetic committed release fixture'
version=v0.0.0-rc.1
failures=0
expect_failure() {
  local label="$1"
  shift
  if "$@" > "$scratch/failure.log" 2>&1; then
    printf 'release check: expected failure: %s\n' "$label" >&2
    exit 1
  fi
  [[ ! -e "$scratch/rejected" ]] || { printf 'release check: failed build exposed output\n' >&2; exit 1; }
  failures=$((failures + 1))
}
expect_failure 'missing arguments' ./scripts/build-release.sh
expect_failure 'stable version unsupported' ./scripts/build-release.sh v0.1.0 "$scratch/rejected"
expect_failure 'unsafe version unsupported' ./scripts/build-release.sh '../invalid' "$scratch/rejected"
expect_failure 'inconsistent source timestamp' env SOURCE_DATE_EPOCH=1 ./scripts/build-release.sh "$version" "$scratch/rejected"
expect_failure 'repository output forbidden' ./scripts/build-release.sh "$version" "$scratch/repo/release-output"
mkdir "$scratch/existing"
expect_failure 'existing output forbidden' ./scripts/build-release.sh "$version" "$scratch/existing"
ln -s "$scratch/missing" "$scratch/output-link"
expect_failure 'symlink output forbidden' ./scripts/build-release.sh "$version" "$scratch/output-link"
printf '\nmodified\n' >> README.md
expect_failure 'modified source forbidden' ./scripts/build-release.sh "$version" "$scratch/rejected"
git restore README.md
printf 'synthetic untracked data\n' > untracked-input
expect_failure 'untracked source forbidden' ./scripts/build-release.sh "$version" "$scratch/rejected"
rm untracked-input
git tag "$version"
GIT_AUTHOR_DATE='2000-01-01T00:00:01Z' GIT_COMMITTER_DATE='2000-01-01T00:00:01Z' git commit --allow-empty -qm 'Synthetic second fixture commit'
expect_failure 'version tag mismatch forbidden' ./scripts/build-release.sh "$version" "$scratch/rejected"
git tag -d "$version" >/dev/null
mkdir "$scratch/fake-bin"
printf '#!/usr/bin/env bash\nexit 1\n' > "$scratch/fake-bin/go"
chmod +x "$scratch/fake-bin/go"
expect_failure 'toolchain failure has no output' env PATH="$scratch/fake-bin:$PATH" ./scripts/build-release.sh "$version" "$scratch/rejected"
printf 'ignored-release-test\n' >> .git/info/exclude
printf 'synthetic ignored marker, never a credential\n' > ignored-release-test
unset SOURCE_DATE_EPOCH
printf 'release check: first real Linux amd64/arm64 build\n'
./scripts/build-release.sh "$version" "$scratch/first"
printf 'release check: second real Linux amd64/arm64 build\n'
./scripts/build-release.sh "$version" "$scratch/second"
python3 - "$scratch" "$version" "$(git rev-parse HEAD)" <<'PY'
import hashlib, json, pathlib, struct, subprocess, sys, tarfile
root, version, commit = sys.argv[1:]
root = pathlib.Path(root)
first, second = root / "first", root / "second"
prefix = "sentinelflow-" + version
expected = {"RELEASE-INFO.json", "SHA256SUMS", prefix + "-source.tar.gz",
            prefix + "-linux-amd64.tar.gz", prefix + "-linux-arm64.tar.gz"}
assert {p.name for p in first.iterdir()} == expected
assert {p.name for p in second.iterdir()} == expected
def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as data:
        while block := data.read(1024 * 1024):
            value.update(block)
    return value.hexdigest()
for name in expected:
    assert digest(first / name) == digest(second / name), "non-reproducible: " + name
checksums = {}
for line in (first / "SHA256SUMS").read_text().splitlines():
    sha, name = line.split("  ", 1)
    assert name not in checksums
    checksums[name] = sha
    assert digest(first / name) == sha, "checksum mismatch: " + name
assert set(checksums) == expected - {"SHA256SUMS"}
metadata = json.loads((first / "RELEASE-INFO.json").read_text())
assert metadata["commit"] == commit and metadata["version"] == version
assert metadata["source_date_epoch"] == 946684801
assert metadata["classification"] == "experimental-research-prerelease"
with tarfile.open(first / (prefix + "-source.tar.gz")) as archive:
    names = archive.getnames()
    assert all(name == prefix or name.startswith(prefix + "/") for name in names)
    assert not any("ignored-release-test" in name or "/.git/" in name for name in names)
    assert archive.extractfile(prefix + "/README.md").read() == (root / "repo/README.md").read_bytes()
    assert prefix + "/web/package-lock.json" in names
for arch, machine in (("amd64", 62), ("arm64", 183)):
    base = prefix + "-linux-" + arch
    with tarfile.open(first / (base + ".tar.gz")) as archive:
        commands = []
        for member in archive.getmembers():
            assert member.name.startswith(base)
            assert member.uid == member.gid == 0 and member.mtime == 946684801
            if member.name.startswith(base + "/bin/") and member.isfile():
                commands.append(member.name.rsplit("/", 1)[-1])
                data = archive.extractfile(member).read(20)
                assert data[:6] == b"\x7fELF\x02\x01", "not a little-endian ELF64 binary"
                assert struct.unpack("<H", data[18:20])[0] == machine, "wrong architecture"
                assert member.mode == 0o755
                if member.name.endswith("/executor"):
                    inspected = root / ("inspect-executor-" + arch)
                    binary = archive.extractfile(member).read()
                    inspected.write_bytes(binary)
                    # -trimpath intentionally omits linker flags from Go build
                    # metadata. Inspect the linked symbol bytes without running it.
                    symbols = subprocess.check_output(["go", "tool", "nm", "-size", str(inspected)], text=True)
                    symbol = next(line.split() for line in symbols.splitlines()
                                  if line.endswith("/internal/buildinfo.Version.str"))
                    address, size = int(symbol[0], 16), int(symbol[1])
                    sections = struct.unpack_from("<Q", binary, 40)[0]
                    entry_size, count = struct.unpack_from("<HH", binary, 58)
                    linked_version = None
                    for index in range(count):
                        virtual, offset, length = struct.unpack_from("<QQQ", binary, sections + index * entry_size + 16)
                        if virtual <= address and address + size <= virtual + length:
                            start = offset + address - virtual
                            linked_version = binary[start:start + size].rstrip(b"\0").decode()
                            break
                    assert linked_version == version, "incorrect embedded release version"
        assert sorted(commands) == metadata["commands"][arch]
        assert {"gateway", "api", "executor", "dispatcher", "simulator"}.issubset(commands)
        assert archive.extractfile(base + "/RELEASE-INFO.json").read() == (first / "RELEASE-INFO.json").read_bytes()
        notices = json.load(archive.extractfile(base + "/THIRD_PARTY_NOTICES.json"))
        components = {item["component"] for item in notices["components"]}
        assert {"go", "github.com/go-chi/chi/v5", "github.com/jackc/pgx/v5", "golang.org/x/crypto"}.issubset(components)
        for item in notices["components"]:
            assert item["files"]
            assert any(path["source_path"].upper().startswith(("LICENSE", "COPYING")) for path in item["files"])
            for path in item["files"]:
                data = archive.extractfile(base + "/" + path["artifact_path"]).read()
                assert data and hashlib.sha256(data).hexdigest() == path["sha256"]
print("release check: checksums, source exclusion, provenance, licenses, ELF platforms and byte-identical rebuilds passed")
PY
printf 'release check: %s failure cases passed; no runtime, Docker, credentials or publication used\n' "$failures"
