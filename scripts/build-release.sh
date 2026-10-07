#!/usr/bin/env bash
# Build experimental research assets from one clean, immutable Git commit.
set -euo pipefail
umask 022
export LC_ALL=C TZ=UTC

fail() { printf 'release: %s\n' "$*" >&2; exit 1; }
[[ $# == 2 ]] || fail 'usage: scripts/build-release.sh VERSION OUTPUT_DIR'
version="$1"
[[ "$version" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-(alpha|beta|rc)\.(0|[1-9][0-9]*)$ ]] || fail 'version must be an experimental SemVer prerelease, for example v0.1.0-rc.1'
for tool in git go python3 tar; do
  command -v "$tool" >/dev/null 2>&1 || fail "required tool unavailable: $tool"
done
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repo_root"
[[ -z "$(git status --porcelain --untracked-files=all)" ]] || fail 'source must be committed and clean (including untracked files)'
commit="$(git rev-parse --verify HEAD^{commit})"
if git show-ref --verify --quiet "refs/tags/$version"; then
  [[ "$(git rev-parse "refs/tags/$version^{commit}")" == "$commit" ]] || fail 'existing version tag does not point to HEAD'
fi
epoch="$(git show -s --format=%ct "$commit")"
[[ "${SOURCE_DATE_EPOCH:-$epoch}" == "$epoch" ]] || fail 'SOURCE_DATE_EPOCH must equal the source commit timestamp'
export SOURCE_DATE_EPOCH="$epoch"
output="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$2")"
case "$output/" in "$repo_root/"*) fail 'output must be outside the repository' ;; esac
[[ ! -e "$output" && ! -L "$2" ]] || fail 'output directory already exists or is a symlink'
[[ -d "$(dirname "$output")" ]] || fail 'output parent directory must exist'
scratch="$(mktemp -d "${TMPDIR:-/tmp}/sentinelflow-release.XXXXXX")"
cleanup() { rm -rf "$scratch"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$scratch/source" "$scratch/assets"
prefix="sentinelflow-$version"
# git archive cannot include ignored credentials, build output, or untracked data.
git -c tar.umask=0022 archive --format=tar --prefix="$prefix/" "$commit" > "$scratch/source.tar"
tar -xf "$scratch/source.tar" -C "$scratch/source"
source_root="$scratch/source/$prefix"
required_go="$(awk '$1 == "go" { print $2 }' "$source_root/go.mod")"
[[ "$required_go" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'go.mod must pin the complete Go toolchain version'
export GOTOOLCHAIN="go$required_go" GOENV=off GOFLAGS= GOWORK=off
export GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GOPRIVATE= GONOPROXY= GONOSUMDB=
export CGO_ENABLED=0 GOOS=linux GOAMD64=v1 GOARM64=v8.0 GOEXPERIMENT=
[[ "$(go env GOVERSION)" == "go$required_go" ]] || fail 'Go toolchain mismatch'
cd "$source_root"
go mod verify
module_path="$(go list -m)"
link_flags="-buildid= -X=$module_path/internal/buildinfo.Version=$version"
for arch in amd64 arm64; do
  export GOARCH="$arch"
  bundle="$scratch/$prefix-linux-$arch"
  mkdir -p "$bundle/bin"
  # Include every committed command; never infer a runtime from directory names.
  go list -mod=readonly -f '{{if eq .Name "main"}}{{.ImportPath}}{{end}}' ./cmd/... > "$scratch/commands-$arch.txt"
  [[ -s "$scratch/commands-$arch.txt" ]] || fail "no Linux $arch commands found"
  while IFS= read -r package; do
    [[ -n "$package" ]] || continue
    go build -mod=readonly -trimpath -buildvcs=false -ldflags="$link_flags" -o "$bundle/bin/${package##*/}" "$package"
  done < "$scratch/commands-$arch.txt"
  cp LICENSE "$bundle/LICENSE"
  go list -mod=readonly -deps -json ./cmd/... > "$scratch/dependencies-$arch.json"
done
python3 - "$scratch" "$prefix" "$version" "$commit" "$epoch" "$required_go" "$(go env GOROOT)" "$link_flags" <<'PY'
import gzip, hashlib, json, pathlib, sys, tarfile
scratch, prefix, version, commit, epoch, toolchain, goroot, link_flags = sys.argv[1:]
root = pathlib.Path(scratch)
assets = root / "assets"
epoch = int(epoch)
provenance = {
    "schema": "sentinelflow-release-v1", "version": version,
    "classification": "experimental-research-prerelease", "commit": commit,
    "source_date_epoch": epoch, "go_toolchain": "go" + toolchain,
    "platforms": ["linux/amd64", "linux/arm64"], "cgo_enabled": False,
    "build_flags": ["-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags=" + link_flags],
    "microarchitectures": {"amd64": "v1", "arm64": "v8.0"},
    "third_party_notices": "THIRD_PARTY_NOTICES.json and licenses/ in each binary archive",
    "commands": {},
    "limitations": ["Not production-qualified or the completed v0.1 reference release.",
                    "Binaries require configuration and source-bundle runtime contracts; no credentials are included.",
                    "Web assets are built from the source bundle using its pinned npm lockfile and Compose workflow.",
                    "Checksums establish integrity, not a cryptographic publisher signature or an SLSA attestation."]
}
for arch in ("amd64", "arm64"):
    bundle = root / (prefix + "-linux-" + arch)
    provenance["commands"][arch] = sorted(p.name for p in (bundle / "bin").iterdir())
    # Module metadata comes from actual non-test command dependency graphs.
    # Preserve original license bytes, including nested third-party notices.
    dependencies = (root / ("dependencies-" + arch + ".json")).read_text()
    decoder = json.JSONDecoder()
    modules = {"go": ("go" + toolchain, pathlib.Path(goroot))}
    while dependencies.strip():
        package, consumed = decoder.raw_decode(dependencies.lstrip())
        dependencies = dependencies.lstrip()[consumed:]
        module = package.get("Module", {})
        if module and not module.get("Main"):
            if module.get("Replace"):
                raise SystemExit("release: replacement modules require an explicit licensing review")
            modules[module["Path"]] = (module["Version"], pathlib.Path(module["Dir"]))
    license_dir = bundle / "licenses"
    license_dir.mkdir()
    notices = []
    for component, (module_version, directory) in sorted(modules.items()):
        candidates = sorted(path for path in directory.rglob("*") if path.is_file()
                            and path.name.upper().startswith(("LICENSE", "COPYING", "NOTICE", "PATENTS")))
        if not any(path.name.upper().startswith(("LICENSE", "COPYING")) for path in candidates):
            raise SystemExit("release: missing third-party license: " + component)
        files = []
        for path in candidates:
            relative = str(path.relative_to(directory))
            identity = hashlib.sha256((component + "@" + module_version + "/" + relative).encode()).hexdigest()[:16]
            target = "licenses/" + identity + "-" + path.name
            data = path.read_bytes()
            (bundle / target).write_bytes(data)
            files.append({"source_path": relative, "artifact_path": target,
                          "sha256": hashlib.sha256(data).hexdigest()})
        notices.append({"component": component, "version": module_version, "files": files})
    (bundle / "THIRD_PARTY_NOTICES.json").write_text(
        json.dumps({"schema": "sentinelflow-third-party-notices-v1", "components": notices},
                   sort_keys=True, indent=2) + "\n", encoding="utf-8")
metadata = (json.dumps(provenance, sort_keys=True, indent=2) + "\n").encode()
(assets / "RELEASE-INFO.json").write_bytes(metadata)
with (root / "source.tar").open("rb") as src, (assets / (prefix + "-source.tar.gz")).open("wb") as raw:
    with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0, compresslevel=9) as gz:
        while block := src.read(1024 * 1024):
            gz.write(block)
for arch in ("amd64", "arm64"):
    bundle = root / (prefix + "-linux-" + arch)
    (bundle / "RELEASE-INFO.json").write_bytes(metadata)
    with (assets / (bundle.name + ".tar.gz")).open("wb") as raw:
        with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0, compresslevel=9) as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for path in [bundle, *sorted(bundle.rglob("*"))]:
                    info = archive.gettarinfo(str(path), arcname=str(path.relative_to(root)))
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mtime = epoch
                    info.mode = 0o755 if path.is_dir() or path.parent.name == "bin" else 0o644
                    if path.is_file():
                        with path.open("rb") as data:
                            archive.addfile(info, data)
                    else:
                        archive.addfile(info)
checksums = []
for path in sorted(assets.iterdir()):
    digest = hashlib.sha256()
    with path.open("rb") as data:
        while block := data.read(1024 * 1024):
            digest.update(block)
    checksums.append(f"{digest.hexdigest()}  {path.name}\n")
(assets / "SHA256SUMS").write_text("".join(checksums), encoding="ascii")
PY
# A failed build leaves no advertised output directory.
[[ ! -e "$output" ]] || fail 'output appeared while building; refusing to overwrite it'
mv "$scratch/assets" "$output"
printf 'release: built %s at commit %s in %s\n' "$version" "$commit" "$output"
