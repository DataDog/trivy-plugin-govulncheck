# trivy-plugin-govulncheck

A [Trivy](https://trivy.dev) **output plugin** that reduces false positives for Go binaries by running [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) on each Go binary in the report and keeping only vulnerabilities that govulncheck confirms are actually used.

## How it works

1. Trivy runs an **image** scan and sends the JSON report to the plugin via stdin.
2. The plugin pulls and extracts the image (via go-containerregistry), then for each **Go binary** result:
   - Resolves the binary path under the extracted image root.
   - Runs `govulncheck -format openvex -mode binary <binary>` and parses the OpenVEX output using [go-vex](https://github.com/openvex/go-vex).
   - Keeps only Trivy vulnerabilities whose IDs match govulncheck’s findings (actually used).
   - Moves the rest into **ModifiedFindings** (status `not_affected`, source `trivy-plugin-govulncheck`) so they appear as suppressed rather than dropped.
3. The plugin writes the filtered report to stdout.

Use **`--show-suppressed`** with Trivy to include those findings in the output (e.g. in table or JSON). If a binary cannot be read or govulncheck fails for it, that result’s vulnerabilities are left unchanged (no filtering).

### Image download caveat

The plugin does **not** use Trivy's image cache. When you run `trivy image ... | ./trivy-govulncheck`, Trivy pulls the image for its scan and the plugin pulls the same image again (via go-containerregistry) to extract and run govulncheck on the binaries. That can mean **downloading the image twice** per run. We have a TODO to explore ways to avoid this (e.g. reusing Trivy's extracted layers or a shared cache).

## Prerequisites

**None.** The plugin uses [go-containerregistry](https://github.com/google/go-containerregistry) to pull and extract images in pure Go (no Docker binary required). Govulncheck is compiled in via [golang.org/x/vuln/scan](https://pkg.go.dev/golang.org/x/vuln/scan).

## Installation

**One-step install** (after a release is published, e.g. v0.1.3):

```bash
trivy plugin install github.com/DataDog/trivy-plugin-govulncheck
```

**From a local build** (development or unreleased versions):

```bash
# From a local directory (after building)
make build
tar -czvf govulncheck.tar.gz plugin.yaml trivy-govulncheck
trivy plugin install govulncheck.tar.gz
```

## Usage

The plugin **only supports `trivy image`** output. Use either the **piped** workflow (recommended for development and faster iteration) or the **installed plugin** workflow.

### Piped (recommended for iteration)

No install step: build the binary and pipe Trivy’s JSON into it. Re-run `make build` after code changes; no need to reinstall a plugin.

```bash
make build
trivy image -f json <image> | ./trivy-govulncheck
```

With options (e.g. verbose, pinned vuln DB):

```bash
trivy image -f json tianon/gosu | ./trivy-govulncheck --vuln-db=file:///opt/vulndb -v
```

Redirect to a file or pipe to `jq`:

```bash
trivy image -f json tianon/gosu | ./trivy-govulncheck > report.json
trivy image -f json tianon/gosu | ./trivy-govulncheck | jq '.Results[] | select(.Type=="gobinary")'
```

### Installed plugin

Install once, then use Trivy’s output plugin (same result; useful when you don’t want to manage the binary path):

```bash
trivy image -f json -o plugin=govulncheck <image>
```

Pass plugin options with `--output-plugin-arg`:

```bash
trivy image -f json -o plugin=govulncheck --output-plugin-arg "--vuln-db=file:///opt/vulndb" --output-plugin-arg "-v" <image>
```

### Plugin flags

| Flag        | Description                                                                 |
|-------------|-----------------------------------------------------------------------------|
| `--vuln-db` | Go vulnerability database URL (`file://`, `https://`, or `http://`). If set, govulncheck uses this instead of vuln.go.dev. Use `file:///path` for fully offline scans; no network calls. |
| `-v`        | Verbose: log when a Go binary is skipped (path not found or govulncheck failed). |
| `--export`  | Export a file from an image to a local path (see below). When set, the binary runs in export-only mode and does not read a Trivy report from stdin. |

### Export a file from an image (CLI)

You can run the plugin binary directly to export a single file from a container image for analysis:

```bash
./trivy-govulncheck --export "image_ref:path_inside_image local_path"
```

Example: export the `gosu` binary from the image to the current directory:

```bash
./trivy-govulncheck --export "tianon/gosu:latest:usr/local/bin/gosu ./gosu"
```

The first space in the `--export` value separates the spec from the local path, so the local path may contain spaces. The spec uses the **last** colon to separate the image reference from the path inside the image (so image tags are preserved), e.g. `myreg.io/img:tag:path/to/file`.

### Pinning the vulnerability database (offline / at scale)

By default, govulncheck talks to [vuln.go.dev](https://vuln.go.dev). To avoid network calls and pin to a specific DB version:

1. **Download a snapshot**: [vuln.go.dev/vulndb.zip](https://vuln.go.dev/vulndb.zip) (bulk download per [Go vuln database](https://go.dev/security/vuln/database)).
2. **Extract** the zip to a directory (e.g. `/opt/vulndb` or a path in your CI workspace).
3. **Run the plugin** with a `file://` URL so govulncheck never hits the internet:

   ```bash
   trivy image -f json <image> | ./trivy-govulncheck --vuln-db=file:///opt/vulndb
   ```

The DB must implement the [Go vulnerability database API](https://go.dev/security/vuln/database) (index + per-ID JSON). The zip layout is compatible.

## When filtering applies

- **Go binaries**: Only results with type `gobinary` are processed. Other targets (OS packages, other languages) are left as-is.
- **`trivy image` only**: The plugin pulls and extracts the image to a temp dir using [go-containerregistry](https://github.com/google/go-containerregistry) (pure Go) and runs govulncheck on each Go binary. Reports from `trivy rootfs` or `trivy fs` are not supported; Go binary results from those scans are skipped.

## Build and test locally

```bash
make deps   # go mod tidy
make build  # builds trivy-govulncheck
go test -v ./...
```

For local testing, use the piped workflow (no install): `make build` then `trivy image -f json <image> | ./trivy-govulncheck`. To install from the current directory:

```bash
tar -czvf govulncheck.tar.gz plugin.yaml trivy-govulncheck
trivy plugin install govulncheck.tar.gz
```

### Integration test

The integration test runs the plugin against the Docker image `tianon/gosu` (or override with `TRIVY_PLUGIN_GOVULNCHECK_IMAGE`). It runs `trivy image`, pipes the report to the plugin, and asserts the filtered report is valid and vuln counts only decrease.

Requirements: **trivy** on PATH, and the plugin built (`make build`). Govulncheck is built into the plugin.

```bash
make test-integration
# Or: go test -v -tags=integration ./...
```

**Repeatable runs:** To lock in DB versions and avoid network-dependent variance:

| Env var | Purpose |
|---------|---------|
| `TRIVY_PLUGIN_GOVULNCHECK_IMAGE` | Image to scan. Use a **digest** for a fixed image, e.g. `tianon/gosu@sha256:...`. |
| `TRIVY_PLUGIN_GOVULNCHECK_TRIVY_CACHE` | Directory containing Trivy’s vulnerability DB cache. Trivy is run with `TRIVY_CACHE_DIR` set and `--skip-db-update`, so the DB is not updated. Populate once (e.g. run a trivy image scan with that cache dir), then reuse. |
| `TRIVY_PLUGIN_GOVULNCHECK_VULNDB` | Path to an **extracted** Go vulnerability DB (contents of [vuln.go.dev/vulndb.zip](https://vuln.go.dev/vulndb.zip)). The plugin is given `--vuln-db=file://<path>` so govulncheck uses this DB instead of vuln.go.dev. |

Example for a repeatable integration test run:

```bash
# Optional: use a digest for the image
export TRIVY_PLUGIN_GOVULNCHECK_IMAGE=tianon/gosu@sha256:9cb506f5037e...

# Optional: pin Trivy DB (create cache dir, run one trivy scan to populate, then reuse)
export TRIVY_PLUGIN_GOVULNCHECK_TRIVY_CACHE=$HOME/.cache/trivy-plugin-govulncheck/trivy-db

# Optional: pin Go vuln DB (download vulndb.zip, extract to a dir)
# curl -sL -o vulndb.zip https://vuln.go.dev/vulndb.zip && unzip vulndb.zip -d vulndb
export TRIVY_PLUGIN_GOVULNCHECK_VULNDB=$HOME/.cache/trivy-plugin-govulncheck/vulndb

go test -v -tags=integration ./...
```

## License

See [LICENSE](LICENSE) in this repository.

## Releasing

Releases are built with [GoReleaser](https://goreleaser.com/). Pushing a tag `v*` (e.g. `v0.1.3`) triggers [.github/workflows/release.yaml](.github/workflows/release.yaml), which builds binaries for darwin/linux and amd64/arm64, packages them with `plugin.yaml`, README, and LICENSE, and publishes the artifacts to the [GitHub Releases](https://github.com/DataDog/trivy-plugin-govulncheck/releases) page.

After cutting a new release, update the `version` and `platforms[].uri` URLs in `plugin.yaml` to match the new version so `trivy plugin install github.com/DataDog/trivy-plugin-govulncheck` fetches the new release.

To test the release locally without publishing:

```bash
goreleaser release --snapshot --clean -f goreleaser.yaml
```
