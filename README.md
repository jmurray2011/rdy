# rdy

rdy checks whether a release artifact matches its Git source and whether its shipped dependencies have unresolved vulnerabilities. It embeds Syft and Grype, checks numeric release versions and missing patches, applies optional triage and identity aliases, and produces Markdown, JSON and VEX evidence. Untriaged Critical/High findings, KEV findings under the default blocking policy, and source problems fail the release. Warnings are informational by default.

```text
fictional-app 1.2.3  PASS | source ok | 0 Critical, 0 High untriaged | 0 Medium | 0 KEV untriaged
```

## Install

Download the matching binary, SHA256SUMS, and SHA256SUMS.sigstore.json from [Releases](https://github.com/jmurray2011/rdy/releases). Install cosign v3.1.3 to verify signatures. Replace the example tag with the downloaded release:

```sh
tag=v0.1.0
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/jmurray2011/rdy/.github/workflows/release.yml@refs/tags/$tag" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
chmod +x rdy-linux-amd64
./rdy-linux-amd64 --version
# Or build from source (Go 1.26.8):
go install github.com/jmurray2011/rdy/cmd/rdy@latest
```

The selected binary must appear as OK in the checksum output. Each binary also has a `.sigstore.json` verification bundle and `.cdx.json` SBOM. Verify GitHub provenance with `gh attestation verify rdy-linux-amd64 --repo jmurray2011/rdy`. Releases include LICENSE, NOTICE and THIRD_PARTY_NOTICES. SHA tools differ on macOS/Windows; use an equivalent SHA-256 check there.

## Quick start

Use a local Git clone with release tags fetched, and an artifact whose version matches the release:

```sh
printf '[]\n' > triage.yaml
rdy --name fictional-app --release 1.2.3 --artifact build/app.jar \
  --repo . --branch main --commit FULL_COMMIT_SHA --triage triage.yaml --out report
```

Read `report/report.md` after either PASS or FAIL. `findings.json` contains provenance, effective options and machine-readable findings; `triage.vex.json` contains matched decisions. The first run downloads Anchore's advisory database; choose a persistent cache with `--db-cache`.

| Exit | Meaning |
| --- | --- |
| 0 | PASS; help or version output also exits 0 |
| 1 | FAIL, including when notification fails |
| 2 | Usage, input, extraction, scanner or report error |
| 3 | PASS, but webhook notification failed |

## Gate flags

| Flags | Purpose |
| --- | --- |
| `--name`, `--release` | Required display name and numeric candidate version |
| `--artifact` | JAR, WAR, RPM or DEB; alternative to `--sbom` |
| `--sbom`, `--artifact-version` | CycloneDX JSON plus required declared version; evidence is declared, not extracted |
| `--repo`, `--branch`, `--commit` | Required local clone and branch; optional full source commit assertion |
| `--triage`, `--out` | Required triage YAML and report directory |
| `--line`, `--tag-pattern` | Optional release prefix and regex with exactly one numeric-version capture group |
| `--aliases` | Explicit runtime/advisory and rename identity mappings |
| `--min-components` | Minimum candidate SBOM component count; default 1 |
| `--baseline`, `--deployed`, `--baseline-dev-sbom` | Optional deployed artifact/SBOM, display label and declared npm fallback |
| `--dev-sbom` | Deprecated declared npm fallback; not verified shipped |
| `--kev-policy` | `block` (default) or `report` |
| `--strict`, `--allow-warning` | Fail on warnings; allow selected stable IDs (repeatable or comma-separated) |
| `--db-cache`, `--offline` | Persistent advisory cache; scan using a valid fresh cache without updates |
| `--notify-webhook` | Post verdict; defaults to `RDY_WEBHOOK` |
| `--version`, `--help` | Version/commit/Go metadata or usage |

### Frontend build mode

This separate mode supports webpack module graphs and npm package-lock v2/v3. It writes the shipped npm SBOM before minification; no source maps are needed.

| Flags | Purpose |
| --- | --- |
| `--bundle-stats` | Required webpack stats JSON; deleted after successful generation |
| `--lockfile` | Required npm package-lock.json v2/v3 |
| `--bundle-out` | Required output named `bundle.cdx.json`, packaged inside the artifact |

```sh
rdy --bundle-stats build/bundle-stats.json --lockfile package-lock.json --bundle-out build/bundle.cdx.json
```

## Warnings and strict mode

Warnings have stable IDs in JSON (`id`, `message`) and reports (`[id] message`); see the [complete ID table](docs/coverage-limits.md#warning-ids). By default they never affect PASS/FAIL or exit codes. `--allow-warning` without strict mode has no effect and is noted once in the report. Unknown IDs are usage errors listing the valid IDs.

For unattended CI gates that only inspect the exit code, opt into `--strict`. Every warning blocks unless its ID is allowed. Allowed warnings remain visible as `(allowed)`; failures include `strict: N blocking warnings`.

```sh
rdy ... --strict --allow-warning tags-ignored,frontend-not-covered
```

## CI

Fetch tags and full history, use HEAD for tag-triggered builds, and retain the database cache:

```yaml
- uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
  with: {fetch-depth: 0}
- uses: actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830
  with:
    path: .cache/rdy/db
    key: rdy-db-${{ runner.os }}-${{ github.run_id }}
    restore-keys: rdy-db-${{ runner.os }}-
- run: rdy --name fictional-app --release 1.2.3 --artifact build/app.jar --repo . --branch HEAD --commit "$GITHUB_SHA" --triage triage.yaml --db-cache .cache/rdy/db --out report
```

## Supported artifacts

| OS | Artifact support and requirements |
| --- | --- |
| Linux amd64/arm64 | JAR/WAR; RPM with `rpm`/`bsdtar`; DEB with `dpkg-deb`/`bsdtar`; CycloneDX SBOM |
| macOS amd64/arm64 | JAR/WAR and CycloneDX SBOM; RPM/DEB require compatible native extraction tools |
| Windows amd64 | JAR/WAR and CycloneDX SBOM |

JAR/WAR versions come from `Implementation-Version`; RPM VERSION ignores release and strips `~`/`^` suffixes; DEB Version strips epoch and revision. Containers, plain binaries, wheels and npm tarballs use `--sbom` instead of `--artifact`. Numeric tags allow leading `v`; prerelease tags are ignored. Calendar releases work (for example `--release 2026.10.2`); use `--tag-pattern '^api-v([0-9]+(?:\.[0-9]+)*)$'` for prefixed numeric tags.

## Details

[Triage](docs/triage.md) · [Aliases](docs/aliases.md) · [Frontend evidence](docs/frontend-evidence.md) · [KEV](docs/kev.md) · [Database/offline](docs/database-and-offline.md) · [Coverage limits](docs/coverage-limits.md) · [Architecture](docs/architecture.md). See [CONTRIBUTING](CONTRIBUTING.md) for builds and tests, and [SECURITY](SECURITY.md) for private reporting.

## Data sources and terms

rdy does not bundle or redistribute the vulnerability database. It downloads Anchore's database, assembled from upstream feeds with mixed licenses and terms; consult [Grype data sources](https://oss.anchore.com/docs/reference/grype/data-sources/). Reports include provider-derived advisory text.

## License

[Apache-2.0](LICENSE), Copyright 2026 Josh Murray. [NOTICE](NOTICE) points to generated [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES), including upstream notices, elected dual licenses and MPL source URLs.
