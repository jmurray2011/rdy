# Artifact support and coverage limits

JAR/WAR extraction and manifests use the Go standard library. RPM extraction requires
`rpm` and `bsdtar`; DEB requires `dpkg-deb` and `bsdtar`. Native tools query versions.
ZIP symlinks remain rejected: JAR/WAR manifests and cataloging expect regular
archive entries, and a link would make runtime contents ambiguous. RPM/DEB
payload links are conventional and skipped with counted warnings; database
archives always reject links. All paths retain traversal checks.
bsdtar converts payloads into tar; Go extracts regular files and directories with
traversal and size checks. Symlinks and hardlinks are skipped without being created or followed; their count
is a warning. Special files, unsafe paths and duplicate file paths are rejected.
Limits are 1 GiB per member and 4 GiB per archive. Tests include a tiny real RPM with a symlink when `rpmbuild`, `rpm` and `bsdtar`
are installed; otherwise that integration test reports a clear skip.

Set a meaningful `--min-components` floor for your application. The default catches
empty catalogs; it cannot decide whether a one-component catalog is plausible.
Unmatched counts expose potential advisory blind spots; no match does not prove
absence of exposure. Review runtime identities and opaque bundles separately.
The report header lists provider names and the database build date/age/update
outcome. Matched namespaces/URLs remain in JSON. SHA256 input bindings cover the
artifact, baseline, triage, aliases, embedded/developer SBOMs and the exact candidate
SBOM, alongside tool version, UTC timestamp and effective options without webhook. The scanner descriptor preserves database identity and
configuration in JSON. Counts for missing PURLs use ecosystem `unknown`.

Scanner versions are pinned for reproducibility; Grype updates the advisory database.
Use the same snapshot for repeatable historical comparisons. Scan commands use
controlled defaults rather than inherited scanner-specific environment overrides.


## Warnings

When the artifact ships JavaScript files and no
bundle.cdx.json is embedded, the gate adds a warning even if other npm
components were cataloged. Scripts under node_modules count when their package
has no package.json. Embedded bundle documents without the helper
rdy:frontend-evidence property are warned as unstamped; the property is
an evidence marker, not a cryptographic attestation. Per-bundle paths, component
counts and opaque counts appear in reports. Warnings appear in the verdict line and
report but do not change the verdict in default mode.

`--dev-sbom` and `--baseline-dev-sbom` are deprecated fallbacks. They add all npm
components, without trusting scope, and label added findings `declared, not verified
shipped`. They may contain build-only code or miss bundled code; adopt the embedded
build step for shipped evidence. Artifact evidence takes precedence on an exact
component duplicate. Non-npm build components are never added.


## Rule and outputs

Exit 0 means PASS. Exit 1 means FAIL: a source problem, a candidate SBOM below the
component floor, an untriaged Critical/High finding, or an untriaged KEV under the default block policy. Medium and lower non-KEV findings
are reported without blocking. Exit 2 means usage, Git, extraction, scanner, report,
or stdout error. Exit 3 means a PASS verdict whose notification failed. A FAIL verdict retains
exit 1 even when notification fails. The verdict line is printed before posting;
verdict reports remain intact, while `notify-error.txt` and stderr contain a fixed
error category (DNS, connect, timeout, TLS or HTTP status) without hosts or IPs. Evaluation
errors never print PASS. `--help` and `--version` exit 0
without evaluating a release.

The source check reads the artifact's declared version, orders numeric release tags
with optional leading v and any number of parts, rejects backwards releases, and
lists non-merge patches from the previous release absent on the candidate. Tags are
compared within the release's line: by default the release version without its last
part, so 7.2.7 is checked against 7.2.x and a parallel 7.3.x line does not make it
backwards. A four-part hotfix such as 7.3.2.1 stays on 7.3.2. The previous release is
the highest tag on the line below the release; the first release of a new line falls
back to the highest tag below it in the repository. `--line` sets a different prefix,
for example `--line 7` to order every 7.x tag as one line. Trailing
zero parts compare equally. Patch equivalence makes cherry-picked fixes and previous
tags on later merge commits work correctly. Skipped backwards/missing-patch checks replace `source ok` with `source checks
skipped (N)`. Warnings explain empty latest tags, shallow history, ignored tags
and numeric tags excluded by an explicit --line. JSON records tag count and
selected tag commit SHAs. Without --commit, source identity is explicitly
reported as not asserted.
The report records the source branch
and its resolved commit. `--commit` checks a full SHA supplied by the build against
that commit. This is a source assertion; an artifact without embedded provenance
cannot prove which branch built it.

The output directory contains:

- `report.md`: verdict, source problems, warnings, every missing commit,
  unmatched counts per ecosystem, opaque bundled code, applied aliases, untriaged findings, triaged
  reasons, comparison, vulnerability source set and database build date.
- `findings.json`: normalized evidence, provenance labels, the complete scanner
  descriptor, and baseline findings and triage when supplied.
- `candidate.cdx.json`: the exact merged and aliased CycloneDX SBOM scanned.
- `baseline.cdx.json`: the baseline SBOM when supplied.
- `triage.vex.json`: matched decisions exported as CycloneDX 1.6 VEX, with
  installed versions, UTC timestamp, tool version and artifact identity/hash.

Calendar versions work as numeric parts: `--release 2026.10.2 --line 2026.10`.
For prefixed tags use `--tag-pattern '^api-v([0-9]+(?:\.[0-9]+)*)$'`.
Prerelease tags such as `v2.4.0-rc1` or `api-v2.4.0-rc1` remain ignored,
even with a capture pattern; ignored tag names/counts appear in the evidence.

Use a dedicated output directory. Known report files are replaced each run. Input
paths that collide with those outputs are rejected. Evaluation and stdout
errors replace verdict reports with ERROR when the directory is writable. Partial
SBOM evidence may remain.


## Flags and comparison

Required gate flags: `--name`, `--release`, `--artifact` (or `--sbom` plus
`--artifact-version`), `--repo`, `--branch`,
`--triage`, `--out`.

| Optional flag | Meaning |
| --- | --- |
| `--sbom` | CycloneDX JSON alternative to artifact extraction |
| `--artifact-version` | Required declared numeric version for --sbom |
| `--tag-pattern` | Regex with exactly one capture group for the numeric version |
| `--kev-policy` | `block` (default) or `report` |
| `--aliases` | Reviewed runtime/rename identity table |
| `--commit` | Full declared source SHA |
| `--line` | Release line as a version prefix; default is the release without its last part |
| `--baseline` | Deployed artifact or CycloneDX JSON (`.json`) |
| `--deployed` | Human label for the baseline |
| `--dev-sbom` | Deprecated candidate npm declaration fallback |
| `--baseline-dev-sbom` | Deprecated baseline npm declaration fallback |
| `--min-components` | Candidate component floor, default 1; must be at least 1 |
| `--notify-webhook` | HTTP(S) POST of `{"text":"verdict line"}` |
| `--db-cache` | Database cache directory (default: user cache/rdy/db) |
| `--offline` | Use a valid cached database without network updates |

Baseline processing uses the same catalog, merge, aliases, scanner and triage.
Additions/clearances compare package and advisory only; installed versions do not
change the key. Comparison is informational and never changes the vulnerability
verdict. Baseline tool errors still exit 2. Its counts, coverage and database evidence
are recorded; source checks apply only to the candidate. Baseline JSON skips
extraction because it already represents deployed contents.

The webhook has a 15-second timeout. Non-2xx responses and transport failures preserve verdict reports; PASS exits 3
and FAIL keeps exit 1. Set `RDY_WEBHOOK` as a CI secret instead
of putting the URL on the command line; `--notify-webhook` takes precedence.
Notification errors use fixed categories and omit URLs, hosts and IPs. No webhook is sent on evaluation errors.


## Warning IDs

| Warning ID | Meaning |
| --- | --- |
| source-check-skipped | A backwards-version or missing-patch check could not run. |
| line-override | An explicit release line excludes higher numeric release tags. |
| tags-ignored | Tags could not be parsed as numeric release versions. |
| shallow-repo | Shallow history may omit tags or patches. |
| commit-not-asserted | No source commit identity was asserted. |
| alias-removed-finding | Aliasing removed a Critical, High, or KEV finding. |
| frontend-not-covered | JavaScript ships without an embedded bundle SBOM. |
| bundle-unstamped | An embedded bundle SBOM lacks frontend evidence. |
| archive-links-skipped | Linked artifact files were skipped and lack coverage. |
| db-update-failed | Database updates failed; a valid cached database was used. |
| db-cleanup-failed | Stale database scratch cleanup failed. |
| triage-expired | A triage entry has expired but still applies. |
| kev-not-blocking | Report-only KEV policy allows untriaged KEV findings. |
