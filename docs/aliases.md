# Runtime identities and renames

Advisories sometimes name an embedded artifact while standalone runtimes ship
separately named JARs. Use a reviewed YAML identity table with `--aliases`:

```yaml
- from: pkg:maven/org.example.server/server-core
  to: pkg:maven/org.example.server.embed/server-embed-core
- from: pkg:maven/org.example.old/parser
  to: pkg:maven/org.example/parser
```

The table rewrites only those explicit PURLs and their Maven name/group and retained
Syft Maven identity properties before scanning,
preserving version and other component metadata. The gate also scans the pre-alias SBOM and reports findings removed by aliases;
Critical, High or KEV removal adds a warning without changing the default verdict rule.
The headline counts applied aliases/components, and each mapping lists rewritten
versions. Pre-alias candidate/baseline SBOMs are retained when a rewrite occurs.
The same canonical identities are
used for candidate, baseline and triage, so major-version renames do not create
comparison churn. Alias chains resolve to their final identity; cycles, duplicates,
self-aliases and versioned aliases are errors. Applied mappings appear in the report.
There are no guessed or product-wide aliases. Configure the table for the runtime
packages your application ships; `../examples/aliases.yaml` is fictional test data.

Grype uses default matching. Global Java CPE matching is forbidden. The adapter supplies explicit library configuration and does not load scanner config files or SYFT_/GRYPE_ environment overrides. Unknown severity, ignored matches, or missing/invalid database
provenance produce an error. Findings are deduplicated by package, advisory and
installed version, retaining highest severity and all reported fixes.

