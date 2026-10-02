# Build-time frontend evidence

The build dependency graph's scope is not evidence of what ships. Instead, collect
the bundler graph before minification and resolve exact module paths against
`package-lock.json` v2/v3. Nested `node_modules/a/node_modules/b` paths resolve to
the nested lockfile entry, including duplicate package versions. Scoped packages,
loader identifiers, nested modules, compilation children and chunks are supported.
Dependencies absent from the graph are excluded regardless of dev/runtime scope.
Unresolved module packages are errors rather than silently missing components.

For a webpack build (including CRA 5's `react-scripts build --stats`):

```sh
react-scripts build --stats
./rdy --bundle-stats build/bundle-stats.json --lockfile package-lock.json --bundle-out build/bundle.cdx.json
# Package build/ into the release artifact, including bundle.cdx.json.
```

The helper writes CycloneDX and removes the stats file only after successful emission.
Do not package stats files or source maps. For other webpack setups, use `webpack
--json` or a stats plugin to capture the same module graph. The helper requires the
output basename `bundle.cdx.json`, which matches Syft's `**/*.cdx.*` cataloger pattern.
The gate explicitly enables `+sbom-cataloger`; it also verifies that every component
in extracted `bundle.cdx.json` files survived cataloging. Syft reads nested runtime
JARs and the embedded bundle SBOM, then Grype reads only the resulting SBOM.

A module under a package's dist/ tree or named *.min.js is opaque only when its declared runtime dependencies (lockfile dependencies) are absent from the module graph. A node_modules tree inside dist/ is always opaque and resolves to the outer package. Opaque rows include the unaccounted dependencies. Other prebuilt packages contribute only to the report's prebuilt_without_vendoring_evidence count; they are not counted as opaque. Counts use distinct package/version identities and exclude packages with opaque modules.

