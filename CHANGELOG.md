# Changelog

All notable changes are documented here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0-rc1]

### Added
- First release candidate for rdy: static binaries for Linux, macOS and Windows, with checksums, signatures, provenance, SBOMs and license notices.
- Source and artifact version checks, embedded Syft/Grype scanning, KEV policy, triage/VEX, baseline comparisons, explicit aliases, webpack/npm frontend evidence, warnings and opt-in strict mode.

## [0.1.0]

### Added
- Release readiness CLI with source/tag/patch checks and artifact version verification.
- Embedded Syft and Grype, explicit advisory sources, KEV blocking/report policy, triage and CycloneDX VEX export.
- Deployed baseline comparisons, runtime identity aliases, webpack/npm bundle evidence and opaque-code reporting.
- Stable warning IDs, opt-in strict mode and webhook notifications.
- Static Linux, macOS and Windows binaries, SHA-256 checksums, cosign bundles, GitHub provenance, per-binary SBOMs and Apache-2.0 licensing.
