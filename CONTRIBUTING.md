# Contributing

Open an issue before changing behavior. No DCO or CLA is required.

Use Go 1.26.8 and Git. Install the pinned validation tools:

```sh
go install mvdan.cc/gofumpt@v0.12.0
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
go install golang.org/x/vuln/cmd/govulncheck@v1.8.0
CGO_ENABLED=0 go build -trimpath -o build/rdy ./cmd/rdy
sh scripts/validate.sh
```

The embedded scanners are Syft 1.54.0 and Grype 0.119.0; scanner executables are not prerequisites. Linux native fixture tests need libarchive-tools, rpm (rpmbuild) and dpkg-deb. Race tests need a C compiler; Windows can use LLVM-MinGW clang (`CC=clang`) with `pwsh -File scripts/validate.ps1`.

Use TDD for code changes: show the failing test before implementation. Tests are hermetic and use fictional names, temporary repositories and scanner fakes. `core` is stdlib-only, enforced by depguard. Preserve default verdict behavior, opt-in strict behavior and the documented opaque rule unless a behavior change is agreed first.

After dependency changes run `go mod tidy`, then `sh scripts/third-party-notices.sh` (or `go run ./internal/notices` on Windows), and include the generated THIRD_PARTY_NOTICES with your change. The generator builds all five static release targets in temporary storage and reads `go version -m` plus module-cache license files. Validation checks formatting, vet, lint, race tests, vulnerabilities, module integrity/tidiness and notice drift. Run gofumpt before submitting; all Go files carry the Apache-2.0 SPDX header.

Release notes come from the exact CHANGELOG section matching the tag, including prereleases. Actions are pinned by commit SHA; signing uses cosign v3.1.3. Release publication is maintained by the owner.
