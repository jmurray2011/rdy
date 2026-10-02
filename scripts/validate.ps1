$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
$format = & gofumpt -l .
if ($LASTEXITCODE -ne 0 -or $format) { throw "Formatting failed: $format" }
& go vet ./...
if ($LASTEXITCODE -ne 0) { throw 'Vet failed' }
& golangci-lint run
if ($LASTEXITCODE -ne 0) { throw 'Lint failed' }
$env:CGO_ENABLED = '1'
& go test -race ./...
if ($LASTEXITCODE -ne 0) { throw 'Race tests failed' }
& govulncheck ./...
if ($LASTEXITCODE -ne 0) { throw 'Vulnerability check failed' }
# Preserve upstream cache filenames containing trailing spaces during Windows verification.
$rdyModuleCache = (& go env GOMODCACHE).Trim()
$rdyPreviousModuleCache = $env:GOMODCACHE
try {
    if ($rdyModuleCache.StartsWith('\\?\')) {
        $env:GOMODCACHE = $rdyModuleCache
    } elseif ($rdyModuleCache.StartsWith('\\')) {
        $env:GOMODCACHE = '\\?\UNC\' + $rdyModuleCache.Substring(2)
    } else {
        $env:GOMODCACHE = '\\?\' + $rdyModuleCache
    }
    & go mod verify
    if ($LASTEXITCODE -ne 0) { throw 'Module verification failed' }
} finally {
    $env:GOMODCACHE = $rdyPreviousModuleCache
}
& go mod tidy -diff
if ($LASTEXITCODE -ne 0) { throw 'Module tidy drift' }
