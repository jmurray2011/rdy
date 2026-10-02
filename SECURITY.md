# Security policy

The latest released version of rdy is supported. Please update before reporting an issue.

Report security vulnerabilities privately using [GitHub private vulnerability reporting](https://github.com/jmurray2011/rdy/security/advisories/new). Please include the version, platform, reproduction steps and impact, with fictional or redacted evidence. Expect acknowledgement within five business days; coordinated disclosure timing is agreed during investigation.

The scope includes artifact extraction, source checks, verdict handling and report integrity. Issues in embedded Syft or Grype should also be reported privately to their upstream projects. Scanner-update requests are welcome as ordinary issues when they do not expose a new vulnerability.

Known advisory: [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) affects golang.org/x/crypto/openpgp in a required module. rdy does not import or call that package; govulncheck reports it as unreachable. No fix is available for that advisory. Recheck reachability and upstream status when dependencies change.
