# Triage

The YAML file is one document containing a list of `{package, cve, status, reason}`.
Unknown fields, duplicate decisions, missing required values, invalid statuses, extra documents
and blank reasons are errors. Status is `not_affected`, `fixed_in` or `accepted`.
Decisions match package and advisory across every installed version. `fixed_in` is
a reviewed assertion, not an automatically enforced version constraint.

Package keys are PURLs without version, qualifiers or subpath, for example
`pkg:maven/org.example/runtime` or `pkg:npm/%40example/frontend`. Copy keys from
`findings.json`. The `cve` field matches a finding's advisory ID or any related
identifier, so a decision keyed by CVE matches a finding reported under a GHSA and the
reverse. Baseline comparison treats related identifiers as the same advisory. Alias
canonicalization also applies to historical triage identities.

The VEX export maps `not_affected` to `not_affected`, `fixed_in` to `in_triage`, and
`accepted` to `exploitable` with response `will_not_fix`. Reasons become analysis
details. It exports only decisions that matched this run's candidate findings,
with each matched installed version. The complete decision list remains in
`findings.json`. Optional `justification` on `not_affected` maps to CycloneDX
`analysis.justification` only for a valid CycloneDX enum value; other text remains
in analysis.detail.

Optional `reviewed_by`, `reviewed_on` and `expires` appear in reports and JSON.
Dates must use YYYY-MM-DD when supplied. Expired decisions still apply and add an
informational warning; entries matching neither candidate nor baseline are listed under "Triage entries
with no match in this run", with a JSON count.
Triaged rows show severity and mark expired entries `(expired)`. The headline
counts triaged Critical/High/KEV findings and expired decisions still in force.
A matched `fixed_in` decision is marked `fixed_in (scanner still reports this
version)`; it is not version-checked.

