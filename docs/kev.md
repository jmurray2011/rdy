# Known exploited vulnerabilities

Grype's database includes CISA KEV data. The gate reads native `knownExploited`
records from both matched advisories and related CVE aliases, retaining membership
through deduplication. Every verdict line includes an untriaged KEV count. Reports
include CVE, date added, due date, required action and ransomware-campaign context,
plus the KEV provider capture timestamp and full database descriptor.

`--kev-policy block` (default) fails on any untriaged KEV finding regardless of
severity. `--kev-policy report` highlights KEV while retaining the Critical/High
severity rule, and warns when untriaged KEV is allowed without KEV blocking. Valid triage decisions resolve KEV under either policy. The chosen
policy is recorded in both reports. Invalid policies and a missing KEV database
provider are tool errors. CISA due dates are reported as context; no deadline or
federal-agency applicability is assumed by the gate. Database updates can change
KEV membership even when the artifact is unchanged.

KEV awareness only covers scanner findings: it does not repair unknown package
identities or opaque bundles. Keep runtime aliases and bundle evidence in place.
See [Grype data sources](https://oss.anchore.com/docs/reference/grype/data-sources/)
and [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

