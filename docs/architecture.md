# Architecture and dependencies

Go was chosen for a static binary and standard-library archives, JSON, HTTP and
process handling. Pinned Syft and Grype Go libraries provide cataloging and matching inside the binary. Their dependency trees increase binary size but eliminate separate scanner installations. YAML parsing uses go.yaml.in/yaml/v3. The dependency graph is pinned in go.mod and go.sum.

`core` is pure and I/O-free: numeric versions, tag selection, merge, triage, diff,
verdict, module-graph resolution and aliases. `gate` owns Git, extraction, scanners
and reports. The scanner seam has two methods and uses small test fakes. The CLI
wires dependencies and cancellation. depguard restricts `core` to standard-library
imports. The linker supplies the build version; it is never changed at runtime.

