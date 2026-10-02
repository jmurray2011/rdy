# Database freshness and offline use

Grype enforces a maximum database build age of five days, online and offline.
Reports show build date, age and update outcome: `ok`, `failed: reason`, or
`skipped: offline`. An update failure can use a still-valid cache and adds a
warning; a missing, invalid or over-age cache remains a scanner error.

To seed an offline machine, run a normal online gate with `--db-cache /path/db`,
then copy that entire cache directory (including its `6/` schema folder) to the
offline machine and use `--db-cache /copied/db --offline`. Refresh within five days.
No separate scanner executable is needed to seed or use the cache. Downloads have
30-second connect/header timeouts, a 10-second TLS handshake timeout and a two-minute
idle timeout that resets on progress; there is no whole-download deadline. Startup
tries to remove abandoned download scratch directories older than 24 hours while
retaining recently active directories. Missing entries are ignored; other cleanup
errors add warnings and never abort a scan. SIGINT and SIGTERM cancel the run.

