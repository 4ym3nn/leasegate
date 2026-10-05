# Private integration snapshots

These packages are owned by the same repository owner and retained for reproducible integration checks:

| Package | Version | Source |
| --- | --- | --- |
| authority-boundary | 0.2.1 | https://github.com/4ym3nn/authority-boundary |
| authztrace | 0.1.0 | https://github.com/4ym3nn/authztrace |

`SHA256SUMS` pins the exact archives. The npm lockfile additionally pins installation integrity and transitive dependencies. Verify with `cd integrations/vendor && sha256sum -c SHA256SUMS`.

These are private, unlicensed package snapshots. Do not redistribute them without permission. They are loaded only by the test harness; the Go runtime does not depend on them.
