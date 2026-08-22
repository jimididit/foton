# Public/Collect

Live triage acquisition. **This layer may touch a running Windows host.**

One file per category (System, Users, Processes, Network, Persistence, Security,
EventLogs, Filesystem, Software), matching the nine sections in frozen `WinFoton.ps1`.

Each task should go through the collection wrapper (to be extracted as
`Invoke-FotonCollection`): write artifact, manifest row, timing, error capture, cache.

Collectors emit **facts**. Do not call `Add-FotonFinding` from Collect.

**Privilege:** tasks that need an Administrator token must set `RequiresElevation` on the collection wrapper so StandardUser runs skip them with a disclosed gap (`SkippedNotElevated`). Do not dump Access Denied into `collection_errors.csv` for those tasks. Never skip a task that is still useful without admin (process list, HKCU, readable HKLM).

Ships to endpoints only via `dist/Foton-Collect.ps1` (flattened). Do not tell operators
to `Import-Module` this tree on a possibly compromised host.
