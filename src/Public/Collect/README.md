# Public/Collect

Live triage acquisition. **This layer may touch a running Windows host.**

Ships to endpoints only via `dist/Foton-Collect.ps1` (rebuild after Collect edits). Collect functions are not exported; `Invoke-FotonTriage` orchestrates.

| File | Status |
|------|--------|
| `Invoke-FotonSystemCollection.ps1` | Extracted |
| `Invoke-FotonUserCollection.ps1` | Extracted |
| `Invoke-FotonProcessCollection.ps1` | Extracted |
| `Invoke-FotonNetworkCollection.ps1` | Extracted |
| `Invoke-FotonPersistenceCollection.ps1` | Extracted |
| `Invoke-FotonSecurityCollection.ps1` | Extracted |
| `Invoke-FotonEventLogCollection.ps1` | Extracted |
| `Invoke-FotonFilesystemCollection.ps1` | Extracted |
| `Invoke-FotonSoftwareCollection.ps1` | Extracted |

Collectors emit **facts**. Do not call `Add-FotonFinding` from Collect.

**Coverage:** Collect includes per-user Run keys, **startup_approved**, BITS, COM candidates, LSA/IFEO, **cmd_autorun / session_manager_boot / known_dlls / winsock_lsp / active_setup**, **named_pipes**. Prefetch `.pf`, Amcache.hve, and SRUM are **copied** into `08_Filesystem/{prefetch,amcache,srum}`. Gap list: [docs/COVERAGE.md](../../../docs/COVERAGE.md).

**Privilege:** `-RequiresElevation` on the collection wrapper for admin-only tasks.

Ships to endpoints only via `dist/Foton-Collect.ps1`.
