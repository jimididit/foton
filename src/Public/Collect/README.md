# Public/Collect

Live triage acquisition. **This layer may touch a running Windows host.**

`WinFoton.ps1` is the frozen **v1** endpoint runner. `dist/Foton-Collect.ps1` is the flattened module Collect (rebuild after Collect edits). These files are not all exported from `Foton.psd1`; `Invoke-FotonTriage` is the orchestrator.

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

**Privilege:** `-RequiresElevation` on the collection wrapper for admin-only tasks.

Ships to endpoints only via `dist/Foton-Collect.ps1` once flatten exists.
