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

**Coverage:** Collect includes per-user Run keys, **startup_approved**, BITS, COM candidates, LSA/IFEO, **cmd_autorun / session_manager_boot / known_dlls / winsock_lsp / active_setup / silent_process_exit / netsh_helpers / time_providers / screensaver**, **named_pipes**, **entra_workplace_join**, **onedrive_teams_local**. Prefetch `.pf`, Amcache.hve, SRUM, **LNK/jumplists**, **Tasks XML**, **browser DBs**, and **host text logs** are **copied** into `08_Filesystem/...`. **Registry hives** are exported with `reg save` when loaded (SYSTEM, SOFTWARE, DEFAULT, signed-in users' NTUSER/UsrClass) and copied when not; SAM and SECURITY are never collected. `services.csv` records `ServiceDll` for svchost-hosted services. `os_info` / `boot_and_firmware` carry SMBIOS, BIOS release date, EC version, and Firmware-class devices. BAM/DAM UserSettings CSV and raw **AppCompatCache.bin** live under Filesystem (admin). Optional `-IncludeUsnJournal`; `-Deep` adds task scripts, PnP, DriverStore, and gpresult. Operator view: [docs/USAGE.md](../../../docs/USAGE.md).

**Status:** copy tasks derive `Partial` / `Failed` from their per-file `Status` rows (`Get-FotonCopyTaskStatus`), so a task that missed files never reports Good. Profile scans skip this run's case folder and earlier Foton packages (`Test-FotonCaseOutputPath`).

**Privilege:** `-RequiresElevation` on the collection wrapper for admin-only tasks.

Ships to endpoints only via `dist/Foton-Collect.ps1`.
