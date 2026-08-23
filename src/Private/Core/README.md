# Private/Core

Helpers used by Collect, Baseline capture, Analyze, and Report. One function per file.
These are **not** exported - tests use `InModuleScope Foton`.

Windows PowerShell 5.1 syntax only. Empty catch blocks on best-effort paths are intentional.

Session state lives in `$script:FotonSession` (see `Initialize-FotonSession.ps1`).
Call `Initialize-FotonSession` at the start of a collect/baseline run.

Name mapping from the historical v1 collector (if `WinFoton.ps1` is still in the tree for tests):

| WinFoton.ps1              | Foton                          |
|---------------------------|--------------------------------|
| Write-Status              | Write-FotonStatus              |
| Add-Finding               | Add-FotonFinding               |
| Invoke-Collection         | Invoke-FotonCollection         |
| Get-ArtifactPath          | Get-FotonArtifactPath          |
| Test-Elevated             | Test-FotonElevated             |
| Get-SafeHash              | Get-FotonSafeHash              |
| Get-SignatureInfo         | Get-FotonSignatureInfo         |
| Test-UserWritablePath     | Test-FotonUserWritablePath     |
| Test-SuspiciousCommand    | Test-FotonSuspiciousCommand    |
| Get-RegValueSafe          | Get-FotonRegValue              |
| Get-RegValueList          | Get-FotonRegValueList          |
| ConvertTo-SafeHtml        | ConvertTo-FotonSafeHtml        |
| Get-UserProfileList       | Get-FotonUserProfile           |
| Mount-OfflineUserHives    | Mount-FotonOfflineUserHive     |
| Dismount-OfflineUserHives | Dismount-FotonOfflineUserHive  |
| Get-UserHiveRoots         | Get-FotonUserHiveRoot          |

`Get-FotonPatternLines` is module-only (no WinFoton equivalent). Pattern files live in `src/Private/Patterns/`.

`Get-FotonReportMarkSvg` is the HTML brand mark (wave packet). `Get-FotonReportNavCss` / `NavBarHtml` / `NavScript` are report chrome.

`Copy-FotonHostFile` / `Copy-FotonCappedHostFiles` / `Copy-FotonHostFileFamily` copy live files with `FileShare.ReadWrite` (Prefetch, Amcache, SRUM). Parse the copies only.

`ConvertFrom-FotonFileTimeUtc` / `Get-FotonBamDamRows` support Collect BAM/DAM. AppCompatCache is a raw blob export, not a parsed Shimcache table.

Hive mount prefix is `Foton_<SID>`. `Get-FotonUserHiveRoot` also accepts historical `WinFoton_<SID>` mounts.
