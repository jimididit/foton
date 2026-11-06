#
# Foton module manifest
#
# This is the workstation import path (Parse / Analyze / Report / Baseline diff).
# The Collect layer still ships as a single flattened script from build/Build-Standalone.ps1 -
# never deploy this module tree onto a target endpoint.
#
# Versioning:
#   ModuleVersion     - Foton product version (bump when behavior or public API changes)
#   PrivateData.Foton - schema versions for packages and baselines (Compare-FotonBaseline
#                       must refuse incompatible baseline schemas)
#
@{
    RootModule        = 'Foton.psm1'
    ModuleVersion     = '1.37.0'
    GUID              = 'b7e4c1a2-8d3f-4a91-9c6e-2f0d5a8b1e73'
    Author            = 'JDI Consulting'
    CompanyName       = 'JDI Consulting'
    Copyright         = '(c) JDI Consulting. All rights reserved.'
    Description       = @'
Foton is a Windows forensic, baseline, and security-audit toolkit.

Collect captures live host state into a hashed case package. Baseline snapshots
stable configuration for later comparison. Parse, Carve, and Analyze run only
against already-collected data so work is reproducible and testable.

Windows PowerShell 5.1 compatible for Collect and Baseline. Parse/Carve/Analyze
may require PowerShell 7; if they do, it will be stated on those commands.
'@
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    # FunctionsToExport is an allow-list. Add a name here when you add a Public/*.ps1
    # file; do not use '*' - contributors should see the command surface in one place.
    FunctionsToExport = @(
        'Get-FotonVersion'
        'Get-FotonPackage'
        'Invoke-FotonAnalysis'
        'New-FotonReport'
        'Invoke-FotonTriage'
        'New-FotonBaseline'
        'New-FotonBaselineReport'
        'New-FotonBaselineCompareReport'
        'Compare-FotonBaseline'
        'Invoke-FotonIocMatch'
        'ConvertFrom-FotonPrefetch'
        'ConvertFrom-FotonLnk'
        'ConvertFrom-FotonEvtx'
        'ConvertFrom-FotonJumplist'
        'ConvertFrom-FotonAmcache'
        'Invoke-FotonParse'
        'Invoke-FotonExternalParse'
        'Install-FotonTool'
        'New-FotonParseReport'
        'Invoke-FotonCarve'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags         = @('DFIR', 'Forensics', 'Windows', 'Baseline', 'SecurityAudit', 'Triage')
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            ProjectUri   = 'https://github.com/jimididit/foton'
            ReleaseNotes = '1.37.0: services.csv records ServiceDll for svchost-hosted services (path, ServiceDllSource, user-writable flag, signature, signer, SHA-256); per-user instances get the template DLL, marked Template:<name>. Analyze adds a user-writable ServiceDll to the High user-writable service finding, a Medium finding for NotSigned/HashMismatch ServiceDll, and stops excluding a per-user service install event when that instance has its own ServiceDll or the DLL is outside System32, user-writable, or unsigned. Collect schema 1.13.0. 1.36.0: Compose and tools. Install-FotonTool -Name EZTools|Chainsaw|<tool> -Path <folder> registers an existing install in tools.json (observed SHA-256, not verified; PATH untouched), including EZ Tools per-tool subfolders; Foton.cmd tools EZTools <dir>. RECmd runs with BatchExamples\DFIRBatch.reb (or Kroll_Batch.reb), else NoBatch. Chainsaw runs hunt with rules/sigma beside the binary, else NoRules (no more EVTX dump). Hayabusa writes UTC (-U). Tool stdout is captured; a missing .NET runtime is recorded as MissingRuntime. Each tool runs into a staging folder; earlier output is swapped out by folder rename only when the run produced files, otherwise it is kept and listed as Retained (SwapError if the rename fails). Tool arguments are quoted so case paths with spaces survive. Banner and Triage/Baseline version fallbacks read the manifest instead of stale literals. 1.35.0: Analyze accuracy. EvtxECmd suspicious-command matching only on command-bearing events (4688, Sysmon 1, 4104, 4697, 7045, 4698, 4702), so lsass.exe as the image of 4673/4674 no longer counts; EvtxECmd rows inside the collection window are excluded from path/pattern counts with an Info methodology finding; the CSV is streamed. Service installs (native 7045 and EvtxECmd 4697/7045) exclude per-user service instances (Name_<hex>) and name the services; title no longer claims the collection window. Account findings separate create-then-delete within 60 s (Low) from persistent accounts and privileged group adds (Medium); adds to the default primary group are not privilege changes. Host baseline says days since last boot includes sleep/hibernation. New Low finding when Sysmon is set to Auto but not running; new Info finding listing Partial/Failed collection tasks. 1.33.0: Collect correctness from a real before/after-BIOS case. Loaded registry hives (SYSTEM, SOFTWARE, DEFAULT, signed-in users NTUSER/UsrClass) are exported with reg save instead of a FileShare copy that always failed; SAM and SECURITY are recorded as NotCollectedByDesign. Copy tasks report Partial/Failed (manifest, coverage, errors) instead of Good when files were not captured. Prefetch copy cap 200 -> 1024. Profile scans skip earlier Foton case folders. Local group membership falls back to ADSI on error 1789. os_info adds SMBIOS version, BIOS release date, EC version; boot_and_firmware adds Firmware-class devices (staged UEFI updates). Collect schema 1.12.0. 1.32.0: Collect -Deep opt-in (forces FileTimeline + UsnJournal; adds task_action_scripts, pnp_devices, driverstore_inventory, gpresult_html with raised budgets and 2 GiB free-space gate). Collect schema 1.11.0. 1.31.0: Analyze/Collect accuracy - local group enum errors no longer look empty; scheduled-task UserWritableTarget probes Arguments; firewall/Sysmon bool comparisons fixed; -enc pattern uses word boundaries; unreadable Defender exclusions are Info visibility gaps; PowerShell operational Highs exclude collector window. 1.30.0: Baseline operator path - Compare writes baseline_diff.csv; findings cite provider FalsePositives; Analyze lifts all High-attention baseline_diff rows with FP notes; USAGE temporal and fleet recipes. 1.29.0: Invoke-FotonAnalysis ingests PECmd and EvtxECmd compose CSV (coverage, user-writable path references, high-attention EventIds 1102/104/4697/7045/4698, and suspicious-command matches on ExecutableInfo); findings cite the tool. Chainsaw ingest still open. 1.28.0: Install-FotonTool + Foton.cmd tools provision pinned Hayabusa into %LOCALAPPDATA%\Foton\tools (tools.json); compose resolves -ToolPath then manifest then PATH and never mutates PATH; inventory/report carry tool Version and RulesVersion; NotOnPath points at Install-FotonTool. 1.27.0: External tools now run with their own install directory as the working directory, fixing Hayabusa reporting missing rules/config. Hayabusa hits caused by the Foton collection itself are attributed (collection window from collection.log, plus rows naming a Foton function) and excluded from the severity bands, with an Info methodology finding - on a real package this cut 350 medium-level hits to 60. Fix Defender AMSI blocking the Collect flatten as Trojan:PowerShell/PSAttackTool.A - the embedded suspicious-command pattern list is no longer inlined into dist. Collectors stop interpreting: SuspiciousHits/SuspiciousCmdHits are written empty and Analyze derives them from the raw Command/Actions/CommandLine columns, with an Info visibility-gap finding when no pattern list is loaded. New build/Test-FotonAmsiLoad.ps1 runs an AMSI load check in both flatten builds, since ParseFile never invokes AMSI. 1.26.0: ZIP analyze writes <zip-stem>_Report.html/_findings.csv beside the ZIP; New-FotonReport returns its path. Detect and skip packages that contain a copy of themselves. Analyze says when it is reproducing the endpoint Collect report. Hayabusa v4 (dfir-timeline, -w) supported and hits are banded by level with rule names instead of one generic row.'
        }
        Foton  = @{
            # Collect package layout / artifact columns. Bump when a collector changes the on-disk contract.
            CollectSchemaVersion  = '1.13.0'
            # Baseline payload identity keys and compared fields. Diff must refuse a mismatch.
            BaselineSchemaVersion = '1.14.0'
            # Findings object shape (Severity, Tier, Artifact, ...).
            FindingsSchemaVersion = '1.0.0'
        }
    }
}
