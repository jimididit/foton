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
    ModuleVersion     = '1.11.0'
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
        'Invoke-FotonParse'
        'New-FotonParseReport'
        'Invoke-FotonCarve'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags         = @('DFIR', 'Forensics', 'Windows', 'Baseline', 'SecurityAudit', 'Triage')
            LicenseUri   = ''
            ProjectUri   = ''
            ReleaseNotes = '1.11.0: baseline schema 1.6.0 LsaPackage (SSP/AP/NP tokens, Added/Removed). Recapture day0. RemoteAccessConfig remains 1.5.0 surfaces.'
        }
        Foton  = @{
            # Collect package layout / artifact columns. Bump when a collector changes the on-disk contract.
            CollectSchemaVersion  = '1.2.0'
            # Baseline payload identity keys and compared fields. Diff must refuse a mismatch.
            BaselineSchemaVersion = '1.6.0'
            # Findings object shape (Severity, Tier, Artifact, ...).
            FindingsSchemaVersion = '1.0.0'
        }
    }
}
