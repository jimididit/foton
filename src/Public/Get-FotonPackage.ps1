function Get-FotonPackage {
    <#
    .SYNOPSIS
        Open a Foton or WinFoton case folder (or ZIP) and load artifacts into session.

    .DESCRIPTION
        Analyze and Report never read the live host. This command points the session
        at an already-collected package: hashed CSVs/JSON/TXT under 00_Collection
        through 09_Software_and_Drivers. v1 folders named WinFoton_* are valid.

        Does not modify hashes.csv or original collect artifacts. ZIP files are
        extracted to a temp directory for this process.

    .PARAMETER Path
        Case folder, or a ZIP produced by WinFoton.ps1 / Foton collect.

    .EXAMPLE
        Get-FotonPackage -Path C:\FotonCases\WinFoton_HOST_20260101-120000Z
        Invoke-FotonAnalysis
        New-FotonReport

        Re-run heuristics and HTML against a package collected earlier, offline.

    .OUTPUTS
        PSCustomObject (CaseRoot, SourcePath, Kind)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Package path not found: $Path"
    }

    Initialize-FotonSession

    $item = Get-Item -LiteralPath $Path
    $kind = 'Folder'
    $caseRoot = $item.FullName

    if ($item.Extension -eq '.zip') {
        $kind = 'Zip'
        $dest = Join-Path $env:TEMP ('FotonPkg-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path $dest -ItemType Directory -Force | Out-Null
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        [System.IO.Compression.ZipFile]::ExtractToDirectory($item.FullName, $dest)
        $caseRoot = Resolve-FotonCaseRoot -SearchRoot $dest
    }
    else {
        $caseRoot = Resolve-FotonCaseRoot -SearchRoot $item.FullName
    }

    Import-FotonPackageData -CaseRoot $caseRoot
    $script:FotonSession.Package = @{
        SourcePath = $item.FullName
        Kind       = $kind
        CaseRoot   = $caseRoot
    }

    Write-FotonStatus ("Loaded package {0} ({1} cached artifact keys)" -f $caseRoot, $script:FotonSession.Data.Count) 'Good'

    [PSCustomObject]@{
        CaseRoot     = $caseRoot
        SourcePath   = $item.FullName
        Kind         = $kind
        ArtifactKeys = @($script:FotonSession.Data.Keys | Sort-Object)
        ManifestRows = $script:FotonSession.Manifest.Count
    }
}
