function New-FotonBaseline {
    <#
    .SYNOPSIS
        Capture a normalized snapshot of stable host configuration.

    .DESCRIPTION
        Live capture (WMI/registry). Excludes PIDs, connections, uptime, and sessions.
        Same machine state should serialize to the same compared payload (header
        timestamps are outside the hashed records). Store the package off-host.

        A snapshot taken after intrusion is a picture of that state. Diffs prove
        change between two observations, not when or who.

        Default is a FotonBaseline_<host>_<stamp>Z folder (JSON, HTML snapshot,
        hashes, optional ZIP). Pass -Path to a .json file for a bare snapshot
        (scripts and Compare fixtures).

    .PARAMETER Path
        Write only this JSON file (no package folder).

    .PARAMETER OutputPath
        Parent directory for a baseline package folder. Default: Desktop.

    .PARAMETER NoZip
        Leave the package folder uncompressed.

    .PARAMETER NoHtml
        Skip Foton_Baseline.html.

    .PARAMETER RequireAdministrator
        Exit without capturing if the token is not elevated.

    .EXAMPLE
        New-FotonBaseline -OutputPath D:\Baselines -NoZip

        Package folder on D:\Baselines. Open Foton_Baseline.html inside it.

    .EXAMPLE
        New-FotonBaseline -Path D:\Baselines\web01-provision.json

        JSON only, for Compare-FotonBaseline.

    .OUTPUTS
        PSCustomObject (Path, PackageRoot, PayloadSha256, SchemaVersion, RecordCounts)
    #>
    [CmdletBinding(DefaultParameterSetName = 'Package')]
    param(
        [Parameter(ParameterSetName = 'Json', Mandatory)]
        [string]$Path,
        [Parameter(ParameterSetName = 'Package')]
        [string]$OutputPath = "$env:USERPROFILE\Desktop",
        [Parameter(ParameterSetName = 'Package')]
        [switch]$NoZip,
        [switch]$NoHtml,
        [switch]$RequireAdministrator
    )

    if ($env:OS -ne 'Windows_NT') {
        throw 'New-FotonBaseline captures a live Windows host.'
    }

    Initialize-FotonSession
    Write-FotonBanner -Kind 'Baseline'

    $psd1 = Join-Path $script:FotonModuleRoot 'Foton.psd1'
    if (Test-Path -LiteralPath $psd1) {
        $man = Import-PowerShellDataFile -LiteralPath $psd1
        $script:FotonSession.Version = [string]$man.ModuleVersion
    }
    elseif (-not $script:FotonSession.Version) {
        $script:FotonSession.Version = '1.25.0'
    }

    $script:FotonSession.IsElevated = Test-FotonElevated
    $capturedUtc = (Get-Date).ToUniversalTime()
    $script:FotonSession.StartTimeUtc = $capturedUtc

    if ($RequireAdministrator -and -not $script:FotonSession.IsElevated) {
        Write-Host '  [x] -RequireAdministrator was set, but this process is not elevated.' -ForegroundColor Red
        return
    }

    $schema = Get-FotonBaselineSchemaVersion
    $providersMeta = @()
    $records = [ordered]@{}
    $coverage = New-Object System.Collections.ArrayList

    foreach ($p in $script:FotonBaselineProviders) {
        $providersMeta += [PSCustomObject]@{
            RecordType     = $p.RecordType
            IdentityFields = @($p.IdentityFields)
            ComparedFields = @($p.ComparedFields)
            FalsePositives = $p.FalsePositives
        }
        $got = @()
        $status = 'Success'
        $errMsg = ''
        try {
            $got = @(& $p.Collect)
        }
        catch {
            $status = 'Error'
            $errMsg = $_.Exception.Message
            Write-FotonStatus ("Baseline provider $($p.RecordType) failed: $errMsg") 'Warn'
        }
        $records[$p.RecordType] = @($got)
        $null = $coverage.Add([PSCustomObject]@{
                RecordType = $p.RecordType
                Status     = $status
                Count      = @($got).Count
                Error      = $errMsg
            })
    }

    $recordsJson = $records | ConvertTo-Json -Depth 8 -Compress
    $sha = [BitConverter]::ToString(
        [System.Security.Cryptography.SHA256]::Create().ComputeHash(
            [Text.Encoding]::UTF8.GetBytes($recordsJson)
        )
    ).Replace('-', '')

    $doc = [ordered]@{
        Header    = [ordered]@{
            BaselineSchemaVersion = $schema
            ToolVersion           = $script:FotonSession.Version
            Hostname              = $env:COMPUTERNAME
            CapturedUtc           = $capturedUtc.ToString('yyyy-MM-dd HH:mm:ss')
            Elevated              = [bool]$script:FotonSession.IsElevated
            PayloadSha256         = $sha
            Note                  = 'Header timestamps are not part of the compared payload hash. Diff proves change between observations, not attribution. A baseline taken after an incident is a picture of that state.'
        }
        Providers = $providersMeta
        Records   = $records
    }

    $counts = [ordered]@{}
    foreach ($k in $records.Keys) { $counts[$k] = @($records[$k]).Count }

    $jsonPath = $null
    $packageRoot = $null
    $zipPath = $null
    $zipHash = $null

    if ($PSCmdlet.ParameterSetName -eq 'Json') {
        $dir = Split-Path $Path -Parent
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }
        ($doc | ConvertTo-Json -Depth 8) | Out-File -FilePath $Path -Encoding utf8
        $jsonPath = (Resolve-Path -LiteralPath $Path).Path
        if (-not $NoHtml) {
            New-FotonBaselineReport -Path $jsonPath | Out-Null
        }
    }
    else {
        if (-not (Test-Path -LiteralPath $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }
        $stamp = $capturedUtc.ToString('yyyyMMdd-HHmmss')
        $folderName = "FotonBaseline_{0}_{1}Z" -f $env:COMPUTERNAME, $stamp
        $packageRoot = Join-Path $OutputPath $folderName
        New-Item -Path $packageRoot -ItemType Directory -Force | Out-Null
        $script:FotonSession.CaseRoot = $packageRoot
        $script:FotonSession.Dirs['Collection'] = $packageRoot
        $script:FotonSession.LogFile = Join-Path $packageRoot 'baseline.log'
        "Foton $($script:FotonSession.Version) baseline capture log" | Out-File -FilePath $script:FotonSession.LogFile -Encoding UTF8

        $jsonPath = Join-Path $packageRoot 'baseline.json'
        ($doc | ConvertTo-Json -Depth 8) | Out-File -FilePath $jsonPath -Encoding utf8

        $covDoc = [ordered]@{
            Elevated              = [bool]$script:FotonSession.IsElevated
            BaselineSchemaVersion = $schema
            ToolVersion           = $script:FotonSession.Version
            CapturedUtc           = $doc.Header.CapturedUtc
            Providers             = @($coverage)
        }
        ($covDoc | ConvertTo-Json -Depth 6) | Out-File -FilePath (Join-Path $packageRoot 'coverage.json') -Encoding utf8

        if (-not $NoHtml) {
            New-FotonBaselineReport -Path $packageRoot | Out-Null
        }

        Write-FotonArtifactHashes | Out-Null

        if (-not $NoZip) {
            $zipPath = Compress-FotonCasePackage
            if ($zipPath -and (Test-Path -LiteralPath $zipPath)) {
                try {
                    $zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
                    $stampLines = @(
                        "Foton baseline package integrity record"
                        "Folder   : $packageRoot"
                        "ZIP      : $zipPath"
                        "SHA-256  : $zipHash"
                        "UTC      : $($capturedUtc.ToString('yyyy-MM-dd HH:mm:ss'))"
                    )
                    $stampLines | Out-File -FilePath ($packageRoot + '_PACKAGE_HASH.txt') -Encoding UTF8
                    Write-FotonStatus ("Package SHA-256: {0}" -f $zipHash) 'Good'
                }
                catch { }
            }
        }

        Write-Host ''
        Write-Host "   Baseline folder : $packageRoot" -ForegroundColor White
        Write-Host "   Snapshot JSON   : $jsonPath" -ForegroundColor White
        if (-not $NoHtml) {
            Write-Host "   Snapshot HTML   : $(Join-Path $packageRoot 'Foton_Baseline.html')" -ForegroundColor White
        }
        if ($zipPath) {
            Write-Host "   Package         : $zipPath" -ForegroundColor White
        }
        Write-Host '   Open Foton_Baseline.html from inside the folder. Compare uses baseline.json.' -ForegroundColor DarkGray
        Write-Host ''
    }

    [PSCustomObject]@{
        Path           = $jsonPath
        PackageRoot    = $packageRoot
        ZipPath        = $zipPath
        PackageSha256  = $zipHash
        PayloadSha256  = $sha
        SchemaVersion  = $schema
        RecordCounts   = [PSCustomObject]$counts
    }
}
