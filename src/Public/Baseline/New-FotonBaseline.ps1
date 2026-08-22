function New-FotonBaseline {
    <#
    .SYNOPSIS
        Capture a normalized snapshot of stable host configuration.

    .DESCRIPTION
        Live capture (WMI/registry). Excludes PIDs, connections, uptime, and sessions.
        Same machine state should serialize to the same compared payload (header
        timestamps are outside the hashed records). Store the file off-host.

        A snapshot taken after intrusion is a picture of that state. Diffs prove
        change between two observations, not when or who.

    .PARAMETER Path
        Output JSON path.

    .EXAMPLE
        New-FotonBaseline -Path D:\Baselines\web01-provision.json

        Capture at provisioning. Hash and store off the endpoint.

    .OUTPUTS
        PSCustomObject (Path, PayloadSha256, RecordCounts)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if ($env:OS -ne 'Windows_NT') {
        throw 'New-FotonBaseline captures a live Windows host.'
    }

    Initialize-FotonSession
    $psd1 = Join-Path $script:FotonModuleRoot 'Foton.psd1'
    $man = Import-PowerShellDataFile -LiteralPath $psd1
    $script:FotonSession.Version = [string]$man.ModuleVersion

    $schema = Get-FotonBaselineSchemaVersion
    $providersMeta = @()
    $records = [ordered]@{}

    foreach ($p in $script:FotonBaselineProviders) {
        $providersMeta += [PSCustomObject]@{
            RecordType     = $p.RecordType
            IdentityFields = @($p.IdentityFields)
            ComparedFields = @($p.ComparedFields)
            FalsePositives = $p.FalsePositives
        }
        $got = @()
        try {
            $got = @(& $p.Collect)
        }
        catch {
            Write-FotonStatus ("Baseline provider $($p.RecordType) failed: $($_.Exception.Message)") 'Warn'
        }
        $records[$p.RecordType] = @($got)
    }

    $recordsJson = $records | ConvertTo-Json -Depth 8 -Compress
    $sha = [BitConverter]::ToString(
        [System.Security.Cryptography.SHA256]::Create().ComputeHash(
            [Text.Encoding]::UTF8.GetBytes($recordsJson)
        )
    ).Replace('-', '')

    $doc = [ordered]@{
        Header = [ordered]@{
            BaselineSchemaVersion = $schema
            ToolVersion           = $script:FotonSession.Version
            Hostname              = $env:COMPUTERNAME
            CapturedUtc           = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
            Elevated              = [bool](Test-FotonElevated)
            PayloadSha256         = $sha
            Note                  = 'Header timestamps are not part of the compared payload hash. Diff proves change between observations, not attribution.'
        }
        Providers = $providersMeta
        Records   = $records
    }

    $dir = Split-Path $Path -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }
    ($doc | ConvertTo-Json -Depth 8) | Out-File -FilePath $Path -Encoding utf8

    $counts = [ordered]@{}
    foreach ($k in $records.Keys) { $counts[$k] = @($records[$k]).Count }

    [PSCustomObject]@{
        Path           = (Resolve-Path -LiteralPath $Path).Path
        PayloadSha256  = $sha
        SchemaVersion  = $schema
        RecordCounts   = [PSCustomObject]$counts
    }
}
