function Get-FotonToolRoot {
    <#
        .SYNOPSIS
        Default Foton-owned tool install root (not PATH, not inside a case).

        .DESCRIPTION
        %LOCALAPPDATA%\Foton\tools unless -ToolRoot overrides. Tools installed
        here are recorded in tools.json so compose can find them without mutating PATH.
    #>
    param([string]$ToolRoot)

    if ($ToolRoot -and $ToolRoot.Trim()) {
        return [IO.Path]::GetFullPath($ToolRoot.Trim())
    }
    $base = $env:LOCALAPPDATA
    if (-not $base) { $base = Join-Path $env:USERPROFILE 'AppData\Local' }
    return [IO.Path]::GetFullPath((Join-Path $base 'Foton\tools'))
}

function Get-FotonToolManifestPath {
    param([string]$ToolRoot)
    $root = Get-FotonToolRoot -ToolRoot $ToolRoot
    return (Join-Path $root 'tools.json')
}

function Get-FotonInstalledTool {
    <#
        .SYNOPSIS
        Returns one installed tool record from tools.json, or $null.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$ToolRoot
    )

    $manPath = Get-FotonToolManifestPath -ToolRoot $ToolRoot
    if (-not (Test-Path -LiteralPath $manPath)) { return $null }
    try {
        $man = Get-Content -LiteralPath $manPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch { return $null }
    if (-not $man -or -not $man.Installed) { return $null }
    $want = $Name.Trim()
    foreach ($row in @($man.Installed)) {
        if ([string]$row.Name -eq $want) { return $row }
    }
    return $null
}

function Get-FotonInstalledToolList {
    <#
        .SYNOPSIS
        Every tool row in tools.json (pinned installs and registered folders). Empty when none.
    #>
    param([string]$ToolRoot)

    $manPath = Get-FotonToolManifestPath -ToolRoot $ToolRoot
    if (-not (Test-Path -LiteralPath $manPath)) { return @() }
    try {
        $man = Get-Content -LiteralPath $manPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch { return @() }
    if (-not $man -or -not $man.Installed) { return @() }
    return @($man.Installed)
}

function Save-FotonToolManifestEntry {
    <#
        .SYNOPSIS
        Upserts one installed-tool row into tools.json under the tool root.
    #>
    param(
        [Parameter(Mandatory)][string]$ToolRoot,
        [Parameter(Mandatory)][object]$Entry
    )

    $root = Get-FotonToolRoot -ToolRoot $ToolRoot
    New-Item -Path $root -ItemType Directory -Force | Out-Null
    $manPath = Join-Path $root 'tools.json'
    $list = New-Object System.Collections.ArrayList
    if (Test-Path -LiteralPath $manPath) {
        try {
            $existing = Get-Content -LiteralPath $manPath -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($row in @($existing.Installed)) {
                if ([string]$row.Name -ne [string]$Entry.Name) {
                    $null = $list.Add($row)
                }
            }
        }
        catch { }
    }
    $null = $list.Add($Entry)
    $doc = [PSCustomObject]@{
        ToolRoot      = $root
        UpdatedUtc    = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')
        Installed     = @($list)
    }
    ($doc | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $manPath -Encoding UTF8
    return $manPath
}
