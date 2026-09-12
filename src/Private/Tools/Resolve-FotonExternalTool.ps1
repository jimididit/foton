function Resolve-FotonExternalTool {
    <#
        .SYNOPSIS
        Resolves an external tool executable for compose.

        .DESCRIPTION
        Order (do not change lightly):
        1. Explicit -ToolPath for this tool
        2. Foton tools.json under the tool root (Install-FotonTool)
        3. PATH via Get-Command

        Never mutates PATH. Returns a PSCustomObject with Path, Source, Version,
        RulesVersion, or $null when not found.
    #>
    param(
        [Parameter(Mandatory)][string]$ToolName,
        [Parameter(Mandatory)][string[]]$ExecutableNames,
        [string]$ToolPath,
        [string]$ToolRoot
    )

    if ($ToolPath -and $ToolPath.Trim()) {
        $p = $ToolPath.Trim()
        if (Test-Path -LiteralPath $p) {
            return [PSCustomObject]@{
                Path         = (Get-Item -LiteralPath $p).FullName
                Source       = 'ToolPath'
                Version      = ''
                RulesVersion = ''
            }
        }
    }

    $installed = Get-FotonInstalledTool -Name $ToolName -ToolRoot $ToolRoot
    if ($installed -and $installed.ExecutablePath -and (Test-Path -LiteralPath ([string]$installed.ExecutablePath))) {
        return [PSCustomObject]@{
            Path         = (Get-Item -LiteralPath ([string]$installed.ExecutablePath)).FullName
            Source       = 'Manifest'
            Version      = [string]$installed.Version
            RulesVersion = [string]$installed.RulesVersion
        }
    }

    foreach ($n in $ExecutableNames) {
        $cmd = Get-Command $n -ErrorAction SilentlyContinue
        $src = $null
        if ($cmd -and $cmd.Source) { $src = [string]$cmd.Source }
        elseif ($cmd -and $cmd.Path) { $src = [string]$cmd.Path }
        if ($src -and (Test-Path -LiteralPath $src)) {
            return [PSCustomObject]@{
                Path         = (Get-Item -LiteralPath $src).FullName
                Source       = 'PATH'
                Version      = ''
                RulesVersion = ''
            }
        }
    }

    return $null
}
