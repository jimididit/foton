function Get-FotonVersion {
    <#
    .SYNOPSIS
        Returns Foton module and schema versions.

    .DESCRIPTION
        Use this to confirm the module imported, and to stamp logs or packages with
        the schema versions this build understands. Compare-FotonBaseline will later
        refuse to diff baselines whose schema version is incompatible with
        BaselineSchemaVersion returned here.

    .EXAMPLE
        Import-Module .\Foton.psd1 -Force
        Get-FotonVersion

        Shows the loaded module version and collect/baseline/findings schema numbers.

    .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    param()

    $psd1 = Join-Path $script:FotonModuleRoot 'Foton.psd1'
    $man  = Import-PowerShellDataFile -LiteralPath $psd1
    $meta = $man.PrivateData.Foton

    [PSCustomObject]@{
        ProductName             = 'Foton'
        ModuleVersion           = [string]$man.ModuleVersion
        CollectSchemaVersion    = [string]$meta.CollectSchemaVersion
        BaselineSchemaVersion   = [string]$meta.BaselineSchemaVersion
        FindingsSchemaVersion   = [string]$meta.FindingsSchemaVersion
        ReferenceCollector      = 'dist/Foton-Collect.ps1 (live triage; standard-user coverage supported)'
        ModuleRoot              = $script:FotonModuleRoot
    }
}
