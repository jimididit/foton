function Register-FotonBaselineProvider {
    <#
        Called from provider files at module load. IdentityFields form the stable key.
        ComparedFields are the only values that produce Modified diffs.
    #>
    param(
        [Parameter(Mandatory)][string]$RecordType,
        [Parameter(Mandatory)]        [string[]]$IdentityFields,
        [string[]]$ComparedFields = @(),
        [Parameter(Mandatory)][scriptblock]$Collect,
        [string]$FalsePositives = ''
    )
    if ($null -eq $script:FotonBaselineProviders) {
        $script:FotonBaselineProviders = New-Object System.Collections.ArrayList
    }
    $null = $script:FotonBaselineProviders.Add([PSCustomObject]@{
            RecordType     = $RecordType
            IdentityFields = @($IdentityFields)
            ComparedFields = @($ComparedFields)
            Collect        = $Collect
            FalsePositives = $FalsePositives
        })
}

function Get-FotonBaselineIdentity {
    param($Record, [string[]]$IdentityFields)
    $parts = @()
    foreach ($f in $IdentityFields) {
        $parts += [string]$Record.$f
    }
    return ($parts -join '|')
}

function Get-FotonBaselineFalsePositives {
    <#
        Provider-documented false-positive notes for a RecordType, or empty.
        Used by Compare and Analyze so findings cite the same FP text as the provider.
    #>
    param([Parameter(Mandatory)][string]$RecordType)
    if ($null -eq $script:FotonBaselineProviders) { return '' }
    $p = @($script:FotonBaselineProviders | Where-Object { $_.RecordType -eq $RecordType } | Select-Object -First 1)
    if ($p.Count -eq 0) { return '' }
    return [string]$p[0].FalsePositives
}

function Get-FotonBaselineSchemaVersion {
    if ($script:FotonEmbeddedBaselineSchema) {
        return [string]$script:FotonEmbeddedBaselineSchema
    }
    $psd1 = Join-Path $script:FotonModuleRoot 'Foton.psd1'
    if ($script:FotonModuleRoot -and (Test-Path -LiteralPath $psd1)) {
        $man = Import-PowerShellDataFile -LiteralPath $psd1
        return [string]$man.PrivateData.Foton.BaselineSchemaVersion
    }
    return '1.14.0'
}
