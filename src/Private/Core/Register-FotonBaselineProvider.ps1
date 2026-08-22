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

function Get-FotonBaselineSchemaVersion {
    $psd1 = Join-Path $script:FotonModuleRoot 'Foton.psd1'
    $man = Import-PowerShellDataFile -LiteralPath $psd1
    return [string]$man.PrivateData.Foton.BaselineSchemaVersion
}
