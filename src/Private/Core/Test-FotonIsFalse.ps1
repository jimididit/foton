function Test-FotonIsFalse {
    <#
        True when a CSV/JSON field means boolean false.

        Import-FotonPackageData coerces "True"/"False" to [bool]. Comparing a
        bool with -eq 'False' is wrong: PowerShell converts the right operand to
        bool, and [bool]'False' is $true (non-empty string), so Enabled=$true
        matched "disabled" firewall findings.
    #>
    param($Value)
    if ($Value -is [bool]) { return -not $Value }
    if ($null -eq $Value) { return $false }
    $s = ([string]$Value).Trim()
    return ($s -eq 'False' -or $s -eq '0' -or $s -eq 'No')
}

function Test-FotonIsTrue {
    <# Companion to Test-FotonIsFalse for Enabled / IsEnabled style fields. #>
    param($Value)
    if ($Value -is [bool]) { return [bool]$Value }
    if ($null -eq $Value) { return $false }
    $s = ([string]$Value).Trim()
    return ($s -eq 'True' -or $s -eq '1' -or $s -eq 'Yes')
}
