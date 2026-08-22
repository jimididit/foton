function Invoke-FotonIocMatch {
    <#
    .SYNOPSIS
        Match a simple IOC list against an already-loaded package (offline).

    .DESCRIPTION
        Does not query the live host or the network. IOC file: one indicator per
        line. Lines starting with # are comments. Prefixes:
          sha256:<hex>   match any SHA256 / sha256 / Hash property
          text:<string>  case-insensitive substring across string properties

        Hits are Tier 2 observations (lists match admin tools and attacker tools).

    .PARAMETER Path
        Package folder or ZIP (Get-FotonPackage).

    .PARAMETER IocPath
        Text file of indicators.

    .EXAMPLE
        Get-FotonPackage -Path D:\Cases\Foton_HOST_20260101-120000Z
        Invoke-FotonIocMatch -IocPath D:\intel\lab-iocs.txt

    .OUTPUTS
        Match rows.
    #>
    [CmdletBinding()]
    param(
        [string]$Path,
        [Parameter(Mandatory)][string]$IocPath
    )

    if ($Path) {
        Get-FotonPackage -Path $Path | Out-Null
    }
    if ($null -eq $script:FotonSession -or $null -eq $script:FotonSession.Data) {
        throw 'Load a package first (Get-FotonPackage) or pass -Path.'
    }

    $iocs = @()
    foreach ($line in (Get-Content -LiteralPath $IocPath -ErrorAction Stop)) {
        if ($line -match '^\s*$' -or $line -match '^\s*#') { continue }
        $trim = $line.Trim()
        if ($trim -like 'sha256:*') {
            $iocs += [PSCustomObject]@{ Kind = 'sha256'; Value = $trim.Substring(7).Trim().ToUpper() }
        }
        elseif ($trim -like 'text:*') {
            $iocs += [PSCustomObject]@{ Kind = 'text'; Value = $trim.Substring(5).Trim() }
        }
        else {
            $iocs += [PSCustomObject]@{ Kind = 'text'; Value = $trim }
        }
    }

    $hits = @()
    foreach ($key in $script:FotonSession.Data.Keys) {
        foreach ($row in @($script:FotonSession.Data[$key])) {
            if ($null -eq $row) { continue }
            $props = @($row.PSObject.Properties)
            foreach ($ioc in $iocs) {
                foreach ($prop in $props) {
                    $pv = [string]$prop.Value
                    if ([string]::IsNullOrWhiteSpace($pv)) { continue }
                    $matched = $false
                    if ($ioc.Kind -eq 'sha256' -and $prop.Name -match 'SHA256|Hash' -and $pv.ToUpper() -eq $ioc.Value) {
                        $matched = $true
                    }
                    if ($ioc.Kind -eq 'text' -and $pv.ToLower().Contains($ioc.Value.ToLower())) {
                        $matched = $true
                    }
                    if ($matched) {
                        $hits += [PSCustomObject]@{
                            IocKind    = $ioc.Kind
                            IocValue   = $ioc.Value
                            Artifact   = $key
                            Property   = $prop.Name
                            Sample     = $pv
                        }
                    }
                }
            }
        }
    }

    foreach ($h in $hits) {
        Add-FotonFinding -Severity 'Medium' -Category 'Ioc' -Tier 2 `
            -Title ("IOC match ({0})" -f $h.IocKind) `
            -Observation ("Indicator matched {0}.{1}: {2}" -f $h.Artifact, $h.Property, $h.Sample) `
            -WhyItMatters 'IOC lists match strings and hashes, including legitimate software and reused lab indicators. A match is a lead to verify against the cited artifact, not a conclusion.' `
            -Artifact $h.Artifact `
            -NextStep 'Confirm the artifact context (signer, path, time) before treating this as related to an incident.'
    }

    Write-FotonStatus ("IOC matches: {0}" -f $hits.Count) 'Good'
    return $hits
}
