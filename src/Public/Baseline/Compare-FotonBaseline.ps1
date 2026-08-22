function Compare-FotonBaseline {
    <#
    .SYNOPSIS
        Field-level diff of two Foton baseline JSON files (offline).

    .DESCRIPTION
        Refuses to diff if BaselineSchemaVersion does not match. Emits change
        records and Add-FotonFinding rows (Tier 1 for the fact of change).
        Temporal (same hostname) vs fleet (host vs golden) only changes wording.

    .PARAMETER ReferencePath
        Older / golden baseline.

    .PARAMETER DifferencePath
        Newer / candidate baseline.

    .EXAMPLE
        Compare-FotonBaseline -ReferencePath D:\Baselines\web01-day0.json -DifferencePath D:\Baselines\web01-day30.json

        Temporal diff. New Administrators members are High attention, not proof of compromise.

    .OUTPUTS
        Change records (RecordType, Identity, ChangeType, Field, OldValue, NewValue).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ReferencePath,
        [Parameter(Mandatory)][string]$DifferencePath
    )

    $ref = Get-Content -LiteralPath $ReferencePath -Raw | ConvertFrom-Json
    $dif = Get-Content -LiteralPath $DifferencePath -Raw | ConvertFrom-Json

    $sv = $ref.Header.BaselineSchemaVersion
    if ($sv -ne $dif.Header.BaselineSchemaVersion) {
        throw ("Baseline schema mismatch: reference {0} vs difference {1}. Refuse to diff." -f $sv, $dif.Header.BaselineSchemaVersion)
    }

    $mode = 'Fleet'
    if ($ref.Header.Hostname -eq $dif.Header.Hostname) { $mode = 'Temporal' }

    if ($null -eq $script:FotonSession) { Initialize-FotonSession }
    $script:FotonSession.Findings = New-Object System.Collections.ArrayList

    $provByType = @{}
    foreach ($p in @($ref.Providers)) { $provByType[$p.RecordType] = $p }

    $changes = @()
    $types = @($ref.Records.PSObject.Properties.Name)
    foreach ($t in @($dif.Records.PSObject.Properties.Name)) {
        if ($types -notcontains $t) { $types += $t }
    }

    foreach ($type in ($types | Sort-Object)) {
        $meta = $provByType[$type]
        if (-not $meta) {
            $meta = [PSCustomObject]@{ IdentityFields = @('Name'); ComparedFields = @() }
        }
        $idFields = @($meta.IdentityFields)
        $cmpFields = @($meta.ComparedFields)

        $refMap = @{}
        foreach ($r in @($ref.Records.$type)) {
            $refMap[(Get-FotonBaselineIdentity -Record $r -IdentityFields $idFields)] = $r
        }
        $difMap = @{}
        foreach ($r in @($dif.Records.$type)) {
            $difMap[(Get-FotonBaselineIdentity -Record $r -IdentityFields $idFields)] = $r
        }

        foreach ($id in ($difMap.Keys | Sort-Object)) {
            if (-not $refMap.ContainsKey($id)) {
                $changes += [PSCustomObject]@{
                    RecordType = $type; Identity = $id; ChangeType = 'Added'
                    Field = ''; OldValue = ''; NewValue = ''
                }
                continue
            }
            $a = $refMap[$id]; $b = $difMap[$id]
            foreach ($f in $cmpFields) {
                $ov = [string]$a.$f; $nv = [string]$b.$f
                if ($ov -cne $nv) {
                    $changes += [PSCustomObject]@{
                        RecordType = $type; Identity = $id; ChangeType = 'Modified'
                        Field = $f; OldValue = $ov; NewValue = $nv
                    }
                }
            }
        }
        foreach ($id in ($refMap.Keys | Sort-Object)) {
            if (-not $difMap.ContainsKey($id)) {
                $changes += [PSCustomObject]@{
                    RecordType = $type; Identity = $id; ChangeType = 'Removed'
                    Field = ''; OldValue = ''; NewValue = ''
                }
            }
        }
    }

    foreach ($c in $changes) {
        $sev = 'Medium'
        if ($c.RecordType -eq 'InstalledSoftware' -and $c.Field -eq 'DisplayVersion') { $sev = 'Info' }
        if ($c.RecordType -eq 'Service' -and $c.Field -eq 'PathName') { $sev = 'High' }
        if ($c.RecordType -eq 'HardeningRegistry' -and $c.Identity -in @('UseLogonCredential', 'EnableLUA', 'AlwaysInstallElevated')) { $sev = 'High' }
        if ($c.RecordType -eq 'LocalGroupMember' -and $c.ChangeType -eq 'Added' -and $c.Identity -like 'Administrators|*') { $sev = 'High' }
        if ($c.RecordType -eq 'LocalAccount' -and $c.ChangeType -eq 'Added') { $sev = 'Medium' }

        $title = "{0} {1}" -f $c.ChangeType, $c.RecordType
        $obs = "Identity '{0}'." -f $c.Identity
        if ($c.ChangeType -eq 'Modified') {
            $obs = "Identity '{0}' field {1}: '{2}' -> '{3}'." -f $c.Identity, $c.Field, $c.OldValue, $c.NewValue
        }
        Add-FotonFinding -Severity $sev -Category 'Baseline' -Tier 1 -Title $title `
            -Observation $obs `
            -WhyItMatters ("{0} mode ({1} vs {2}). A baseline diff records change between two snapshots. It does not establish when the change occurred, who made it, or that the host is compromised. Software version bumps and GPO are common benign sources." -f `
                $mode, $ref.Header.CapturedUtc, $dif.Header.CapturedUtc) `
            -Artifact (Split-Path $DifferencePath -Leaf) `
            -NextStep 'Confirm against change control or the role golden image. Prefer a provisioning-time reference stored off-host.'
    }

    Write-FotonStatus ("Baseline diff ({0}): {1} change(s), {2} finding(s)" -f $mode, $changes.Count, $script:FotonSession.Findings.Count) 'Good'
    return $changes
}
