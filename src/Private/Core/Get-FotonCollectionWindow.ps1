function Get-FotonCollectionWindow {
    <#
        .SYNOPSIS
        Returns the UTC start and end of the collection recorded in a package.

        .DESCRIPTION
        Analysis needs to know when the collector was running so that events caused
        by Foton itself can be separated from events about the host. Script block
        logging records the collector's own PowerShell, so hunt engines report the
        collection as suspicious scripting activity.

        The window comes from 00_Collection\collection.log, which stamps every line
        "yyyy-MM-dd HH:mm:ss UTC"; the earliest and latest stamps bound the run.
        chain_of_custody.txt supplies the start if the log is unreadable, but it
        records no end, so no window is returned in that case - a start without an
        end cannot bound anything, and guessing a duration would invent evidence.

        Returns $null when the window cannot be established. Callers must treat that
        as "cannot attribute", not as "nothing to attribute".

        .EXAMPLE
        $w = Get-FotonCollectionWindow -CaseRoot $script:FotonSession.CaseRoot
        if ($w) { "Collector ran {0} to {1}" -f $w.StartUtc, $w.EndUtc }

        Bounds the collection so time-based attribution can run.
    #>
    param([string]$CaseRoot)

    if (-not $CaseRoot -or -not (Test-Path -LiteralPath $CaseRoot)) { return $null }

    $log = Join-Path $CaseRoot '00_Collection\collection.log'
    if (-not (Test-Path -LiteralPath $log)) { return $null }

    $min = $null
    $max = $null
    try {
        foreach ($line in (Get-Content -LiteralPath $log -ErrorAction Stop)) {
            $m = [regex]::Match($line, '^(?<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) UTC')
            if (-not $m.Success) { continue }
            $d = [datetime]::MinValue
            if (-not [datetime]::TryParseExact($m.Groups['ts'].Value, 'yyyy-MM-dd HH:mm:ss',
                    [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal,
                    [ref]$d)) {
                continue
            }
            if ($null -eq $min -or $d -lt $min) { $min = $d }
            if ($null -eq $max -or $d -gt $max) { $max = $d }
        }
    }
    catch { }

    if ($null -eq $min -or $null -eq $max) { return $null }

    return [PSCustomObject]@{
        StartUtc = [datetimeoffset]::new($min, [timespan]::Zero)
        EndUtc   = [datetimeoffset]::new($max, [timespan]::Zero)
    }
}
