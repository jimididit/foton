function Test-FotonMessageNamesCollector {
    <#
        True when text names a Foton cmdlet (Verb-FotonNoun) or FotonSession.

        Used to attribute hunt/script-block noise to the collector. A bare
        "Foton" substring is too weak - paths like C:\Cases\Foton_HOST_... and
        attacker-chosen comments would suppress High findings.
    #>
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    # Approved-verb style exports and private helpers all use *-Foton*
    if ($Text -match '(?i)\b[A-Za-z]+-Foton[A-Za-z0-9]*\b') { return $true }
    if ($Text -match '(?i)\bFotonSession\b') { return $true }
    return $false
}

function Test-FotonCollectorAttributedEvent {
    <#
        True when an event is attributed to the Foton collector rather than the host.

        Same signals as Hayabusa footprint exclusion: timestamp inside the collection
        window from collection.log, or the message naming a Foton function (earlier
        run outside the window). Callers must treat $false as "not attributed", not
        as proof of host malice.
    #>
    param(
        [string]$TimeCreatedUtc,
        [string]$Message,
        $Window
    )

    if (Test-FotonMessageNamesCollector -Text $Message) {
        return $true
    }

    if (-not $Window -or [string]::IsNullOrWhiteSpace($TimeCreatedUtc)) { return $false }

    try {
        $ts = [datetime]::MinValue
        $ok = [datetime]::TryParse(
            $TimeCreatedUtc,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal,
            [ref]$ts)
        if (-not $ok) { return $false }
        $dto = [datetimeoffset]::new($ts, [timespan]::Zero)
        return ($dto -ge $Window.StartUtc -and $dto -le $Window.EndUtc)
    }
    catch { return $false }
}
