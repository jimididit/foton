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

    if ($Message -and $Message.IndexOf('Foton', [StringComparison]::OrdinalIgnoreCase) -ge 0) {
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
