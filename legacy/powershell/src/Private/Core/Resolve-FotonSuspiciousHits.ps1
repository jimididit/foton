function Resolve-FotonSuspiciousHits {
    <#
        .SYNOPSIS
        Returns the suspicious-command pattern hits for one collected row.

        .DESCRIPTION
        Suspicious-command matching used to happen inside the collectors, which both
        violated "collectors never interpret" and made the endpoint flatten look like
        an offensive toolkit to AMSI (see build/Build-Standalone.ps1). Collect now
        writes the column empty and preserves only the raw text; the interpretation
        happens here, at analysis time, on the workstation.

        Packages captured before collect schema 1.10.0 carry hits computed on the
        endpoint. Those are trusted as-is so historical cases keep reproducing the
        same findings, rather than being silently re-scored against a newer pattern
        list.

        Returns an empty string when no pattern list is loaded, which is the case
        inside the flatten. Callers must not read that as "clean" - the caller-side
        visibility-gap finding covers it.

        .EXAMPLE
        Resolve-FotonSuspiciousHits -Row $proc -StoredProperty 'SuspiciousCmdHits' -TextProperty 'CommandLine'

        Returns the matched pattern names for a running-process row, computing them
        from CommandLine when the collected column is empty. Do not quote example
        patterns here: this file is flattened into the endpoint collector, and a run
        of such strings is what antivirus blocks.
    #>
    param(
        [Parameter(Mandatory)][object]$Row,
        [Parameter(Mandatory)][string]$StoredProperty,
        [Parameter(Mandatory)][string]$TextProperty
    )

    $stored = ''
    if ($Row.PSObject.Properties[$StoredProperty]) { $stored = [string]$Row.$StoredProperty }
    if ($stored.Trim()) { return $stored }

    $text = ''
    if ($Row.PSObject.Properties[$TextProperty]) { $text = [string]$Row.$TextProperty }
    if (-not $text.Trim()) { return '' }

    return [string](Test-FotonSuspiciousCommand -Text $text)
}
