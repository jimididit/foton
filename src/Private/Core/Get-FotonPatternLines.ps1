function Get-FotonPatternLines {
    <# One non-comment, non-blank line per entry. Used for heuristic lists, not live-host reads. #>
    param([Parameter(Mandatory)][string]$Path)
    $lines = @()
    if (-not (Test-Path -LiteralPath $Path)) { return $lines }
    $raw = Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue
    foreach ($line in $raw) {
        if (-not $line) { continue }
        $trim = $line.Trim()
        if ($trim -eq '') { continue }
        if ($trim -match '^#') { continue }
        $lines += $trim
    }
    return $lines
}
