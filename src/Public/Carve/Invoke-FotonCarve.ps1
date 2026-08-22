function Invoke-FotonCarve {
    <#
    .SYNOPSIS
        Signature scan a blob for MZ/PE headers (Tier 3). Not NTFS unallocated carving.

    .DESCRIPTION
        Walks a file you already copied (image fragment, unallocated dump, or sample).
        Records MZ hits and, when e_lfanew points at 'PE\0\0', labels them PE.
        Does not recover filenames or MAC times. Full NTFS FILE-record carving is
        not implemented — see docs/CARVE.md.

        Caps: -MaxBytes (default 8 MiB) and -MaxHits (default 50) so a huge blob
        cannot hang the analyst box.

    .PARAMETER Path
        Blob or file to scan.

    .PARAMETER MaxBytes
        Stop reading after this many bytes.

    .PARAMETER MaxHits
        Stop after this many MZ signatures.

    .EXAMPLE
        Invoke-FotonCarve -Path D:\evidence\unalloc-sample.bin

    .OUTPUTS
        Carve hit records (Offset, Kind, SHA256 of a 64-byte window).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxBytes = 8388608,
        [int]$MaxHits = 50
    )

    if ($null -eq $script:FotonSession) { Initialize-FotonSession }

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Carve input not found: $Path"
    }
    $item = Get-Item -LiteralPath $Path
    $len = [int][Math]::Min($item.Length, $MaxBytes)
    $fs = [IO.File]::OpenRead($item.FullName)
    try {
        $buf = New-Object byte[] $len
        $read = $fs.Read($buf, 0, $len)
    }
    finally {
        $fs.Close()
    }
    if ($read -lt $len) { $len = $read }

    $hits = @()
    $i = 0
    while ($i -lt ($len - 1) -and $hits.Count -lt $MaxHits) {
        if ($buf[$i] -eq 0x4D -and $buf[$i + 1] -eq 0x5A) {
            $kind = 'MZ'
            if (($i + 0x40) -le $len) {
                $peOff = [BitConverter]::ToInt32($buf, $i + 0x3C)
                $abs = $i + $peOff
                if ($peOff -ge 0 -and ($abs + 4) -le $len -and
                    $buf[$abs] -eq 0x50 -and $buf[$abs + 1] -eq 0x45 -and
                    $buf[$abs + 2] -eq 0 -and $buf[$abs + 3] -eq 0) {
                    $kind = 'PE'
                }
            }
            $winLen = [Math]::Min(64, $len - $i)
            $window = New-Object byte[] $winLen
            [Array]::Copy($buf, $i, $window, 0, $winLen)
            $sha = [BitConverter]::ToString(
                [System.Security.Cryptography.SHA256]::Create().ComputeHash($window)
            ).Replace('-', '')
            $hits += [PSCustomObject]@{
                SourcePath = $item.FullName
                Offset     = $i
                Kind       = $kind
                WindowSha256 = $sha
                Note       = 'Signature hit only. No path or timestamp. Tier 3 until a collected file hash or Prefetch/LNK name corroborates it.'
            }
        }
        $i++
    }

    foreach ($h in $hits) {
        Add-FotonFinding -Severity 'Info' -Category 'Carve' -Tier 3 `
            -Title ("Carved {0} header at offset {1}" -f $h.Kind, $h.Offset) `
            -Observation ("{0} magic at byte {1} in {2}." -f $h.Kind, $h.Offset, $item.Name) `
            -WhyItMatters 'Unallocated or blob scans find remnants and also find packed installers, memory dumps, and coincidence. This is not evidence the file executed. Corroborate with a package artifact hash or parser output before promoting the finding.' `
            -Artifact $item.Name `
            -NextStep 'Hash-match the window or surrounding bytes against collected executables. Do not treat offset-only hits as a timeline.'
    }

    Write-FotonStatus ("Carve signature hits: {0} (scanned {1} bytes, NTFS unallocated parser not used)" -f $hits.Count, $len) 'Good'
    return $hits
}
