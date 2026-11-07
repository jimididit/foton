function Get-FotonWinsockPackedPath {
    <#
        DLL path from a Winsock PackedCatalogItem blob.
        Current Windows: MAX_PATH ANSI (260 bytes) then WSAPROTOCOL_INFOW.
        Older layout used WCHAR[MAX_PATH]. UTF-16 on ANSI data looks like CJK mojibake.
    #>
    param($Bytes)
    if ($null -eq $Bytes) { return '(not set)' }
    $b = $null
    if ($Bytes -is [byte[]]) { $b = $Bytes }
    else { try { $b = [byte[]]$Bytes } catch { return '(not set)' } }
    if ($null -eq $b -or $b.Length -lt 4) { return '(not set)' }

    $ascii = $true
    $lim = [Math]::Min(260, $b.Length)
    for ($i = 0; $i -lt $lim; $i++) {
        $x = [int]$b[$i]
        if ($x -eq 0) { break }
        if ($x -lt 32 -or $x -gt 126) { $ascii = $false; break }
    }

    if ($ascii) {
        $s = [Text.Encoding]::ASCII.GetString($b, 0, $lim)
    }
    else {
        $n = [Math]::Min(520, $b.Length)
        if (($n % 2) -eq 1) { $n = $n - 1 }
        $s = [Text.Encoding]::Unicode.GetString($b, 0, $n)
    }
    $z = $s.IndexOf([char]0)
    if ($z -ge 0) { $s = $s.Substring(0, $z) }
    $s = $s.Trim()
    if (-not $s) { return '(not set)' }
    return $s
}
