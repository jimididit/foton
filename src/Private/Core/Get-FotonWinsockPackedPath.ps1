function Get-FotonWinsockPackedPath {
    <# First WCHAR string in a Winsock PackedCatalogItem blob (LSP DLL path). #>
    param($Bytes)
    if ($null -eq $Bytes) { return '(not set)' }
    $b = $null
    if ($Bytes -is [byte[]]) { $b = $Bytes }
    else { try { $b = [byte[]]$Bytes } catch { return '(not set)' } }
    if ($null -eq $b -or $b.Length -lt 4) { return '(not set)' }
    $n = [Math]::Min(520, $b.Length)
    if (($n % 2) -eq 1) { $n = $n - 1 }
    $s = [Text.Encoding]::Unicode.GetString($b, 0, $n)
    $z = $s.IndexOf([char]0)
    if ($z -ge 0) { $s = $s.Substring(0, $z) }
    $s = $s.Trim()
    if (-not $s) { return '(not set)' }
    return $s
}
