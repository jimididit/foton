function ConvertFrom-FotonFileTimeUtc {
    <# 8-byte Windows FILETIME at Offset to UTC string, or a sentinel. Do not invent. #>
    param(
        $Bytes,
        [int]$Offset = 0
    )
    if ($null -eq $Bytes) { return '(not set)' }
    $b = $null
    if ($Bytes -is [byte[]]) { $b = $Bytes }
    else {
        try { $b = [byte[]]$Bytes } catch { return '(unparsed)' }
    }
    if ($null -eq $b -or $b.Length -lt ($Offset + 8)) { return '(not set)' }
    try {
        $ticks = [BitConverter]::ToInt64($b, $Offset)
        if ($ticks -le 0) { return '(not set)' }
        return [datetime]::FromFileTimeUtc($ticks).ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
    }
    catch {
        return '(unparsed)'
    }
}
