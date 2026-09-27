function ConvertFrom-FotonAmcache {
    <#
    .SYNOPSIS
        Parse an Amcache.hve already copied off the host (offline hive bytes).

    .DESCRIPTION
        Pure function over a file path. Does not load the hive into the live
        registry and does not read %SystemRoot%\AppCompat\Programs.

        Win10+ InventoryApplicationFile keys: named values only (path, FileId,
        Name, Publisher, Version, Size, LinkDate as stored). KeyLastWriteUtc is
        the nk FILETIME (key last-write), not proof of execution. LinkDate is
        left as the hive string; it is not converted to UTC.

        Legacy Root\File numeric value IDs are recorded as unsupported rather
        than guessed. Use a dedicated hive tool (for example AmcacheParser) for
        those layouts.

    .PARAMETER Path
        Copied Amcache.hve (or a fixture hive).

    .PARAMETER MaxEntries
        Cap on InventoryApplicationFile rows (default 8000).

    .EXAMPLE
        ConvertFrom-FotonAmcache -Path D:\Cases\CASE-0001\08_Filesystem\amcache\Amcache.hve

    .OUTPUTS
        One or more parse rows.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxEntries = 8000
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Amcache hive not found: $Path"
    }
    $item = Get-Item -LiteralPath $Path
    $bytes = [IO.File]::ReadAllBytes($item.FullName)
    $sha = Get-FotonSha256Hex -LiteralPath $item.FullName

    $row = {
        param($Format, $Supported, $Identity, $Note, $FileId, $Name, $Publisher, $Version, $Size, $LinkDateRaw, $KeyLastWriteUtc, $LowerCaseLongPath)
        [PSCustomObject]@{
            SourcePath         = $item.FullName
            SizeBytes          = $bytes.Length
            SHA256             = $sha
            Format             = $Format
            Supported          = $Supported
            Identity           = $Identity
            FileId             = $FileId
            Name               = $Name
            Publisher          = $Publisher
            Version            = $Version
            Size               = $Size
            LinkDateRaw        = $LinkDateRaw
            KeyLastWriteUtc    = $KeyLastWriteUtc
            LowerCaseLongPath  = $LowerCaseLongPath
            Path               = $LowerCaseLongPath
            Note               = $Note
        }
    }

    if ($bytes.Length -lt 0x1000) {
        return @(
            & $row 'Unsupported-TooSmall' $false '' 'Shorter than a registry hive header. Paths and times were not guessed.' '' '' '' '' '' '' '' ''
        )
    }
    $magic = [Text.Encoding]::ASCII.GetString($bytes, 0, 4)
    if ($magic -ne 'regf') {
        return @(
            & $row 'Unsupported-NotHive' $false '' 'Header is not regf. Wrong Amcache fields would be worse than this record.' '' '' '' '' '' '' '' ''
        )
    }

    $root = Get-FotonRegfRootNk -Bytes $bytes
    if ($null -eq $root) {
        return @(
            & $row 'Unsupported-HiveWalk' $false '' 'regf header present but the root nk was not read. Use a hive tool; times were not guessed.' '' '' '' '' '' '' '' ''
        )
    }

    $inv = Get-FotonRegfFindSubkey -Bytes $bytes -StartNk $root -Name 'InventoryApplicationFile' -MaxDepth 4
    if ($null -eq $inv) {
        $legacy = Get-FotonRegfFindSubkey -Bytes $bytes -StartNk $root -Name 'File' -MaxDepth 3
        if ($null -ne $legacy) {
            $note = 'Amcache Root\File (Win7/8-style) numeric value IDs are not mapped here. Use an Amcache/hive tool. FILETIME fields were not guessed.'
            return @(
                & $row 'Amcache-LegacyFile' $false '' $note '' '' '' '' '' '' '' ''
            )
        }
        $note = 'regf hive has no InventoryApplicationFile key. Absence of parsed rows is not evidence the host never executed software. Use a hive tool if this is a non-Amcache hive.'
        return @(
            & $row 'AmcacheHive' $false '' $note '' '' '' '' '' '' '' ''
        )
    }

    $noteOk = 'InventoryApplicationFile named values. KeyLastWriteUtc is the registry key last-write, not proof of execution. LinkDateRaw is the stored string (often PE compile time), not converted to UTC.'
    $children = @(Get-FotonRegfSubkeys -Bytes $bytes -Nk $inv)
    if ($children.Count -eq 0) {
        return @(
            & $row 'AmcacheHive' $true '' 'InventoryApplicationFile is present but has no file subkeys. That is an empty key, not proof of a clean host.' '' '' '' '' '' '' $inv.KeyLastWriteUtc ''
        )
    }

    $out = @()
    $n = 0
    foreach ($ch in $children) {
        if ($n -ge $MaxEntries) { break }
        $vals = Get-FotonRegfValues -Bytes $bytes -Nk $ch
        $path = ''
        $fileId = ''
        $nm = ''
        $pub = ''
        $ver = ''
        $size = ''
        $link = ''
        if ($vals.ContainsKey('LowerCaseLongPath')) { $path = [string]$vals['LowerCaseLongPath'] }
        if ($vals.ContainsKey('FileId')) { $fileId = [string]$vals['FileId'] }
        if ($vals.ContainsKey('Name')) { $nm = [string]$vals['Name'] }
        if ($vals.ContainsKey('Publisher')) { $pub = [string]$vals['Publisher'] }
        if ($vals.ContainsKey('Version')) { $ver = [string]$vals['Version'] }
        if ($vals.ContainsKey('Size')) { $size = [string]$vals['Size'] }
        if ($vals.ContainsKey('LinkDate')) { $link = [string]$vals['LinkDate'] }
        $id = $path
        if (-not $id) { $id = $nm }
        if (-not $id) { $id = $fileId }
        if (-not $id) { $id = [string]$ch.Name }
        $out += & $row 'AmcacheFile' $true $id $noteOk $fileId $nm $pub $ver $size $link $ch.KeyLastWriteUtc $path
        $n++
    }
    if ($out.Count -eq 0) {
        return @(
            & $row 'AmcacheHive' $false '' 'InventoryApplicationFile children were present but no values were decoded. Use a hive tool; times were not guessed.' '' '' '' '' '' '' '' ''
        )
    }
    return $out
}
