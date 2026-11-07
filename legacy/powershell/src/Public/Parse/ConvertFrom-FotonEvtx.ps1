function ConvertFrom-FotonEvtx {
    <#
    .SYNOPSIS
        Parse an EVTX file already copied into a case package (offline).

    .DESCRIPTION
        Pure function over a file path. Does not query live logs. Reads ElfFile
        exports (typically 07_Event_Logs/evtx). Emits one row per selected Event ID
        (same ID set Collect queries), newest first, capped. Other IDs in the file
        are ignored rather than dumped. Does not invent messages when Get-WinEvent fails.

    .PARAMETER Path
        Exported .evtx file.

    .PARAMETER MaxEvents
        Cap per file after ID filter (default 500).

    .EXAMPLE
        ConvertFrom-FotonEvtx -Path D:\Cases\CASE-0001\07_Event_Logs\evtx\Security.evtx

    .OUTPUTS
        One unsupported record, or one record per selected event.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxEvents = 500
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "EVTX file not found: $Path"
    }
    $item = Get-Item -LiteralPath $Path
    $sha = Get-FotonSha256Hex -LiteralPath $item.FullName
    $len = $item.Length
    $base = [PSCustomObject]@{
        SourcePath     = $item.FullName
        SizeBytes      = $len
        SHA256         = $sha
        Format         = 'Unknown'
        Supported      = $false
        EventId        = ''
        RecordId       = ''
        TimeCreatedUtc = ''
        Provider       = ''
        Identity       = ''
        Note           = ''
    }
    if ($len -lt 8) {
        $base.Format = 'Unsupported-TooSmall'
        $base.Note = 'Shorter than an ElfFile header. Do not invent Event IDs.'
        return $base
    }
    $fs = [IO.File]::Open($item.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $hdr = New-Object byte[] 8
        $null = $fs.Read($hdr, 0, 8)
    }
    finally { $fs.Close() }
    $magic = [Text.Encoding]::ASCII.GetString($hdr, 0, 7)
    if ($magic -ne 'ElfFile') {
        $base.Format = 'Unsupported-NotEvtx'
        $base.Note = 'Header is not ElfFile. Wrong Event IDs would be worse than this record.'
        return $base
    }

    $ids = Get-FotonSelectedEvtxIds
    $events = $null
    try {
        $filter = @{ Path = $item.FullName; Id = $ids }
        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop)
    }
    catch {
        $events = @()
    }

    if ($events.Count -eq 0) {
        $base.Format = 'EVTX'
        $base.Supported = $true
        $base.Note = 'ElfFile opened. No selected-ID events within the cap. Other Event IDs in this file were not dumped. Absence here is a filter, not an empty log.'
        return $base
    }

    $out = @()
    foreach ($e in $events) {
        $msg = ''
        try { $msg = [string]$e.Message } catch { }
        if ($msg.Length -gt 500) { $msg = $msg.Substring(0, 500) + '...[truncated]' }
        $msg = ($msg -replace '\s+', ' ')
        $t = ''
        if ($e.TimeCreated) {
            $t = $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
        }
        $eid = [string]$e.Id
        $rid = [string]$e.RecordId
        $out += [PSCustomObject]@{
            SourcePath     = $item.FullName
            SizeBytes      = $len
            SHA256         = $sha
            Format         = 'EVTX'
            Supported      = $true
            EventId        = $eid
            RecordId       = $rid
            TimeCreatedUtc = $t
            Provider       = [string]$e.ProviderName
            Identity       = ($eid + '|' + $rid)
            Note           = $msg
        }
    }
    return $out
}

function Get-FotonSelectedEvtxIds {
    <# Event IDs Collect already queries. Parser ignores other IDs in the EVTX. #>
    $raw = @(
        1, 3, 4, 6, 7, 8, 10, 11, 12, 13, 15, 21, 22, 23, 24, 25, 39, 40, 41,
        59, 60, 104, 106, 129, 140, 141, 200, 201, 219, 400, 403, 600, 800,
        1000, 1001, 1002, 1006, 1007, 1008, 1009, 1015, 1074,
        1116, 1117, 1118, 1119, 1148, 1149, 2003, 2004, 2005, 2006, 2033,
        4103, 4104, 4624, 4625, 4634, 4647, 4648, 4656, 4663, 4672,
        4688, 4689, 4697, 4698, 4699, 4700, 4701, 4702, 4719,
        4720, 4722, 4723, 4724, 4725, 4726, 4727, 4728, 4729,
        4732, 4733, 4738, 4739, 4740, 4756, 4757, 4767, 4768, 4769, 4771, 4776, 4778, 4779, 4781,
        4907, 4912, 5001, 5004, 5007, 5010, 5012, 5140, 5142, 5143, 5144, 5145,
        53504, 5857, 5858, 5859, 5860, 5861, 6005, 6006, 6008, 6013,
        7031, 7034, 7036, 7040, 7045
    )
    return @($raw | Sort-Object -Unique)
}
