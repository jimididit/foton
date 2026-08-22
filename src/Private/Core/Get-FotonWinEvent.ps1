function Get-FotonWinEvent {
    <# Wraps Get-WinEvent so a missing log or empty result is a status, not a terminating error. #>
    param(
        [string]$LogName,
        [int[]]$EventIds,
        [datetime]$StartTime,
        [int]$MaxEvents
    )
    try {
        $filter = @{ LogName = $LogName; StartTime = $StartTime }
        if ($EventIds -and $EventIds.Count -gt 0) { $filter['Id'] = $EventIds }
        return Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop
    }
    catch {
        return $null
    }
}

function ConvertTo-FotonEventRow {
    param($EventRecord, [string]$LogLabel)
    $msg = ''
    try { $msg = $EventRecord.Message } catch { }
    if ($msg -and $msg.Length -gt 2000) { $msg = $msg.Substring(0, 2000) + '...[truncated]' }
    return [PSCustomObject]@{
        TimeCreatedUtc = $EventRecord.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        Log            = $LogLabel
        EventId        = $EventRecord.Id
        Level          = [string]$EventRecord.LevelDisplayName
        Provider       = $EventRecord.ProviderName
        Computer       = $EventRecord.MachineName
        UserSid        = [string]$EventRecord.UserId
        RecordId       = $EventRecord.RecordId
        Message        = ($msg -replace '\s+', ' ')
    }
}
