function Write-FotonStatus {
    <#
        Console + collection-log line. Write-Host is intentional (this is a console tool).
        Timestamps in the log are UTC. Do not write findings here — status is operational, not evidentiary.
    #>
    param(
        [string]$Message,
        [ValidateSet('Info', 'Good', 'Warn', 'Error', 'Step')]
        [string]$Level = 'Info'
    )
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    switch ($Level) {
        'Step'  { Write-Host "`n[*] $Message" -ForegroundColor Cyan }
        'Good'  { Write-Host "    [+] $Message" -ForegroundColor Green }
        'Warn'  { Write-Host "    [!] $Message" -ForegroundColor Yellow }
        'Error' { Write-Host "    [x] $Message" -ForegroundColor Red }
        default { Write-Host "    [-] $Message" -ForegroundColor Gray }
    }
    if ($script:FotonSession.LogFile) {
        try {
            "$stamp UTC  [$Level] $Message" | Out-File -FilePath $script:FotonSession.LogFile -Append -Encoding UTF8
        }
        catch { }
    }
}
