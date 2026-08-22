function Write-FotonBanner {
    <#
        Console brand only. Not written to collection.log (not evidence).
        ASCII so cmd.exe / PS 5.1 / RMM transcripts do not mojibake.
        Bump BrandUpdated when you change this wordmark or the credit lines.
    #>
    param(
        [ValidateSet('Collect', 'Baseline', 'Analyze', 'Easy', 'Parse', 'Carve', 'Compare')]
        [string]$Kind = 'Collect'
    )

    $ver = '1.4.0'
    if ($script:FotonSession -and $script:FotonSession.Version) {
        $ver = [string]$script:FotonSession.Version
    }
    elseif ($script:FotonModuleRoot) {
        $psd1 = Join-Path $script:FotonModuleRoot 'Foton.psd1'
        if (Test-Path -LiteralPath $psd1) {
            try {
                $man = Import-PowerShellDataFile -LiteralPath $psd1
                $ver = [string]$man.ModuleVersion
            }
            catch { }
        }
    }

    $mode = 'Collect  (live triage on this host)'
    switch ($Kind) {
        'Baseline' { $mode = 'Baseline (stable config snapshot)' }
        'Analyze'  { $mode = 'Analyze  (offline package)' }
        'Easy'     { $mode = 'Foton.cmd wrapper' }
        'Parse'    { $mode = 'Parse    (offline artifacts)' }
        'Carve'    { $mode = 'Carve    (signature scan, Tier 3)' }
        'Compare'  { $mode = 'Compare  (offline baseline diff)' }
    }

    Write-Host ''
    Write-Host '      _____     _' -ForegroundColor Cyan
    Write-Host '     |  ___|__ | |_ ___  _ __' -ForegroundColor Cyan
    Write-Host '     | |_ / _ \| __/ _ \| ''_ \' -ForegroundColor Cyan
    Write-Host '     |  _| (_) | || (_) | | | |' -ForegroundColor Cyan
    Write-Host '     |_|  \___/ \__\___/|_| |_|' -ForegroundColor Cyan
    Write-Host '            >>>>|::|>>>>' -ForegroundColor DarkCyan
    Write-Host ''
    Write-Host '     Windows DFIR / baseline / audit' -ForegroundColor Gray
    Write-Host '     Author      J. Flynn' -ForegroundColor DarkGray
    Write-Host '     Handle      jimididit' -ForegroundColor DarkGray
    Write-Host ("     Version     {0}" -f $ver) -ForegroundColor DarkGray
    Write-Host '     Updated     2026-08-22' -ForegroundColor DarkGray
    Write-Host ("     Mode        {0}" -f $mode) -ForegroundColor Gray
    Write-Host '     Light through the glass.' -ForegroundColor DarkGray
    Write-Host ''
}
