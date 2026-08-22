function Write-FotonBanner {
    <#
        Console brand only. Not written to collection.log (not evidence).

        Windows mark follows the neofetch / fastfetch Windows 11 flag:
        four solid slash-filled panes, two-space gutter, blank row between
        the upper and lower pair (see dylanaraps/neofetch Windows 11 ascii_data
        and fastfetch src/logo/ascii/windows_11.txt). Backslashes through the
        inner corners are Foton's glass crack, not part of those logos.

        Wordmark is figlet ANSI Shadow. Bump BrandUpdated with credit changes.
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

    $word = @(
        '███████╗ ██████╗ ████████╗ ██████╗ ███╗   ██╗',
        '██╔════╝██╔═══██╗╚══██╔══╝██╔═══██╗████╗  ██║',
        '█████╗  ██║   ██║   ██║   ██║   ██║██╔██╗ ██║',
        '██╔══╝  ██║   ██║   ██║   ██║   ██║██║╚██╗██║',
        '██║     ╚██████╔╝   ██║   ╚██████╔╝██║ ╚████║',
        '╚═╝      ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═══╝',
        '',
        '',
        ''
    )

    # 12-char panes (small fastfetch). Intact fill is all '/'.
    $full = '////////////'
    $rows = @(
        @{ L = $full;           R = $full;           Lc = 'Blue';     Rc = 'Cyan' },
        @{ L = $full;           R = $full;           Lc = 'Blue';     Rc = 'Cyan' },
        @{ L = '//////////\\';  R = $full;           Lc = 'Blue';     Rc = 'Cyan' },
        @{ L = '////////  \\';  R = '\\//////////';  Lc = 'Blue';     Rc = 'Cyan' },
        @{ L = $null;           R = $null;           Lc = '';         Rc = '' },
        @{ L = $full;           R = '\\//////////';  Lc = 'DarkCyan'; Rc = 'Blue' },
        @{ L = $full;           R = '//\\////////';  Lc = 'DarkCyan'; Rc = 'Blue' },
        @{ L = $full;           R = $full;           Lc = 'DarkCyan'; Rc = 'Blue' },
        @{ L = $full;           R = $full;           Lc = 'DarkCyan'; Rc = 'Blue' }
    )

    Write-Host ''
    for ($i = 0; $i -lt $rows.Count; $i++) {
        $row = $rows[$i]
        Write-Host '  ' -NoNewline
        if ($null -eq $row.L) {
            Write-Host ('            ') -NoNewline
            Write-Host '\/' -ForegroundColor Yellow -NoNewline
            Write-Host ('            ') -NoNewline
        }
        else {
            Write-Host $row.L -ForegroundColor $row.Lc -NoNewline
            Write-Host '  ' -NoNewline
            Write-Host $row.R -ForegroundColor $row.Rc -NoNewline
        }
        if ($word[$i]) {
            Write-Host ('  ' + $word[$i]) -ForegroundColor Cyan
        }
        else {
            Write-Host ''
        }
    }
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
