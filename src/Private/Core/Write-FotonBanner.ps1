#Requires -Version 5.1
<#
    Cosmetic only. The Windows-pane ASCII mark is parked (commented at
    render time) until it is refined; the FOTON wordmark still prints.

    NOT EVIDENCE. Nothing here reaches collection.log, the manifest, or any
    packaged artifact. Every render path is wrapped so a console, codepage,
    or font problem can never abort a collection run.

    THE MARK
    --------
    The real Windows 11 logo is four SOLID panes in a single blue, split by a
    cross-shaped gutter. It is not hatched. The slash fill in earlier versions
    of this banner came from the neofetch / fastfetch Windows 11 ascii_data,
    where '/' approximates a solid block using only ASCII -- it is a terminal
    compatibility hack, not part of Microsoft's mark.

    So there are two styles:

      Solid   U+2588 FULL BLOCK panes. Faithful to the logo. Default.
      Hatch   '/' panes. The neofetch/fastfetch approximation. Pure ASCII,
              survives a legacy raster-font conhost or a non-UTF-8 codepage.

    Style Auto probes whether the console output encoding can represent
    U+2588 and falls back to Hatch if it cannot. The wordmark is gated the
    same way -- it previously emitted box-drawing glyphs unconditionally,
    which degrades to '?' on a CP437 / CP1252 console.

    Wordmark is figlet ANSI Shadow, with figlet Standard as the ASCII
    fallback. Bump BrandUpdated with credit changes.
#>

# ---------------------------------------------------------------------------
# Console capability
# ---------------------------------------------------------------------------

$script:FotonColorMode = $null
$script:FotonBlockOk   = $null

function Get-FotonColorMode {
    <#
        Returns 'TrueColor', 'Console16', or 'None'.

        PS 5.1 on conhost does not enable ENABLE_VIRTUAL_TERMINAL_PROCESSING
        by default -- PSReadLine turns it on for interactive sessions, so ANSI
        "just works" at a prompt and emits literal escape garbage under
        `powershell.exe -File`, which is how a deployed collector runs. Probe
        and enable rather than assuming either way.

        Note: enabling VT is a process-wide console state change. It is not
        restored, because restoring it would break every subsequent render.
    #>
    [CmdletBinding()]
    param([switch]$Refresh)

    if ($script:FotonColorMode -and -not $Refresh) { return $script:FotonColorMode }

    $mode = 'Console16'

    if ($env:NO_COLOR -or $env:FOTON_NO_COLOR) { $mode = 'None' }
    elseif ($(try { [Console]::IsOutputRedirected } catch { $false })) { $mode = 'None' }

    # ISE has no VT parser; it renders escapes as literal text.
    elseif ($Host.Name -notmatch 'ConsoleHost' -and $PSVersionTable.PSVersion.Major -lt 6) { $mode = 'Console16' }

    elseif ($PSVersionTable.PSVersion.Major -ge 6) { $mode = 'TrueColor' }
    elseif ($env:WT_SESSION -or $env:TERM_PROGRAM -or $env:ConEmuANSI -eq 'ON') { $mode = 'TrueColor' }
    else {
        try {
            if (-not ('Foton.NativeConsole' -as [type])) {
                Add-Type -Namespace 'Foton' -Name 'NativeConsole' -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr GetStdHandle(int nStdHandle);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
'@ -ErrorAction Stop
            }
            $handle = [Foton.NativeConsole]::GetStdHandle(-11)   # STD_OUTPUT_HANDLE
            [uint32]$current = 0
            if ([Foton.NativeConsole]::GetConsoleMode($handle, [ref]$current)) {
                $vt = 0x0004                                     # ENABLE_VIRTUAL_TERMINAL_PROCESSING
                if (($current -band $vt) -eq $vt) { $mode = 'TrueColor' }
                elseif ([Foton.NativeConsole]::SetConsoleMode($handle, ($current -bor $vt))) { $mode = 'TrueColor' }
            }
        }
        catch { $mode = 'Console16' }
    }

    $script:FotonColorMode = $mode
    return $mode
}

function Test-FotonBlockGlyph {
    <#
        Can the console output encoding carry U+2588 and the box-drawing
        range? Round-trips a probe string; a lossy encoding substitutes '?'
        and we detect it.

        This is an ENCODING test, not a font test -- a console using a raster
        font may still show tofu. Callers can force -Style Hatch.
    #>
    [CmdletBinding()]
    param([switch]$Refresh)

    if ($null -ne $script:FotonBlockOk -and -not $Refresh) { return $script:FotonBlockOk }

    $ok = $false
    try {
        $probe    = [string][char]0x2588 + [char]0x2557 + [char]0x2550
        $encoding = [Console]::OutputEncoding
        if ($encoding) {
            $ok = ($encoding.GetString($encoding.GetBytes($probe)) -eq $probe)
        }
    }
    catch { $ok = $false }

    $script:FotonBlockOk = $ok
    return $ok
}

function Get-FotonMix {
    # Linear blend between two RGB triples. $T is clamped 0..1.
    param([int[]]$From, [int[]]$To, [double]$T)
    if ($T -lt 0) { $T = 0 } elseif ($T -gt 1) { $T = 1 }
    return @(
        [int][Math]::Round($From[0] + ($To[0] - $From[0]) * $T)
        [int][Math]::Round($From[1] + ($To[1] - $From[1]) * $T)
        [int][Math]::Round($From[2] + ($To[2] - $From[2]) * $T)
    )
}

# ---------------------------------------------------------------------------
# The mark
# ---------------------------------------------------------------------------
#
# Both styles are a 26 x 9 grid: two 12-wide panes, 2-column gutter, blank row
# between the upper and lower pair. Glyph contract:
#
#   pane char   intact glass      -> blue/cyan gradient
#   \  _  |     fracture line     -> hot core, amber at the extremities
#   (space)     void              -> open glass, or a structural gutter
#
# Three rules keep the fracture readable instead of looking like stray
# punctuation:
#
#   1. Runs must be CONNECTED. In a monospace cell '\' joins bottom-right to
#      the next cell's top-left, so a '\' run has to step exactly +1 column
#      per row. '_' joins horizontally, '|' vertically. Skipping a column
#      leaves a visible break that reads as noise.
#   2. In Hatch, never draw a fracture with '/'. It is the fill character, so
#      a '/' crack is invisible by definition. Secondary hairlines are cut as
#      pure voids instead.
#   3. In Solid the void carries all the continuity, so the amber glyphs are
#      only glints along the break and may be dashed.
#
# Both paths run from a top-left tip, through an impact point at the logo's
# own centre cross, out through the bottom-right corner.

# Solid panes, UTF-8 base64 so this file stays ASCII: PS 5.1 reads a BOM-less
# .ps1 as the system ANSI codepage, and raw block glyphs then parse as garbage
# (Unexpected token).
$script:FotonMarkSolidB64 = @(
    '4paI4paI4paIXOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiCAg4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI'
    '4paI4paI4paI4paIIFzilojilojilojilojilojiloggIOKWiOKWiOKWiOKWiOKWiCDilojilojilojilojilojilog='
    '4paI4paI4paI4paI4paI4paIIFzilojilojilojiloggIOKWiOKWiOKWiCAg4paI4paI4paI4paI4paI4paI4paI'
    '4paI4paI4paI4paI4paI4paI4paI4paIICBc4paIICDiloggIOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiOKWiA=='
    'ICAgICAgICAgICAgXCAgICAgICAgICAgICA='
    '4paI4paI4paI4paI4paI4paI4paI4paI4paIICDiloggICBc4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI'
    '4paI4paI4paI4paI4paI4paI4paIICDilojilojiloggIOKWiOKWiCBc4paI4paI4paI4paI4paI4paI4paI4paI'
    '4paI4paI4paI4paI4paI4paIIOKWiOKWiOKWiOKWiOKWiCAg4paI4paI4paI4paIIFzilojilojilojilojilojilog='
    '4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paI4paIICDilojilojilojilojilojiloggXOKWiOKWiOKWiOKWiA=='
)

# Hatch panes. Pure ASCII, hand-editable.
$script:FotonMarkHatch = @(
    '//\ ////////  //// ///////'
    '///___\ ////  /// ////////'
    '///////\  //  // /////////'
    '////////___\  / //////////'
    '            __\           '
    '///////////   /\  ////////'
    '////////// /  //___\ /////'
    '///////// //  //////\  ///'
    '//////// ///  ///////_____'
)

$script:FotonMarkWidth = 26

# Impact point in (row, column) grid coordinates. The crack gradient and the
# stress halo both key off this, so moving it re-lights the whole mark.
$script:FotonImpact = @(4.0, 12.5)

# Palette.
$script:FotonPaneDark  = @(0x1E, 0x3A, 0x8A)   # indigo, upper left
$script:FotonPaneLite  = @(0x22, 0xD3, 0xEE)   # cyan, lower right
$script:FotonStress    = @(0xE8, 0xF4, 0xFF)   # glass whitening beside a break
$script:FotonCrackCore = @(0xFF, 0xF7, 0xE0)   # at the impact
$script:FotonCrackTip  = @(0xF5, 0x9E, 0x0B)   # amber, at the extremities
$script:FotonWordDark  = @(0x3B, 0x82, 0xF6)
$script:FotonWordLite  = @(0x7D, 0xEF, 0xFF)

function Get-FotonMarkCells {
    <#
        Resolves the mark into per-character colour. Returns one array of cell
        objects per row: @{ Ch = <char>; Rgb = <int[]>; C16 = <string> }.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Solid', 'Hatch')]
        [string]$Style = 'Solid'
    )

    if ($Style -eq 'Solid') {
        $enc  = [Text.Encoding]::UTF8
        $rows = @($script:FotonMarkSolidB64 | ForEach-Object { $enc.GetString([Convert]::FromBase64String($_)) })
        $pane = [char]0x2588
        # A whole brightened cell is a large visual event in Solid, so the
        # stress halo must be far weaker here than in Hatch, or it competes
        # with the fracture and the panes go mushy.
        $offsets = @(
            @{ dR = 0; dC = -1; W = 0.14 }
            @{ dR = 0; dC = 1; W = 0.084 }
        )
    }
    else {
        $rows = $script:FotonMarkHatch
        $pane = '/'
        # Hatch is thin strokes, so it takes a much stronger halo to register.
        # The right-hand side is left alone: the voids baked into the art sit
        # there and already read as the crack's shadow.
        $offsets = @(
            @{ dR = 0; dC = -1; W = 0.42 }
            @{ dR = -1; dC = 0; W = 0.34 }
            @{ dR = 1; dC = 0; W = 0.34 }
            @{ dR = 0; dC = -2; W = 0.18 }
        )
    }

    $width   = $script:FotonMarkWidth
    $height  = $rows.Count
    $impactR = $script:FotonImpact[0]
    $impactC = $script:FotonImpact[1]

    $halo = @{}
    for ($r = 0; $r -lt $height; $r++) {
        $line = $rows[$r].PadRight($width).Substring(0, $width)
        for ($c = 0; $c -lt $width; $c++) {
            $ch = $line[$c]
            if ($ch -eq ' ' -or $ch -eq $pane) { continue }
            foreach ($o in $offsets) {
                $key = '{0},{1}' -f ($r + $o.dR), ($c + $o.dC)
                if (-not $halo.ContainsKey($key)) { $halo[$key] = $o.W }
            }
        }
    }

    $grid = New-Object 'System.Collections.Generic.List[object]'

    for ($r = 0; $r -lt $height; $r++) {
        $line  = $rows[$r].PadRight($width).Substring(0, $width)
        $cells = New-Object 'System.Collections.Generic.List[object]'

        for ($c = 0; $c -lt $width; $c++) {
            $ch = $line[$c]

            if ($ch -eq ' ') {
                $cells.Add([pscustomobject]@{ Ch = ' '; Rgb = $null; C16 = $null })
                continue
            }

            if ($ch -eq $pane) {
                # Diagonal sweep so the four panes read as one sheet of glass.
                $t   = ($c / ($width - 1)) * 0.6 + ($r / ($height - 1)) * 0.4
                $rgb = Get-FotonMix -From $script:FotonPaneDark -To $script:FotonPaneLite -T $t
                $key = '{0},{1}' -f $r, $c
                if ($halo.ContainsKey($key)) {
                    $rgb = Get-FotonMix -From $rgb -To $script:FotonStress -T $halo[$key]
                }
                $c16 = if ($t -lt 0.34) { 'Blue' } elseif ($t -lt 0.68) { 'DarkCyan' } else { 'Cyan' }
                $cells.Add([pscustomobject]@{ Ch = $ch; Rgb = $rgb; C16 = $c16 })
                continue
            }

            # Fracture. Row delta is weighted because cells run roughly 2:1
            # tall, so this stays circular on screen instead of an oval.
            $d   = [Math]::Sqrt(3.2 * [Math]::Pow($r - $impactR, 2) + [Math]::Pow($c - $impactC, 2))
            $t   = [Math]::Min($d / 14.0, 1.0)
            $rgb = Get-FotonMix -From $script:FotonCrackCore -To $script:FotonCrackTip -T $t
            $c16 = if ($d -lt 7) { 'White' } else { 'Yellow' }
            $cells.Add([pscustomobject]@{ Ch = $ch; Rgb = $rgb; C16 = $c16 })
        }

        $grid.Add($cells)
    }

    return $grid
}

function Write-FotonCells {
    <#
        Emits one line. TrueColor builds a single string with run-length
        collapsed SGR sequences; Console16 falls back to -ForegroundColor;
        None drops colour entirely.
    #>
    [CmdletBinding()]
    param(
        [object[]]$Cells,
        [string]$Mode,
        [object[]]$Trailer
    )

    $all = @()
    if ($Cells)   { $all += $Cells }
    if ($Trailer) { $all += $Trailer }

    if ($Mode -eq 'TrueColor') {
        $esc = [char]27
        $sb  = New-Object System.Text.StringBuilder
        $lastKey = ''
        foreach ($cell in $all) {
            if ($null -eq $cell.Rgb) {
                if ($lastKey -ne '') { [void]$sb.Append("$esc[0m"); $lastKey = '' }
                [void]$sb.Append($cell.Ch)
                continue
            }
            $key = '{0};{1};{2}' -f $cell.Rgb[0], $cell.Rgb[1], $cell.Rgb[2]
            if ($key -ne $lastKey) {
                [void]$sb.Append("$esc[38;2;$key`m")
                $lastKey = $key
            }
            [void]$sb.Append($cell.Ch)
        }
        if ($lastKey -ne '') { [void]$sb.Append("$esc[0m") }
        Write-Host $sb.ToString()
        return
    }

    if ($Mode -eq 'None') {
        Write-Host (-join ($all | ForEach-Object { $_.Ch }))
        return
    }

    $buffer  = New-Object System.Text.StringBuilder
    $lastC16 = $null
    foreach ($cell in $all) {
        if ($cell.C16 -ne $lastC16) {
            if ($buffer.Length -gt 0) {
                if ($lastC16) { Write-Host $buffer.ToString() -ForegroundColor $lastC16 -NoNewline }
                else { Write-Host $buffer.ToString() -NoNewline }
                [void]$buffer.Clear()
            }
            $lastC16 = $cell.C16
        }
        [void]$buffer.Append($cell.Ch)
    }
    if ($buffer.Length -gt 0) {
        if ($lastC16) { Write-Host $buffer.ToString() -ForegroundColor $lastC16 -NoNewline }
        else { Write-Host $buffer.ToString() -NoNewline }
    }
    Write-Host ''
}

# ---------------------------------------------------------------------------

function Write-FotonBanner {
    [CmdletBinding()]
    param(
        [ValidateSet('Collect', 'Baseline', 'Analyze', 'Easy', 'Parse', 'Carve', 'Compare')]
        [string]$Kind = 'Collect',

        # Auto = Solid when the console encoding can carry U+2588, else Hatch.
        [ValidateSet('Auto', 'Solid', 'Hatch')]
        [string]$Style = 'Auto',

        [ValidateSet('Auto', 'TrueColor', 'Console16', 'None')]
        [string]$Color = 'Auto'
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

    try {
        $colorMode = if ($Color -eq 'Auto') { Get-FotonColorMode } else { $Color }
        $blockOk   = Test-FotonBlockGlyph
        # $markStyle = if ($Style -eq 'Auto') { if ($blockOk) { 'Solid' } else { 'Hatch' } } else { $Style }

        # Figlet ANSI Shadow "FOTON", UTF-8 base64 so this file stays ASCII.
        $enc = [Text.Encoding]::UTF8
        $wordShadow = @(
            $enc.GetString([Convert]::FromBase64String('4paI4paI4paI4paI4paI4paI4paI4pWXIOKWiOKWiOKWiOKWiOKWiOKWiOKVlyDilojilojilojilojilojilojilojilojilZcg4paI4paI4paI4paI4paI4paI4pWXIOKWiOKWiOKWiOKVlyAgIOKWiOKWiOKVlw=='))
            $enc.GetString([Convert]::FromBase64String('4paI4paI4pWU4pWQ4pWQ4pWQ4pWQ4pWd4paI4paI4pWU4pWQ4pWQ4pWQ4paI4paI4pWX4pWa4pWQ4pWQ4paI4paI4pWU4pWQ4pWQ4pWd4paI4paI4pWU4pWQ4pWQ4pWQ4paI4paI4pWX4paI4paI4paI4paI4pWXICDilojilojilZE='))
            $enc.GetString([Convert]::FromBase64String('4paI4paI4paI4paI4paI4pWXICDilojilojilZEgICDilojilojilZEgICDilojilojilZEgICDilojilojilZEgICDilojilojilZHilojilojilZTilojilojilZcg4paI4paI4pWR'))
            $enc.GetString([Convert]::FromBase64String('4paI4paI4pWU4pWQ4pWQ4pWdICDilojilojilZEgICDilojilojilZEgICDilojilojilZEgICDilojilojilZEgICDilojilojilZHilojilojilZHilZrilojilojilZfilojilojilZE='))
            $enc.GetString([Convert]::FromBase64String('4paI4paI4pWRICAgICDilZrilojilojilojilojilojilojilZTilZ0gICDilojilojilZEgICDilZrilojilojilojilojilojilojilZTilZ3ilojilojilZEg4pWa4paI4paI4paI4paI4pWR'))
            $enc.GetString([Convert]::FromBase64String('4pWa4pWQ4pWdICAgICAg4pWa4pWQ4pWQ4pWQ4pWQ4pWQ4pWdICAgIOKVmuKVkOKVnSAgICDilZrilZDilZDilZDilZDilZDilZ0g4pWa4pWQ4pWdICDilZrilZDilZDilZDilZ0='))
            ''
            ''
            ''
        )

        # Figlet Standard. Pure ASCII, for consoles that cannot carry the
        # box-drawing range.
        $wordAscii = @(
            ' _____ ___ _____ ___  _   _ '
            '|  ___/ _ \_   _/ _ \| \ | |'
            '| |_ | | | || || | | |  \| |'
            '|  _|| |_| || || |_| | |\  |'
            '|_|   \___/ |_| \___/|_| \_|'
            ''
            ''
            ''
            ''
        )

        $word      = if ($blockOk) { $wordShadow } else { $wordAscii }
        $wordWidth = ($word | Measure-Object -Property Length -Maximum).Maximum
        if (-not $wordWidth) { $wordWidth = 1 }

        $gap = [pscustomobject]@{ Ch = ' '; Rgb = $null; C16 = $null }

        Write-Host ''
        foreach ($text in $word) {
            if (-not $text) { continue }
            $cells = @($gap) * 2
            for ($k = 0; $k -lt $text.Length; $k++) {
                if ($text[$k] -eq ' ') { $cells += $gap; continue }
                $t = if ($wordWidth -gt 1) { $k / ($wordWidth - 1) } else { 0 }
                $cells += [pscustomobject]@{
                    Ch  = $text[$k]
                    Rgb = (Get-FotonMix -From $script:FotonWordDark -To $script:FotonWordLite -T $t)
                    C16 = $(if ($t -lt 0.5) { 'Blue' } else { 'Cyan' })
                }
            }
            Write-FotonCells -Cells $cells -Mode $colorMode
        }

        # Windows-pane mark parked until the crack/logo is refined.
        # $grid = Get-FotonMarkCells -Style $markStyle
        # Write-Host ''
        # foreach ($row in $grid) {
        #     Write-FotonCells -Cells (@($gap) * 2 + $row) -Mode $colorMode
        # }
    }
    catch {
        # Cosmetics must never take down a run.
        Write-Verbose ("Banner render failed, using plain fallback: {0}" -f $_.Exception.Message)
        Write-Host ''
        Write-Host '  FOTON'
        Write-Host ''
        # foreach ($line in $script:FotonMarkHatch) { Write-Host ('  ' + $line) }
    }

    Write-Host ''
    Write-Host '     Windows DFIR / baseline / audit' -ForegroundColor Gray
    Write-Host '     Author      jimididit' -ForegroundColor DarkGray
    Write-Host ("     Version     {0}" -f $ver) -ForegroundColor DarkGray
    Write-Host '     Updated     08-22-2026' -ForegroundColor DarkGray
    Write-Host ("     Mode        {0}" -f $mode) -ForegroundColor Gray
    Write-Host '     See through the panes' -ForegroundColor DarkGray
    Write-Host ''
}