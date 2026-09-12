function Invoke-FotonExternalParse {
    <#
    .SYNOPSIS
        If EZ Tools / Hayabusa / Chainsaw are available, run them on copied package files.

    .DESCRIPTION
        Offline workstation compose. Does not download tools and does not read the live host.
        Native ConvertFrom-Foton* remains the no-dependency fallback (Invoke-FotonParse).

        Resolution order per tool: -ToolPath override, then Foton tools.json (Install-FotonTool),
        then PATH. Never mutates PATH.

        When a tool is present, stdout/CSV lands under analysis/external/<tool>/ and is hashed.
        Missing tools are recorded as Info coverage rows, not parse failures.
        Hayabusa/Chainsaw hits are facts from those engines (Tier 2 unless they only
        report an Event ID / hash match). Name the tool in Artifact.

    .PARAMETER PackagePath
        Case folder or ZIP. If omitted, uses the session CaseRoot from Get-FotonPackage.

    .PARAMETER Path
        Same as PackagePath (Easy wrapper).

    .PARAMETER ToolRoot
        Foton tool install root (default %LOCALAPPDATA%\Foton\tools).

    .PARAMETER ToolPath
        Optional hashtable of ToolName -> executable path overrides.

    .EXAMPLE
        Get-FotonPackage -Path D:\Cases\Foton_HOSTNAME_20260823-011150Z
        Invoke-FotonExternalParse

        Runs PECmd/LECmd/JLECmd/EvtxECmd/AmcacheParser/RECmd/hayabusa/chainsaw if found.

    .OUTPUTS
        Inventory rows (Tool, Status, DestRelative, SHA256, Version, RulesVersion, Note).
    #>
    [CmdletBinding()]
    param(
        [string]$PackagePath,
        [string]$Path,
        [string]$ToolRoot,
        [hashtable]$ToolPath
    )

    if ($null -eq $script:FotonSession) { Initialize-FotonSession }
    $pkg = $PackagePath
    if (-not $pkg) { $pkg = $Path }
    if ($pkg) {
        Get-FotonPackage -Path $pkg | Out-Null
    }
    $root = $script:FotonSession.CaseRoot
    if (-not $root -or -not (Test-Path -LiteralPath $root)) {
        throw 'No package loaded. Pass -PackagePath or call Get-FotonPackage first.'
    }

    $extRoot = Join-Path $root 'analysis\external'
    New-Item -Path $extRoot -ItemType Directory -Force | Out-Null

    if (-not $ToolPath) { $ToolPath = @{} }

    $prefetch = Join-Path $root (Join-Path $script:FotonSession.Categories['Filesystem'] 'prefetch')
    $lnk = Join-Path $root (Join-Path $script:FotonSession.Categories['Filesystem'] 'lnk_jumplist')
    $evtx = Join-Path $root (Join-Path $script:FotonSession.Categories['EventLogs'] 'evtx')
    $am = Join-Path $root (Join-Path $script:FotonSession.Categories['Filesystem'] 'amcache')
    $hives = Join-Path $root (Join-Path $script:FotonSession.Categories['Filesystem'] 'hives')

    $jobs = @(
        @{ Tool = 'PECmd'; Names = @('PECmd.exe', 'PECmd'); NeedDir = $prefetch; Args = { param($exe, $in, $out) @('-d', $in, '--csv', $out, '--csvf', 'pecmd.csv') } }
        @{ Tool = 'LECmd'; Names = @('LECmd.exe', 'LECmd'); NeedDir = $lnk; Args = { param($exe, $in, $out) @('-d', $in, '--csv', $out, '--csvf', 'lecmd.csv') } }
        @{ Tool = 'JLECmd'; Names = @('JLECmd.exe', 'JLECmd'); NeedDir = $lnk; Args = { param($exe, $in, $out) @('-d', $in, '--csv', $out, '--csvf', 'jlecmd.csv') } }
        @{ Tool = 'EvtxECmd'; Names = @('EvtxECmd.exe', 'EvtxECmd'); NeedDir = $evtx; Args = { param($exe, $in, $out) @('-d', $in, '--csv', $out, '--csvf', 'evtxecmd.csv') } }
        @{ Tool = 'AmcacheParser'; Names = @('AmcacheParser.exe', 'AmcacheParser'); NeedDir = $am; Args = { param($exe, $in, $out)
                $hve = Join-Path $in 'Amcache.hve'
                @('-f', $hve, '--csv', $out, '--csvf', 'amcacheparser.csv')
            } }
        @{ Tool = 'RECmd'; Names = @('RECmd.exe', 'RECmd'); NeedDir = $hives; Args = { param($exe, $in, $out) @('-d', $in, '--csv', $out, '--csvf', 'recmd.csv') } }
        @{ Tool = 'Hayabusa'; Names = @('hayabusa.exe', 'hayabusa'); NeedDir = $evtx; Args = { param($exe, $in, $out)
                # v4 renamed csv-timeline to dfir-timeline. Probe the built-in help
                # rather than guessing, so both generations work.
                $sub = 'dfir-timeline'
                try {
                    $help = & $exe '--help' 2>&1 | Out-String
                    if ($help -match 'csv-timeline') { $sub = 'csv-timeline' }
                }
                catch { }
                # -w skips the interactive rule wizard; without it the process waits
                # forever for keyboard input and the compose step looks hung.
                # Rules resolve relative to the working directory, so point -r/-c at
                # the install tree next to the binary.
                $exeDir = Split-Path -Parent $exe
                $a = @($sub, '-d', $in, '-o', (Join-Path $out 'hayabusa.csv'), '-w', '-C')
                $rules = Join-Path $exeDir 'rules'
                if (Test-Path -LiteralPath $rules) {
                    $a += @('-r', $rules)
                    $rcfg = Join-Path $rules 'config'
                    if (Test-Path -LiteralPath $rcfg) { $a += @('-c', $rcfg) }
                }
                $a
            } }
        @{ Tool = 'Chainsaw'; Names = @('chainsaw.exe', 'chainsaw'); NeedDir = $evtx; Args = { param($exe, $in, $out)
                @( 'dump', $in, '-o', (Join-Path $out 'chainsaw'))
            } }
    )

    $rows = New-Object System.Collections.ArrayList
    $anyTool = $false
    foreach ($j in $jobs) {
        $override = $null
        if ($ToolPath.ContainsKey($j.Tool)) { $override = [string]$ToolPath[$j.Tool] }
        $resolved = Resolve-FotonExternalTool -ToolName $j.Tool -ExecutableNames $j.Names `
            -ToolPath $override -ToolRoot $ToolRoot
        $exe = $null
        $toolVer = ''
        $rulesVer = ''
        $resolveSrc = ''
        if ($resolved) {
            $exe = [string]$resolved.Path
            $toolVer = [string]$resolved.Version
            $rulesVer = [string]$resolved.RulesVersion
            $resolveSrc = [string]$resolved.Source
        }
        $toolDir = Join-Path $extRoot $j.Tool.ToLowerInvariant()
        New-Item -Path $toolDir -ItemType Directory -Force | Out-Null
        if (-not $exe) {
            $hint = 'Native ConvertFrom-Foton* / Invoke-FotonParse is the fallback. This is a coverage gap, not a parse error.'
            if ($j.Tool -eq 'Hayabusa') {
                $hint = 'Run Install-FotonTool -Name Hayabusa (or Foton.cmd tools Hayabusa), then compose again. Native ConvertFrom-Foton* remains the air-gap fallback.'
            }
            $null = $rows.Add([PSCustomObject]@{
                    Tool         = $j.Tool
                    Status       = 'NotOnPath'
                    DestRelative = ''
                    SHA256       = ''
                    Version      = ''
                    RulesVersion = ''
                    Note         = ("{0} was not found via -ToolPath, Foton tools.json, or PATH. {1}" -f $j.Tool, $hint)
                })
            continue
        }
        $anyTool = $true
        if (-not (Test-Path -LiteralPath $j.NeedDir)) {
            $null = $rows.Add([PSCustomObject]@{
                    Tool         = $j.Tool
                    Status       = 'NoInput'
                    DestRelative = ''
                    SHA256       = ''
                    Version      = $toolVer
                    RulesVersion = $rulesVer
                    Note         = ("Tool found ({0}) but input folder is missing: {1}. Re-collect elevated if the copy task was skipped." -f $resolveSrc, $j.NeedDir)
                })
            continue
        }
        $arg = & $j.Args $exe $j.NeedDir $toolDir
        $log = Join-Path $toolDir 'tool_stderr.txt'
        $ok = $false
        # Run in the tool's own install tree, not the output folder. Hayabusa resolves
        # its config/ (profiles, level colours) relative to the working directory, so
        # running it from analysis/external/hayabusa made it report missing rules and
        # config even with -r and -c supplied. Every path passed in is absolute, so
        # this is safe for the EZ Tools too.
        $workDir = Split-Path -Parent $exe
        if (-not $workDir -or -not (Test-Path -LiteralPath $workDir)) { $workDir = $toolDir }
        try {
            $p = Start-Process -FilePath $exe -ArgumentList $arg -Wait -PassThru -NoNewWindow -RedirectStandardError $log -WorkingDirectory $workDir
            if ($p.ExitCode -eq 0) { $ok = $true }
        }
        catch {
            Set-Content -LiteralPath $log -Value $_.Exception.Message -Encoding UTF8
        }
        $outs = @(Get-ChildItem -LiteralPath $toolDir -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'tool_stderr.txt' })
        if ($outs.Count -eq 0) {
            $null = $rows.Add([PSCustomObject]@{
                    Tool         = $j.Tool
                    Status       = $(if ($ok) { 'NoOutput' } else { 'ToolError' })
                    DestRelative = (Join-Path 'analysis\external' $j.Tool.ToLowerInvariant())
                    SHA256       = ''
                    Version      = $toolVer
                    RulesVersion = $rulesVer
                    Note         = ("{0} ran but produced no output files. See tool_stderr.txt. Native parse remains valid." -f $j.Tool)
                })
            continue
        }
        foreach ($f in $outs) {
            $rel = $f.FullName.Substring($root.Length).TrimStart('\')
            $null = $rows.Add([PSCustomObject]@{
                    Tool         = $j.Tool
                    Status       = 'Copied'
                    DestRelative = $rel
                    SHA256       = (Get-FotonSafeHash -Path $f.FullName)
                    Version      = $toolVer
                    RulesVersion = $rulesVer
                    Note         = ("Hashed output from {0} (resolved via {1}). Hits from this engine are observations named to the tool, not a Foton verdict." -f $j.Tool, $resolveSrc)
                })
        }
    }

    if (-not $anyTool) {
        $null = $rows.Add([PSCustomObject]@{
                Tool         = '*'
                Status       = 'NotOnPath'
                DestRelative = ''
                SHA256       = ''
                Version      = ''
                RulesVersion = ''
                Note         = 'No EZ Tools / Hayabusa / Chainsaw binaries were found. For Hayabusa: Install-FotonTool -Name Hayabusa. Use Invoke-FotonParse for native ConvertFrom-Foton* fallback.'
            })
    }

    $invPath = Join-Path $extRoot 'external_parse_inventory.csv'
    @($rows) | Export-Csv -Path $invPath -NoTypeInformation -Encoding UTF8
    return @($rows)
}
