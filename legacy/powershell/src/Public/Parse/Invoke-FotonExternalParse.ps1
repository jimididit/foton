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
        # RECmd exports nothing without a search switch; with only -d/--csv it logs a
        # warning and exits. A batch file is the whole point of running it here.
        @{ Tool = 'RECmd'; Names = @('RECmd.exe', 'RECmd'); NeedDir = $hives
            Pre = { param($exe)
                if (-not (Find-FotonRecmdBatch -RecmdPath $exe)) {
                    return [PSCustomObject]@{ Status = 'NoBatch'; Note = 'RECmd found but no BatchExamples\DFIRBatch.reb or Kroll_Batch.reb beside it. RECmd does nothing without a batch or search switch; reinstall EZ Tools with BatchExamples.' }
                }
                return $null
            }
            Args = { param($exe, $in, $out)
                @('-d', $in, '--bn', (Find-FotonRecmdBatch -RecmdPath $exe), '--csv', $out, '--csvf', 'recmd.csv')
            } }
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
                # -U writes timestamps in UTC; the default is the workstation's local
                # zone, which is neither the host's zone nor the package's UTC convention.
                $a = @($sub, '-d', $in, '-o', (Join-Path $out 'hayabusa.csv'), '-w', '-C', '-U')
                $rules = Join-Path $exeDir 'rules'
                if (Test-Path -LiteralPath $rules) {
                    $a += @('-r', $rules)
                    $rcfg = Join-Path $rules 'config'
                    if (Test-Path -LiteralPath $rcfg) { $a += @('-c', $rcfg) }
                }
                $a
            } }
        # Hunt with Sigma/Chainsaw rules shipped beside the binary. Without rules there
        # is nothing to hunt; the old `dump` fallback re-serialised every EVTX record
        # (hundreds of MB) and duplicated EvtxECmd, so it is not run.
        @{ Tool = 'Chainsaw'; Names = @('chainsaw.exe', 'chainsaw'); NeedDir = $evtx
            Pre = { param($exe)
                $r = Find-FotonChainsawRules -ChainsawPath $exe
                if (-not $r.RulesPath -and -not $r.SigmaPath) {
                    return [PSCustomObject]@{ Status = 'NoRules'; Note = 'Chainsaw found but no rules\ or sigma\ (with mappings\sigma-event-logs-all.yml) beside it. Install the Chainsaw release that bundles rules, then compose again. EvtxECmd and Hayabusa cover the EVTX meanwhile.' }
                }
                return $null
            }
            Args = { param($exe, $in, $out)
                $r = Find-FotonChainsawRules -ChainsawPath $exe
                $a = @('hunt', $in)
                if ($r.RulesPath) { $a += @('-r', $r.RulesPath) }
                if ($r.SigmaPath) { $a += @('-s', $r.SigmaPath, '--mapping', $r.MappingPath) }
                $a + @('--csv', '--output', $out, '--skip-errors')
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
        # When this run does not execute the tool, output from an earlier compose is
        # kept (it may be the only copy) but listed as Retained, so the inventory
        # still describes every file analyze will read.
        $addRetained = {
            param([string]$Why)
            foreach ($f in @(Get-ChildItem -LiteralPath $toolDir -File -Recurse -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -notin @('tool_stderr.txt', 'tool_stdout.txt') })) {
                $null = $rows.Add([PSCustomObject]@{
                        Tool         = $j.Tool
                        Status       = 'Retained'
                        DestRelative = $f.FullName.Substring($root.Length).TrimStart('\', '/')
                        SHA256       = (Get-FotonSafeHash -Path $f.FullName)
                        Version      = ''
                        RulesVersion = ''
                        Note         = ("Output from an earlier compose run; {0} did not run this time ({1}). Tool version for this file is not recorded here." -f $j.Tool, $Why)
                    })
            }
        }
        if (-not $exe) {
            $hint = 'If it is installed elsewhere, register it once: Install-FotonTool -Name EZTools -Path <folder> (or -Name Chainsaw). Native ConvertFrom-Foton* / Invoke-FotonParse is the fallback. This is a coverage gap, not a parse error.'
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
            & $addRetained 'NotOnPath'
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
            & $addRetained 'NoInput'
            continue
        }
        if ($j.Pre) {
            $skip = & $j.Pre $exe
            if ($skip) {
                $null = $rows.Add([PSCustomObject]@{
                        Tool         = $j.Tool
                        Status       = $skip.Status
                        DestRelative = ''
                        SHA256       = ''
                        Version      = $toolVer
                        RulesVersion = $rulesVer
                        Note         = $skip.Note
                    })
                & $addRetained $skip.Status
                continue
            }
        }
        # Run into a staging folder; earlier output is replaced only when this run
        # actually produces files, so a failed rerun cannot destroy the last good one.
        $stage = Join-Path $extRoot ('.{0}.staging-{1}' -f $j.Tool.ToLowerInvariant(), [guid]::NewGuid().ToString('N'))
        New-Item -Path $stage -ItemType Directory -Force | Out-Null
        $arg = & $j.Args $exe $j.NeedDir $stage
        $log = Join-Path $stage 'tool_stderr.txt'
        $stdout = Join-Path $stage 'tool_stdout.txt'
        $ok = $false
        # Run in the tool's own install tree, not the output folder. Hayabusa resolves
        # its config/ (profiles, level colours) relative to the working directory, so
        # running it from analysis/external/hayabusa made it report missing rules and
        # config even with -r and -c supplied. Every path passed in is absolute, so
        # this is safe for the EZ Tools too.
        $workDir = Split-Path -Parent $exe
        if (-not $workDir -or -not (Test-Path -LiteralPath $workDir)) { $workDir = $toolDir }
        try {
            # Start-Process joins an array with bare spaces, which splits any path that
            # contains a space (D:\My Cases\...). Pass one correctly quoted string.
            $argLine = ConvertTo-FotonCommandLine -Arguments @($arg)
            $p = Start-Process -FilePath $exe -ArgumentList $argLine -Wait -PassThru -NoNewWindow -RedirectStandardError $log -RedirectStandardOutput $stdout -WorkingDirectory $workDir
            if ($p.ExitCode -eq 0) { $ok = $true }
        }
        catch {
            Set-Content -LiteralPath $log -Value $_.Exception.Message -Encoding UTF8
        }
        $newOuts = @(Get-ChildItem -LiteralPath $stage -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @('tool_stderr.txt', 'tool_stdout.txt') })
        if ($newOuts.Count -gt 0) {
            # Swap by directory rename (same volume): the earlier output is deleted only
            # after the new folder is in place, and is restored if that rename fails.
            $prev = Join-Path $extRoot ('.{0}.prev-{1}' -f $j.Tool.ToLowerInvariant(), [guid]::NewGuid().ToString('N'))
            $swapError = ''
            try {
                Move-Item -LiteralPath $toolDir -Destination $prev -ErrorAction Stop
                try { Move-Item -LiteralPath $stage -Destination $toolDir -ErrorAction Stop }
                catch {
                    Move-Item -LiteralPath $prev -Destination $toolDir -ErrorAction SilentlyContinue
                    throw
                }
                Remove-Item -LiteralPath $prev -Recurse -Force -ErrorAction SilentlyContinue
            }
            catch { $swapError = $_.Exception.Message }
            if ($swapError) {
                $null = $rows.Add([PSCustomObject]@{
                        Tool         = $j.Tool
                        Status       = 'SwapError'
                        DestRelative = $stage.Substring($root.Length).TrimStart('\', '/')
                        SHA256       = ''
                        Version      = $toolVer
                        RulesVersion = $rulesVer
                        Note         = ("{0} produced output, but it could not replace the earlier output ({1}); a file in that folder may be open. The new output was left in the staging folder." -f $j.Tool, $swapError)
                    })
                & $addRetained 'SwapError'
                continue
            }
        }
        else {
            # Nothing new: keep earlier output, but replace the logs so they describe this run.
            foreach ($leaf in @('tool_stderr.txt', 'tool_stdout.txt')) {
                $src = Join-Path $stage $leaf
                if (Test-Path -LiteralPath $src) { Move-Item -LiteralPath $src -Destination (Join-Path $toolDir $leaf) -Force }
            }
        }
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
        $log = Join-Path $toolDir 'tool_stderr.txt'
        $stdout = Join-Path $toolDir 'tool_stdout.txt'
        # .NET 10 builds (AmcacheParser has no other) print this and exit when the
        # runtime is absent; without it the row read as a generic tool error.
        if ($newOuts.Count -eq 0 -and -not $ok -and (Test-FotonToolMissingRuntime -Paths @($log, $stdout))) {
            $null = $rows.Add([PSCustomObject]@{
                    Tool         = $j.Tool
                    Status       = 'MissingRuntime'
                    DestRelative = (Join-Path 'analysis\external' $j.Tool.ToLowerInvariant())
                    SHA256       = ''
                    Version      = $toolVer
                    RulesVersion = $rulesVer
                    Note         = ("{0} needs a .NET runtime that is not installed on this workstation (see tool_stdout.txt / tool_stderr.txt). Install the runtime it names, then compose again." -f $j.Tool)
                })
            & $addRetained 'MissingRuntime'
            continue
        }
        if ($newOuts.Count -eq 0) {
            $failStatus = $(if ($ok) { 'NoOutput' } else { 'ToolError' })
            $null = $rows.Add([PSCustomObject]@{
                    Tool         = $j.Tool
                    Status       = $failStatus
                    DestRelative = (Join-Path 'analysis\external' $j.Tool.ToLowerInvariant())
                    SHA256       = ''
                    Version      = $toolVer
                    RulesVersion = $rulesVer
                    Note         = ("{0} ran but produced no output files. See tool_stderr.txt. Native parse remains valid." -f $j.Tool)
                })
            & $addRetained $failStatus
            continue
        }
        $outs = @(Get-ChildItem -LiteralPath $toolDir -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @('tool_stderr.txt', 'tool_stdout.txt') })
        foreach ($f in $outs) {
            $rel = $f.FullName.Substring($root.Length).TrimStart('\', '/')
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
