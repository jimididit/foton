function Get-FotonComposeToolExecutables {
    <#
        Executable leaf names compose looks for, per tool. EZTools is a bundle name
        that expands to the six Eric Zimmerman tools compose runs.
    #>
    param([Parameter(Mandatory)][string]$Name)
    $map = [ordered]@{
        PECmd         = @('PECmd.exe')
        LECmd         = @('LECmd.exe')
        JLECmd        = @('JLECmd.exe')
        EvtxECmd      = @('EvtxECmd.exe')
        AmcacheParser = @('AmcacheParser.exe')
        RECmd         = @('RECmd.exe')
        Hayabusa      = @('hayabusa.exe', 'hayabusa-*.exe')
        Chainsaw      = @('chainsaw.exe')
    }
    if ($Name -eq 'EZTools') {
        $out = [ordered]@{}
        foreach ($k in @('PECmd', 'LECmd', 'JLECmd', 'EvtxECmd', 'AmcacheParser', 'RECmd')) { $out[$k] = $map[$k] }
        return $out
    }
    foreach ($k in $map.Keys) {
        if ($k -eq $Name) {
            $one = [ordered]@{}
            $one[$k] = $map[$k]
            return $one
        }
    }
    throw ("Unknown tool '{0}'. Use EZTools, PECmd, LECmd, JLECmd, EvtxECmd, AmcacheParser, RECmd, Hayabusa, or Chainsaw." -f $Name)
}

function Get-FotonToolCliVersion {
    <#
        Version printed by the tool itself, for binaries with no file version resource
        (Chainsaw is a Rust build: `chainsaw --version` prints "chainsaw 2.17.1").
        Only tools listed here are run, with a short timeout; empty when unknown.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ExecutablePath,
        [int]$TimeoutMs = 5000
    )
    $versionArgs = @{ Chainsaw = '--version' }
    if (-not $versionArgs.ContainsKey($Name)) { return '' }
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $ExecutablePath
        $psi.Arguments = $versionArgs[$Name]
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.RedirectStandardInput = $true
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $proc.StandardInput.Close()
        $stdout = $proc.StandardOutput.ReadToEndAsync()
        if (-not $proc.WaitForExit($TimeoutMs)) {
            try { $proc.Kill() } catch { }
            return ''
        }
        $m = [regex]::Match([string]$stdout.Result, '\d+\.\d+(?:\.\d+){0,2}')
        if ($m.Success) { return $m.Value }
    }
    catch { }
    return ''
}

function Register-FotonLocalTool {
    <#
        Record an already-installed tool (or the EZ Tools folder) in tools.json
        without downloading anything or touching PATH.

        EZ Tools unpack into per-tool subfolders (EvtxeCmd\, RECmd\, AmcacheParser\)
        that a single PATH entry never covers; recording each executable's full path
        lets compose find them. Upstream publishes no per-file hashes, so the SHA-256
        written here is what Foton observed on disk, not a verification.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path,
        [string]$ToolRoot
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw ("Path not found: {0}" -f $Path)
    }
    $item = Get-Item -LiteralPath $Path
    $searchRoot = $item.FullName
    if (-not $item.PSIsContainer) { $searchRoot = $item.DirectoryName }

    $wanted = Get-FotonComposeToolExecutables -Name $Name
    # Resolve the default root here: Save-FotonToolManifestEntry rejects an empty
    # -ToolRoot, and that binding error does not stop this function on its own.
    $root = Get-FotonToolRoot -ToolRoot $ToolRoot
    $records = @()
    foreach ($tool in $wanted.Keys) {
        $exe = $null
        foreach ($pattern in @($wanted[$tool])) {
            if (-not $item.PSIsContainer) {
                if ($item.Name -like $pattern) { $exe = $item; break }
                continue
            }
            # Depth 2 covers EZTools\EvtxeCmd\EvtxECmd.exe without walking a whole drive.
            $exe = Get-ChildItem -LiteralPath $searchRoot -Filter $pattern -File -Recurse -Depth 2 -ErrorAction SilentlyContinue |
                Sort-Object { $_.FullName.Length } | Select-Object -First 1
            if ($exe) { break }
        }
        if (-not $exe) {
            $records += [PSCustomObject]@{ Name = $tool; Status = 'NotFound'; Version = ''; ExecutablePath = ''; ObservedSha256 = '' }
            continue
        }
        $ver = ''
        try { $ver = [string]$exe.VersionInfo.FileVersion } catch { }
        if (-not $ver.Trim()) { $ver = Get-FotonToolCliVersion -Name $tool -ExecutablePath $exe.FullName }
        $rulesPath = ''
        $rulesVer = ''
        foreach ($leaf in @('rules', 'sigma')) {
            $rp = Join-Path $exe.DirectoryName $leaf
            if (Test-Path -LiteralPath $rp) { $rulesPath = $rp; $rulesVer = 'local-unversioned'; break }
        }
        $sha = Get-FotonSha256Hex -LiteralPath $exe.FullName
        $entry = [PSCustomObject]@{
            Name           = $tool
            Version        = $ver
            SourceUrl      = 'registered local install'
            ArchiveSha256  = ''
            ObservedSha256 = $sha
            Verified       = $false
            InstallDateUtc = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')
            InstallPath    = $exe.DirectoryName
            ExecutablePath = $exe.FullName
            RulesPath      = $rulesPath
            RulesVersion   = $rulesVer
            License        = ''
        }
        $null = Save-FotonToolManifestEntry -ToolRoot $root -Entry $entry -ErrorAction Stop
        $records += [PSCustomObject]@{ Name = $tool; Status = 'Registered'; Version = $ver; ExecutablePath = $exe.FullName; ObservedSha256 = $sha }
    }
    return $records
}
