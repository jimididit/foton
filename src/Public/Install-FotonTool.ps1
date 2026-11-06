function Install-FotonTool {
    <#
    .SYNOPSIS
        Install a pinned external DFIR tool into the Foton tool root (Hayabusa first).

    .DESCRIPTION
        Workstation setup only. Does not run during compose/analyze and does not
        mutate PATH. Downloads (or unpacks -ArchivePath) a catalog-pinned release,
        verifies SHA-256, installs under %LOCALAPPDATA%\Foton\tools by default, and
        writes tools.json so Invoke-FotonExternalParse can find the binary.

        First cut supports Hayabusa only. Compose stays offline; if a tool is
        missing it tells you to run this command.

    .PARAMETER Name
        Catalog tool name (e.g. Hayabusa). Required unless -List.

    .PARAMETER List
        Print supported catalog tools and exit.

    .PARAMETER ToolRoot
        Install root. Default: %LOCALAPPDATA%\Foton\tools.

    .PARAMETER ArchivePath
        Offline install: path to the already-downloaded release zip. Still verifies
        ExpectedSha256 from the catalog.

    .PARAMETER Path
        Register a tool that is already on disk instead of downloading one. Accepts a
        folder or an executable. -Name EZTools registers PECmd, LECmd, JLECmd,
        EvtxECmd, AmcacheParser, and RECmd from one EZ Tools folder, including the
        per-tool subfolders. Writes tools.json only; nothing is downloaded and PATH
        is not changed. The recorded SHA-256 is observed, not verified.

    .PARAMETER CatalogPath
        Optional catalog JSON override (tests).

    .PARAMETER Force
        Skip the confirmation prompt (automation / CI).

    .EXAMPLE
        Install-FotonTool -List

        Shows pinned tools and versions.

    .EXAMPLE
        Install-FotonTool -Name Hayabusa

        Prints source URL and hash, asks for confirmation, downloads and installs.

    .EXAMPLE
        Install-FotonTool -Name Hayabusa -ArchivePath D:\Offline\hayabusa-4.0.0-win-x64.zip -Force

        Air-gapped install from a local archive.

    .EXAMPLE
        Install-FotonTool -Name EZTools -Path C:\Tools\EZTools

        Registers an existing Eric Zimmerman tools folder so compose finds every tool,
        including EvtxeCmd\EvtxECmd.exe and RECmd\RECmd.exe in their subfolders.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [string]$Name,
        [switch]$List,
        [string]$ToolRoot,
        [string]$ArchivePath,
        [string]$Path,
        [string]$CatalogPath,
        [switch]$Force
    )

    if ($Path) {
        if (-not $Name) { throw 'Use -Name with -Path (for example -Name EZTools -Path C:\Tools\EZTools).' }
        # -Force skips the confirmation prompt only; -WhatIf still writes nothing.
        if ($Force) { $ConfirmPreference = 'None' }
        $manifest = Get-FotonToolManifestPath -ToolRoot $ToolRoot
        if (-not $PSCmdlet.ShouldProcess($manifest, ("Register existing {0} install from {1}" -f $Name, $Path))) {
            return
        }
        $rows = @(Register-FotonLocalTool -Name $Name -Path $Path -ToolRoot $ToolRoot)
        Write-Host ''
        Write-Host '  Foton tool registration (existing install; nothing downloaded)' -ForegroundColor Cyan
        $rows | Select-Object Name, Status, Version, ExecutablePath | Format-Table -AutoSize | Out-Host
        Write-Host '  SHA-256 values in tools.json are observed on disk, not verified against an upstream hash.' -ForegroundColor Yellow
        Write-Host '  PATH was not changed. Compose resolves these tools via tools.json.' -ForegroundColor Green
        return $rows
    }

    $catalog = @(Get-FotonToolCatalog -CatalogPath $CatalogPath)
    if ($List -or -not $Name) {
        # Return objects only, with a default view, so the console shows one table and
        # callers still get every field (Format-List * shows SHA-256 and Notes).
        $view = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet', [string[]]@('Name', 'Version', 'License', 'DownloadUrl'))
        $members = [System.Management.Automation.PSMemberInfo[]]@($view)
        foreach ($entry in $catalog) {
            $entry | Add-Member -MemberType MemberSet -Name PSStandardMembers -Value $members -Force
        }
        if (-not $List -and -not $Name) {
            Write-Host "  Usage: Install-FotonTool -Name Hayabusa   (or -List)" -ForegroundColor Cyan
        }
        return $catalog
    }

    $entry = Get-FotonToolCatalogEntry -Name $Name -CatalogPath $CatalogPath
    $root = Get-FotonToolRoot -ToolRoot $ToolRoot
    $dest = Join-Path $root ([string]$entry.Name.ToLowerInvariant())
    $destVer = Join-Path $dest ([string]$entry.Version)

    Write-Host ''
    Write-Host '  Foton tool install (workstation setup — not part of a case package)' -ForegroundColor Cyan
    Write-Host ("  Tool:     {0} {1}" -f $entry.Name, $entry.Version)
    Write-Host ("  License:  {0}  {1}" -f $entry.License, $entry.ProjectUrl)
    Write-Host ("  Source:   {0}" -f $(if ($ArchivePath) { $ArchivePath } else { $entry.DownloadUrl }))
    Write-Host ("  SHA-256:  {0}" -f $entry.ExpectedSha256)
    Write-Host ("  Dest:     {0}" -f $destVer)
    Write-Host ("  Note:     {0}" -f $entry.Notes)
    Write-Host ''

    $confirmText = ("Install {0} {1} into {2}?" -f $entry.Name, $entry.Version, $destVer)
    if (-not $Force) {
        if (-not $PSCmdlet.ShouldContinue($confirmText, 'Install-FotonTool')) {
            Write-Host '  Cancelled.' -ForegroundColor Yellow
            return
        }
    }
    # -Force skips prompts for automation/CI (NonInteractive has no ShouldProcess UI).

    New-Item -Path $root -ItemType Directory -Force | Out-Null
    $logPath = Join-Path $root 'install.log'
    $log = {
        param([string]$Msg)
        $line = '{0} UTC  {1}' -f [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss'), $Msg
        Add-Content -LiteralPath $logPath -Value $line -Encoding UTF8
        Write-Host ("  {0}" -f $Msg)
    }

    $zipPath = $null
    $cleanupZip = $false
    try {
        if ($ArchivePath) {
            if (-not (Test-Path -LiteralPath $ArchivePath)) {
                throw ("Archive not found: {0}" -f $ArchivePath)
            }
            $zipPath = (Get-Item -LiteralPath $ArchivePath).FullName
            & $log ("Using local archive {0}" -f $zipPath)
        }
        else {
            $zipPath = Join-Path $env:TEMP ('foton-tool-' + [guid]::NewGuid().ToString('N') + '.zip')
            $cleanupZip = $true
            & $log ("Downloading {0}" -f $entry.DownloadUrl)
            # Prefer curl.exe when present (same path operators already use); fall back.
            $dlOk = $false
            if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
                & curl.exe -fsSL -o $zipPath $entry.DownloadUrl
                if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $zipPath)) { $dlOk = $true }
            }
            if (-not $dlOk) {
                $wc = New-Object System.Net.WebClient
                try { $wc.DownloadFile([string]$entry.DownloadUrl, $zipPath) }
                finally { $wc.Dispose() }
            }
            if (-not (Test-Path -LiteralPath $zipPath)) {
                throw 'Download produced no file. Use -ArchivePath for an offline install.'
            }
        }

        $hash = (Get-FotonSha256Hex -LiteralPath $zipPath).ToUpperInvariant()
        $expect = ([string]$entry.ExpectedSha256).ToUpperInvariant()
        & $log ("Archive SHA-256 {0}" -f $hash)
        if ($hash -ne $expect) {
            throw ("SHA-256 mismatch for {0}. Expected {1}, got {2}. Refusing to install." -f $entry.AssetName, $expect, $hash)
        }
        & $log 'Hash matches catalog pin.'

        if (Test-Path -LiteralPath $destVer) {
            Remove-Item -LiteralPath $destVer -Recurse -Force
        }
        New-Item -Path $destVer -ItemType Directory -Force | Out-Null
        Expand-Archive -LiteralPath $zipPath -DestinationPath $destVer -Force
        & $log ("Expanded to {0}" -f $destVer)

        $exe = $null
        foreach ($n in @($entry.ExecutableNames)) {
            $hit = @(Get-ChildItem -LiteralPath $destVer -Filter $n -File -Recurse -ErrorAction SilentlyContinue |
                    Select-Object -First 1)
            if ($hit.Count -gt 0) { $exe = $hit[0].FullName; break }
        }
        if (-not $exe) {
            throw ("Archive extracted but no executable named {0} was found under {1}." -f (
                    (@($entry.ExecutableNames) -join '/'), $destVer))
        }

        # Optional convenience link at dest\hayabusa.exe when nested in a version folder.
        $linkDir = $dest
        New-Item -Path $linkDir -ItemType Directory -Force | Out-Null
        $stable = Join-Path $linkDir ([IO.Path]::GetFileName($exe))
        Copy-Item -LiteralPath $exe -Destination $stable -Force
        $exeDir = Split-Path -Parent $exe
        foreach ($leaf in @('config', 'rules')) {
            $srcSide = Join-Path $exeDir $leaf
            $dstSide = Join-Path $linkDir $leaf
            if ((Test-Path -LiteralPath $srcSide) -and -not (Test-Path -LiteralPath $dstSide)) {
                Copy-Item -LiteralPath $srcSide -Destination $dstSide -Recurse -Force
            }
        }
        # Prefer the stable copy for the manifest so rules/config sit beside it.
        if (Test-Path -LiteralPath $stable) { $exe = $stable }

        $rulesVer = ("bundled-{0}" -f $entry.Version)
        $rulesPath = ''
        if ($entry.RulesRelativePath) {
            $rp = Join-Path (Split-Path -Parent $exe) ([string]$entry.RulesRelativePath)
            if (Test-Path -LiteralPath $rp) {
                $rulesPath = (Get-Item -LiteralPath $rp).FullName
                $gitHead = Join-Path $rp '.git\HEAD'
                if (Test-Path -LiteralPath $gitHead) {
                    try {
                        $h = (Get-Content -LiteralPath $gitHead -TotalCount 1).Trim()
                        if ($h -match 'ref:\s*refs/heads/(.+)$') {
                            $ref = Join-Path $rp ('.git\refs\heads\' + $Matches[1])
                            if (Test-Path -LiteralPath $ref) {
                                $rulesVer = ((Get-Content -LiteralPath $ref -TotalCount 1).Trim().Substring(0, [Math]::Min(12, 40)))
                            }
                        }
                        elseif ($h.Length -ge 12) { $rulesVer = $h.Substring(0, 12) }
                    }
                    catch { }
                }
            }
        }

        $record = [PSCustomObject]@{
            Name            = [string]$entry.Name
            Version         = [string]$entry.Version
            SourceUrl       = $(if ($ArchivePath) { $zipPath } else { [string]$entry.DownloadUrl })
            ArchiveSha256   = $hash
            InstallDateUtc  = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')
            InstallPath     = $destVer
            ExecutablePath  = $exe
            RulesPath       = $rulesPath
            RulesVersion    = $rulesVer
            License         = [string]$entry.License
        }
        $manPath = Save-FotonToolManifestEntry -ToolRoot $root -Entry $record
        & $log ("Wrote manifest {0}" -f $manPath)
        & $log ("Installed {0} {1} -> {2}" -f $entry.Name, $entry.Version, $exe)
        Write-Host ''
        Write-Host '  PATH was not changed. Compose resolves this tool via tools.json.' -ForegroundColor Green
        Write-Host '  Next: Foton.cmd compose <case-folder>' -ForegroundColor Green
        return $record
    }
    finally {
        if ($cleanupZip -and $zipPath -and (Test-Path -LiteralPath $zipPath)) {
            Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue
        }
    }
}
