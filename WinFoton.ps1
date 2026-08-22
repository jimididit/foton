<#
.SYNOPSIS
    WinFoton - Windows DFIR triage collector.

.DESCRIPTION
    Collects forensically relevant host state from a live Windows endpoint, organizes it
    by category, hashes every artifact, generates an analyst-facing HTML overview, and
    packages the result into a single shareable ZIP.

    WinFoton performs LIVE COLLECTION. Running it modifies the target system (process
    creation, prefetch, event log entries, file writes). This is documented in the
    collection log so the footprint is disclosed rather than hidden. If a full disk or
    memory image is required, capture that BEFORE running this tool.

    Findings in the HTML report are AUTOMATED OBSERVATIONS, not conclusions. Each one is
    tiered (see the report's Methodology section) and cites the artifact file it came
    from. Analyst verification is required before any finding is used in a report.

.PARAMETER OutputPath
    Directory where the case folder and ZIP are written. Default: current user's Desktop.

.PARAMETER CaseNumber
    Case or engagement identifier, recorded in the chain-of-custody header.

.PARAMETER Examiner
    Name of the person performing collection. Default: current username.

.PARAMETER EventLogDays
    Days of event log history to collect. Default: 14.

.PARAMETER MaxEventsPerLog
    Cap on parsed events per log query, to bound runtime. Default: 3000.

.PARAMETER SkipEvtxExport
    Skip raw .evtx export (parsed summaries are still collected). Reduces package size.

.PARAMETER SkipHashing
    Skip SHA-256 hashing of running process images and suspicious files. Much faster,
    but removes the strongest pivot data for IoC comparison.

.PARAMETER LoadUserHives
    Mount NTUSER.DAT for users who are not currently logged on, so their persistence
    keys are examined. This writes to the registry (load/unload) and is logged.

.PARAMETER IncludeFileTimeline
    Deeper filesystem sweep of user-writable paths. Slower on large systems.

.PARAMETER NoZip
    Leave the case folder uncompressed.

.PARAMETER RequireAdministrator
    Exit immediately if the process is not elevated. Use on IR engagements that must
    have Security-log and other-user coverage. The default is to collect whatever the
    current token can read (standard-user / work-laptop mode).

.EXAMPLE
    .\WinFoton.ps1
    Default triage collection to the Desktop.

.EXAMPLE
    .\WinFoton.ps1 -CaseNumber "JDI-2026-0142" -Examiner "J. Flynn" -OutputPath D:\Cases -EventLogDays 30 -LoadUserHives

.NOTES
    Name       : WinFoton
    Version    : 1.0.4
    Requires   : Windows PowerShell 5.1+ (or PowerShell 7 on Windows). Administrator recommended; standard-user coverage is supported.
    Author     : Built for JDI Consulting DFIR workflows
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Desktop",
    [string]$CaseNumber = "",
    [string]$Examiner = "$env:USERNAME",
    [int]$EventLogDays = 14,
    [int]$MaxEventsPerLog = 3000,
    [switch]$SkipEvtxExport,
    [switch]$SkipHashing,
    [switch]$LoadUserHives,
    [switch]$IncludeFileTimeline,
    [switch]$NoZip,
    [switch]$RequireAdministrator
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

# ==============================================================================
#  GLOBAL STATE
# ==============================================================================

$Script:Version      = '1.0.4'
$Script:StartTimeUtc = (Get-Date).ToUniversalTime()
$Script:Findings     = New-Object System.Collections.ArrayList
$Script:Manifest     = New-Object System.Collections.ArrayList
$Script:Data         = @{}
$Script:Dirs         = @{}
$Script:LogFile      = $null
$Script:Errors       = New-Object System.Collections.ArrayList
$Script:LoadedHives  = New-Object System.Collections.ArrayList
# Token used for this run. StandardUser is a supported coverage profile, not a failed run.
$Script:IsElevated   = $false
$Script:LoadUserHivesActive = $false

$Script:Categories = [ordered]@{
    'Collection'  = '00_Collection'
    'System'      = '01_System'
    'Users'       = '02_Users_and_Access'
    'Processes'   = '03_Processes_and_Volatile'
    'Network'     = '04_Network'
    'Persistence' = '05_Persistence'
    'Security'    = '06_Security_Posture'
    'EventLogs'   = '07_Event_Logs'
    'Filesystem'  = '08_Filesystem'
    'Software'    = '09_Software_and_Drivers'
}

# Paths a normal, well-behaved binary rarely executes from. Used as a heuristic only.
$Script:UserWritablePatterns = @(
    '\\AppData\\',
    '\\Users\\Public\\',
    '\\ProgramData\\',
    '\\Windows\\Temp\\',
    '\\Temp\\',
    '\\Downloads\\',
    '\\Recycle',
    '\\PerfLogs\\'
)

# Command-line / script content substrings commonly present in living-off-the-land abuse.
$Script:SuspiciousCommandPatterns = @(
    '-enc', '-encodedcommand', 'frombase64string', 'downloadstring', 'downloadfile',
    'invoke-expression', 'iex ', 'invoke-webrequest', 'bitsadmin', 'certutil -urlcache',
    'certutil.exe -decode', 'mshta ', 'regsvr32 /s /u', 'rundll32 javascript',
    'wmic process call create', 'vssadmin delete', 'bcdedit /set', 'wbadmin delete',
    'net user /add', 'schtasks /create', 'add-mppreference -exclusionpath',
    'set-mppreference -disable', 'invoke-mimikatz', 'sekurlsa', 'lsass', 'nltest',
    'reg save hklm\sam', 'comsvcs.dll', 'minidump', 'hidden -w hidden', '-windowstyle hidden',
    'nop -w hidden', 'psexec', 'ngrok', 'anydesk', 'rclone', 'megacmd'
)

# ==============================================================================
#  CORE HELPERS
# ==============================================================================

function Write-Status {
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
    if ($Script:LogFile) {
        try { "$stamp UTC  [$Level] $Message" | Out-File -FilePath $Script:LogFile -Append -Encoding UTF8 } catch { }
    }
}

function Add-Finding {
    <#
        Records an automated observation for the HTML report.

        Tier reflects evidentiary strength, not urgency:
          1 = Observed artifact. Stated as fact.
          2 = Supported inference. Reasonable reading of the artifact, other readings possible.
          3 = Unverified hypothesis. Flagged for analyst follow-up only.
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('High', 'Medium', 'Low', 'Info')][string]$Severity,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Observation,
        [ValidateSet(1, 2, 3)][int]$Tier = 2,
        [string]$WhyItMatters = '',
        [string]$Artifact = '',
        [string]$NextStep = ''
    )
    $null = $Script:Findings.Add([PSCustomObject]@{
            Severity     = $Severity
            Category     = $Category
            Title        = $Title
            Observation  = $Observation
            Tier         = $Tier
            WhyItMatters = $WhyItMatters
            Artifact     = $Artifact
            NextStep     = $NextStep
        })
}

function Invoke-Collection {
    <#
        Runs one collection task, writes its output, records it in the manifest, and
        caches the result for the findings engine. A failure here is logged and does not
        stop the run - partial collection is still evidence, silent gaps are not.
    #>
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Script,
        [ValidateSet('Json', 'Csv', 'Txt')][string]$Format = 'Json',
        [string]$Description = '',
        [switch]$NoCache,
        [switch]$RequiresElevation
    )

    $dir = $Script:Dirs[$Category]
    $file = Join-Path $dir ("{0}.{1}" -f $Name, $Format.ToLower())
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $status = 'Success'
    $errMsg = ''
    $data = $null
    $count = 0

    # Tasks that cannot return a useful artifact without an elevated token are skipped
    # on purpose. A skip is a disclosed visibility gap, not a collection error.
    if ($RequiresElevation -and -not $Script:IsElevated) {
        $status = 'SkippedNotElevated'
        $errMsg = 'Requires an Administrator token; skipped in standard-user coverage.'
        $skipText = @(
            "WinFoton: task '$Name' was not run."
            "Status: SkippedNotElevated"
            $errMsg
            'This is a visibility gap. Do not treat a missing or empty artifact as proof the underlying data was absent on the host.'
        ) -join [Environment]::NewLine
        try { $skipText | Out-File -FilePath $file -Encoding UTF8 } catch { }
        $sw.Stop()
        $null = $Script:Manifest.Add([PSCustomObject]@{
                Category    = $Category
                Task        = $Name
                Description = $Description
                File        = (Join-Path $Script:Categories[$Category] (Split-Path $file -Leaf))
                Records     = 0
                Status      = $status
                DurationMs  = [int]$sw.ElapsedMilliseconds
                Error       = $errMsg
            })
        if (-not $NoCache) { $Script:Data[$Name] = $null }
        Write-Status "$Name - skipped (not elevated)" 'Info'
        return $null
    }

    try {
        $data = & $Script
    }
    catch {
        $status = 'Error'
        $errMsg = $_.Exception.Message
        $null = $Script:Errors.Add([PSCustomObject]@{ Task = $Name; Error = $errMsg })
    }

    try {
        if ($null -eq $data -or ($data -is [System.Array] -and $data.Count -eq 0)) {
            if ($status -eq 'Success') { $status = 'NoData' }
            "WinFoton: no data returned for '$Name'. Status: $status. $errMsg" |
                Out-File -FilePath $file -Encoding UTF8
        }
        else {
            $count = @($data).Count
            switch ($Format) {
                'Json' { $data | ConvertTo-Json -Depth 5 -Compress:$false | Out-File -FilePath $file -Encoding UTF8 }
                'Csv' { $data | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8 }
                'Txt' { $data | Out-String -Width 4096 | Out-File -FilePath $file -Encoding UTF8 }
            }
        }
    }
    catch {
        $status = 'WriteError'
        $errMsg = $_.Exception.Message
        try { "WinFoton write error for '$Name': $errMsg" | Out-File -FilePath $file -Encoding UTF8 } catch { }
    }

    $sw.Stop()

    $null = $Script:Manifest.Add([PSCustomObject]@{
            Category    = $Category
            Task        = $Name
            Description = $Description
            File        = (Join-Path $Script:Categories[$Category] (Split-Path $file -Leaf))
            Records     = $count
            Status      = $status
            DurationMs  = [int]$sw.ElapsedMilliseconds
            Error       = $errMsg
        })

    if (-not $NoCache) { $Script:Data[$Name] = $data }

    switch ($status) {
        'Success' { Write-Status "$Name ($count records, $([int]$sw.ElapsedMilliseconds) ms)" 'Good' }
        'NoData' { Write-Status "$Name - no data returned" 'Info' }
        default { Write-Status "$Name - $status : $errMsg" 'Warn' }
    }

    return $data
}

function Get-ArtifactPath {
    param([string]$Category, [string]$Name, [string]$Format = 'json')
    return ("{0}/{1}.{2}" -f $Script:Categories[$Category], $Name, $Format)
}

function Test-Elevated {
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

function Get-SafeHash {
    param([string]$Path)
    if ($SkipHashing) { return 'NotHashed' }
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return 'FileNotFound' }
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($item.Length -gt 200MB) { return 'SkippedTooLarge' }
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    }
    catch { return 'HashError' }
}

function Get-SignatureInfo {
    param([string]$Path)
    $result = [PSCustomObject]@{ Status = 'Unknown'; Signer = ''; IsOSBinary = $false }
    if ([string]::IsNullOrWhiteSpace($Path)) { return $result }
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            $result.Status = 'FileNotFound'
            return $result
        }
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $result.Status = [string]$sig.Status
        if ($sig.SignerCertificate) { $result.Signer = [string]$sig.SignerCertificate.Subject }
        if ($sig.IsOSBinary) { $result.IsOSBinary = $true }
    }
    catch { $result.Status = 'SignatureCheckError' }
    return $result
}

function Test-UserWritablePath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    foreach ($pattern in $Script:UserWritablePatterns) {
        if ($Path -match $pattern) { return $true }
    }
    return $false
}

function Test-SuspiciousCommand {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $lower = $Text.ToLower()
    $hits = @()
    foreach ($pattern in $Script:SuspiciousCommandPatterns) {
        if ($lower.Contains($pattern)) { $hits += $pattern }
    }
    if ($hits.Count -gt 0) { return ($hits -join ', ') }
    return $null
}

function Get-RegValueSafe {
    param([string]$Path, [string]$Name)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    }
    catch { return $null }
}

function Get-RegValueList {
    <# Returns every value under a key as name/data pairs, skipping PS metadata properties. #>
    param([string]$Path)
    $out = @()
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $out }
        $key = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
        foreach ($prop in $key.PSObject.Properties) {
            if ($prop.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) { continue }
            $out += [PSCustomObject]@{
                Key   = $Path
                Name  = $prop.Name
                Value = ($prop.Value -join ' ')
            }
        }
    }
    catch { }
    return $out
}

function ConvertTo-SafeHtml {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $s = [string]$Text
    $s = $s.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&#39;')
    return $s
}

function ConvertTo-ObservationHtml {
    <#
        Renders a finding Observation. Format-Sample joins items with ' ; ', which
        wrapped badly inside an inline span (overlapping lines). Lead sentence stays
        a paragraph; sampled paths/commands become a list.
    #>
    param([string]$Text)
    $safe = ConvertTo-SafeHtml $Text
    $marker = 'Sample: '
    $pos = $safe.IndexOf($marker)
    $lead = ''
    $items = @()
    if ($pos -ge 0) {
        $lead = $safe.Substring(0, $pos).Trim()
        $rest = $safe.Substring($pos + $marker.Length)
        $items = @($rest -split ' ; ' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }
    elseif ($safe.Contains(' ; ')) {
        $items = @($safe -split ' ; ' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }
    else {
        return "<div class=""obs""><p class=""obs-lead"">$safe</p></div>"
    }
    $html = '<div class="obs">'
    if ($lead) {
        $html += "<p class=""obs-lead"">$lead</p>"
    }
    $html += '<ul class="obs-list">'
    foreach ($item in $items) {
        $html += "<li>$item</li>"
    }
    $html += '</ul></div>'
    return $html
}

function Test-PathAccessible {
    <#
        Test-Path that treats access-denied as "not here for this token".
        Default Test-Path writes UnauthorizedAccessException to the console under
        $ErrorActionPreference Continue (SYSTEM and ServiceProfiles paths).
    #>
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try {
        return [bool](Test-Path -LiteralPath $Path -ErrorAction Stop)
    }
    catch {
        return $false
    }
}

function Get-UserProfileList {
    <# Local profiles from ProfileList, used for per-user artifact collection. #>
    $profiles = @()
    try {
        $base = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        Get-ChildItem -LiteralPath $base -ErrorAction Stop | ForEach-Object {
            $sid = Split-Path $_.Name -Leaf
            $path = Get-RegValueSafe -Path $_.PSPath -Name 'ProfileImagePath'
            if ($path) {
                $name = Split-Path $path -Leaf
                $profiles += [PSCustomObject]@{
                    SID         = $sid
                    UserName    = $name
                    ProfilePath = $path
                    Exists      = (Test-PathAccessible -Path $path)
                    HiveLoaded  = (Test-PathAccessible -Path ("Registry::HKEY_USERS\$sid"))
                }
            }
        }
    }
    catch { }
    if (-not $Script:IsElevated) {
        # SYSTEM (S-1-5-18) and service profiles live under Windows\system32\config and
        # ServiceProfiles; a standard user cannot Test-Path them without Access Denied noise.
        $profiles = @($profiles | Where-Object { $_.SID -like 'S-1-5-21-*' })
    }
    return $profiles
}

function Mount-OfflineUserHives {
    <#
        Loads NTUSER.DAT for profiles whose hive is not currently loaded, so per-user
        persistence keys can be read. This WRITES to the registry and is logged for
        methodology disclosure. Hives are unloaded in Dismount-OfflineUserHives.
    #>
    $mounted = @()
    foreach ($userProfile in (Get-UserProfileList)) {
        if ($userProfile.HiveLoaded -or -not $userProfile.Exists) { continue }
        if ($userProfile.SID -notlike 'S-1-5-21-*') { continue }
        $dat = Join-Path $userProfile.ProfilePath 'NTUSER.DAT'
        if (-not (Test-Path -LiteralPath $dat)) { continue }
        $mountName = "WinFoton_$($userProfile.SID)"
        try {
            $null = & reg.exe load "HKU\$mountName" "$dat" 2>&1
            if ($LASTEXITCODE -eq 0) {
                $null = $Script:LoadedHives.Add($mountName)
                $mounted += [PSCustomObject]@{ SID = $userProfile.SID; UserName = $userProfile.UserName; MountPoint = "HKEY_USERS\$mountName" }
                Write-Status "Loaded offline hive for $($userProfile.UserName)" 'Info'
            }
        }
        catch { Write-Status "Could not load hive for $($userProfile.UserName): $($_.Exception.Message)" 'Warn' }
    }
    return $mounted
}

function Dismount-OfflineUserHives {
    foreach ($mountName in $Script:LoadedHives) {
        try {
            [gc]::Collect()
            $null = & reg.exe unload "HKU\$mountName" 2>&1
            Write-Status "Unloaded hive $mountName" 'Info'
        }
        catch { Write-Status "Failed to unload hive $mountName - manual cleanup required" 'Warn' }
    }
}

function Get-UserHiveRoots {
    <# All HKEY_USERS roots worth examining, mapped back to a username where possible. #>
    $roots = @()
    $profiles = Get-UserProfileList
    try {
        Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction Stop | ForEach-Object {
            $leaf = Split-Path $_.Name -Leaf
            if ($leaf -like '*_Classes') { return }
            if ($leaf -notlike 'S-1-5-21-*' -and $leaf -notlike 'WinFoton_*') { return }
            $sid = $leaf -replace '^WinFoton_', ''
            $match = $profiles | Where-Object { $_.SID -eq $sid } | Select-Object -First 1
            $userName = $sid
            if ($match) { $userName = $match.UserName }
            $roots += [PSCustomObject]@{
                SID      = $sid
                UserName = $userName
                Root     = "Registry::HKEY_USERS\$leaf"
            }
        }
    }
    catch { }
    return $roots
}

# ==============================================================================
#  INITIALIZATION
# ==============================================================================

function Initialize-Case {
    $host_ = $env:COMPUTERNAME
    $stamp = $Script:StartTimeUtc.ToString('yyyyMMdd-HHmmss')
    $caseFolderName = "WinFoton_{0}_{1}Z" -f $host_, $stamp

    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }
    $Script:CaseRoot = Join-Path $OutputPath $caseFolderName
    New-Item -Path $Script:CaseRoot -ItemType Directory -Force | Out-Null

    foreach ($key in $Script:Categories.Keys) {
        $dir = Join-Path $Script:CaseRoot $Script:Categories[$key]
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
        $Script:Dirs[$key] = $dir
    }

    $Script:LogFile = Join-Path $Script:Dirs['Collection'] 'collection.log'
    "WinFoton $Script:Version collection log" | Out-File -FilePath $Script:LogFile -Encoding UTF8
    return $Script:CaseRoot
}

function Write-ChainOfCustody {
    $elevated = Test-Elevated
    $tz = [System.TimeZoneInfo]::Local
    $os = $null
    try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { }
    $cs = $null
    try { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop } catch { }

    $lines = @()
    $lines += '================================================================'
    $lines += ' WinFoton - Collection Record / Chain of Custody Header'
    $lines += '================================================================'
    $lines += ''
    $lines += "Case Number          : $(if ($CaseNumber) { $CaseNumber } else { '(not supplied)' })"
    $lines += "Examiner             : $Examiner"
    $lines += "Collection Tool      : WinFoton v$Script:Version"
    $lines += "Collection Type      : Live (running system) logical collection"
    $lines += "Collection Start UTC : $($Script:StartTimeUtc.ToString('yyyy-MM-dd HH:mm:ss'))"
    $lines += "Local Time At Start  : $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))"
    $lines += "System Time Zone     : $($tz.Id) (UTC offset $($tz.GetUtcOffset((Get-Date))))"
    $lines += ''
    $lines += "Hostname             : $env:COMPUTERNAME"
    $lines += "Domain / Workgroup   : $(if ($cs) { $cs.Domain } else { 'unknown' })"
    $lines += "Manufacturer / Model : $(if ($cs) { "$($cs.Manufacturer) $($cs.Model)" } else { 'unknown' })"
    $lines += "Operating System     : $(if ($os) { "$($os.Caption) $($os.Version) (build $($os.BuildNumber))" } else { 'unknown' })"
    $lines += "Last Boot UTC        : $(if ($os) { $os.LastBootUpTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } else { 'unknown' })"
    $lines += ''
    $lines += "Collection Account   : $env:USERDOMAIN\$env:USERNAME"
    $lines += "Elevated (Admin)     : $elevated"
    $lines += "Coverage Profile     : $(if ($elevated) { 'Elevated' } else { 'StandardUser' })"
    $lines += "PowerShell Version   : $($PSVersionTable.PSVersion.ToString())"
    $lines += "Script Path          : $($MyInvocation.ScriptName)"
    $lines += ''
    $lines += 'Parameters Used:'
    $lines += "  OutputPath          = $OutputPath"
    $lines += "  EventLogDays        = $EventLogDays"
    $lines += "  MaxEventsPerLog     = $MaxEventsPerLog"
    $lines += "  SkipEvtxExport      = $SkipEvtxExport"
    $lines += "  SkipHashing         = $SkipHashing"
    $lines += "  LoadUserHives       = $LoadUserHives"
    $lines += "  IncludeFileTimeline = $IncludeFileTimeline"
    $lines += "  NoZip               = $NoZip"
    $lines += "  RequireAdministrator = $RequireAdministrator"
    $lines += ''
    $lines += '----------------------------------------------------------------'
    $lines += ' METHODOLOGY DISCLOSURE'
    $lines += '----------------------------------------------------------------'
    $lines += 'This was a LIVE collection. Executing this tool altered the target'
    $lines += 'system state: it created a process, wrote files to the output path,'
    $lines += 'generated event log entries, updated prefetch/AmCache, and read'
    $lines += 'registry keys (updating last-access metadata on some artifacts).'
    $lines += 'Volatile data (RAM, live network state) was captured only to the'
    $lines += 'extent listed in the manifest. No memory image and no disk image'
    $lines += 'were produced. If either is required, capture them before or'
    $lines += 'independently of this collection.'
    $lines += ''
    if ($LoadUserHives -and $elevated) {
        $lines += 'The -LoadUserHives option was used: NTUSER.DAT hives for users not'
        $lines += 'logged on were mounted read into HKEY_USERS and unloaded at the end'
        $lines += 'of collection. This is a registry write operation on the target.'
        $lines += ''
    }
    elseif ($LoadUserHives -and -not $elevated) {
        $lines += 'The -LoadUserHives option was requested but ignored: mounting NTUSER.DAT'
        $lines += 'requires an elevated token. Per-user keys are limited to hives already loaded.'
        $lines += ''
    }
    if (-not $elevated) {
        $lines += 'Coverage profile STANDARD USER. This process was not elevated. The package'
        $lines += 'contains what the current token could read (typically the interactive user''s'
        $lines += 'processes, HKCU persistence, readable HKLM values, network snapshot, and that'
        $lines += 'user''s profile artifacts). The Security event log, Prefetch, VSS listing,'
        $lines += 'auditpol, secedit export, and other users'' files were not collected (see'
        $lines += 'collection_coverage.json and manifest Status=SkippedNotElevated). Absence of'
        $lines += 'those artifacts is a visibility gap, not evidence they were empty on the host.'
        $lines += ''
    }
    $lines += 'SHA-256 hashes for every collected artifact are recorded in'
    $lines += 'hashes.csv, produced after collection completed. Verify these hashes'
    $lines += 'on receipt and at each transfer. Record custody transfers below.'
    $lines += ''
    $lines += 'Transfer Log:'
    $lines += '  [Date/Time UTC] --- from ______________ to ______________ purpose ______________'
    $lines += '  [Date/Time UTC] --- from ______________ to ______________ purpose ______________'
    $lines += ''

    $file = Join-Path $Script:Dirs['Collection'] 'chain_of_custody.txt'
    $lines | Out-File -FilePath $file -Encoding UTF8
}

function Write-CollectionCoverage {
    <#
        Records how this run was privileged so an analyst does not read a thin package
        as a quiet host. Written after collection so skipped-task counts are accurate.
    #>
    $skipped = @($Script:Manifest | Where-Object { $_.Status -eq 'SkippedNotElevated' })
    $profileName = 'Elevated'
    if (-not $Script:IsElevated) { $profileName = 'StandardUser' }
    $obj = [PSCustomObject]@{
        CoverageProfile        = $profileName
        Elevated               = $Script:IsElevated
        CollectionAccount      = "$env:USERDOMAIN\$env:USERNAME"
        RequireAdministrator   = [bool]$RequireAdministrator
        LoadUserHivesRequested = [bool]$LoadUserHives
        LoadUserHivesActive    = [bool]$Script:LoadUserHivesActive
        SkippedTaskCount       = $skipped.Count
        SkippedTasks           = @($skipped | ForEach-Object { $_.Task })
        WorthCollectingWithoutAdmin = @(
            'Current-user processes (image hash/signature only if the file is readable)',
            'TCP connections and listeners the token can enumerate',
            'HKCU autoruns, user Startup folder, PSReadLine history for accessible profiles',
            'Readable HKLM software/uninstall, OS identity, environment, hosts file',
            'Application / PowerShell / Defender operational logs when ACLs allow',
            'Browser extensions and executables under the current profile'
        )
        NotCollectedWithoutAdmin = @(
            'Security event log (parsed and EVTX export)',
            'Prefetch directory listing',
            'Volume shadow copy listing (vssadmin)',
            'auditpol / secedit exports',
            'Offline NTUSER.DAT for other users',
            'Other users'' AppData, recycle bins, and files the token cannot read'
        )
    }
    $path = Join-Path $Script:Dirs['Collection'] 'collection_coverage.json'
    $obj | ConvertTo-Json -Depth 5 | Out-File -FilePath $path -Encoding UTF8
    $Script:Data['collection_coverage'] = $obj
}

# ==============================================================================
#  SECTION 1 - SYSTEM
# ==============================================================================

function Invoke-SystemCollection {
    Write-Status 'Collecting system identity, configuration, and boot state' 'Step'

    Invoke-Collection -Category 'System' -Name 'os_info' -Description 'Operating system build, install date, uptime' -Script {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            Hostname          = $env:COMPUTERNAME
            Caption           = $os.Caption
            Version           = $os.Version
            BuildNumber       = $os.BuildNumber
            DisplayVersion    = (Get-RegValueSafe 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'DisplayVersion')
            UBR               = (Get-RegValueSafe 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'UBR')
            Architecture      = $os.OSArchitecture
            InstallDateUtc    = $os.InstallDate.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
            LastBootUtc       = $os.LastBootUpTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
            UptimeDays        = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 2)
            SerialNumber      = $os.SerialNumber
            RegisteredUser    = $os.RegisteredUser
            SystemDirectory   = $os.SystemDirectory
            Domain            = if ($cs) { $cs.Domain } else { '' }
            PartOfDomain      = if ($cs) { $cs.PartOfDomain } else { $null }
            Manufacturer      = if ($cs) { $cs.Manufacturer } else { '' }
            Model             = if ($cs) { $cs.Model } else { '' }
            TotalPhysicalMemGB = if ($cs) { [math]::Round($cs.TotalPhysicalMemory / 1GB, 2) } else { $null }
            BiosVersion       = if ($bios) { ($bios.BIOSVersion -join ' ') } else { '' }
            BiosSerial        = if ($bios) { $bios.SerialNumber } else { '' }
            TimeZone          = [System.TimeZoneInfo]::Local.Id
            UtcOffset         = [System.TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).ToString()
        }
    } | Out-Null

    Invoke-Collection -Category 'System' -Name 'time_sync' -Format 'Txt' -Description 'NTP/time source configuration (timestamp reliability)' -Script {
        $out = @()
        $out += '--- w32tm /query /status ---'
        $out += (& w32tm.exe /query /status 2>&1 | Out-String)
        $out += '--- w32tm /query /configuration ---'
        $out += (& w32tm.exe /query /configuration 2>&1 | Out-String)
        $out += '--- Time Service ---'
        $out += (Get-Service W32Time -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType | Out-String)
        $out
    } | Out-Null

    Invoke-Collection -Category 'System' -Name 'hotfixes' -Format 'Csv' -Description 'Installed updates and patch dates' -Script {
        Get-HotFix -ErrorAction Stop |
            Select-Object HotFixID, Description, InstalledBy, @{n = 'InstalledOn'; e = { if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') } else { '' } } } |
            Sort-Object InstalledOn -Descending
    } | Out-Null

    Invoke-Collection -Category 'System' -Name 'boot_and_firmware' -Description 'Secure Boot, TPM, BitLocker, boot configuration' -Script {
        $secureBoot = 'Unknown'
        try { $secureBoot = [string](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { $secureBoot = 'NotSupportedOrLegacyBIOS' }
        $tpm = $null
        try { $tpm = Get-CimInstance -Namespace 'root\cimv2\security\microsofttpm' -ClassName Win32_Tpm -ErrorAction Stop } catch { }
        $bde = @()
        try {
            $bde = Get-CimInstance -Namespace 'root\cimv2\security\microsoftvolumeencryption' -ClassName Win32_EncryptableVolume -ErrorAction Stop |
                Select-Object DriveLetter, ProtectionStatus, ConversionStatus, EncryptionMethod
        }
        catch { }
        [PSCustomObject]@{
            SecureBootEnabled = $secureBoot
            TpmPresent        = ($null -ne $tpm)
            TpmEnabled        = if ($tpm) { $tpm.IsEnabled_InitialValue } else { $null }
            TpmActivated      = if ($tpm) { $tpm.IsActivated_InitialValue } else { $null }
            TpmVersion        = if ($tpm) { $tpm.SpecVersion } else { '' }
            BitLockerVolumes  = $bde
            BcdOutput         = (& bcdedit.exe /enum 2>&1 | Out-String)
        }
    } | Out-Null

    Invoke-Collection -Category 'System' -Name 'disks_and_volumes' -Format 'Csv' -Description 'Logical volumes, free space, filesystem type' -Script {
        Get-CimInstance Win32_LogicalDisk -ErrorAction Stop | Select-Object DeviceID, DriveType, FileSystem, VolumeName,
        @{n = 'SizeGB'; e = { [math]::Round($_.Size / 1GB, 2) } },
        @{n = 'FreeGB'; e = { [math]::Round($_.FreeSpace / 1GB, 2) } }, VolumeSerialNumber
    } | Out-Null

    Invoke-Collection -Category 'System' -Name 'environment_variables' -Format 'Csv' -Description 'Process/machine environment variables' -Script {
        Get-ChildItem Env: | Select-Object Name, Value
    } | Out-Null

    Invoke-Collection -Category 'System' -Name 'system_restore_and_shadowcopies' -Format 'Txt' -Description 'Volume shadow copies (deletion is a ransomware indicator)' -RequiresElevation -Script {
        $out = @()
        $out += '--- vssadmin list shadows ---'
        $out += (& vssadmin.exe list shadows 2>&1 | Out-String)
        $out += '--- vssadmin list shadowstorage ---'
        $out += (& vssadmin.exe list shadowstorage 2>&1 | Out-String)
        $out
    } | Out-Null
}

# ==============================================================================
#  SECTION 2 - USERS AND ACCESS
# ==============================================================================

function Invoke-UserCollection {
    Write-Status 'Collecting accounts, groups, sessions, and access configuration' 'Step'

    Invoke-Collection -Category 'Users' -Name 'local_users' -Format 'Csv' -Description 'Local user accounts and password state' -Script {
        $users = @()
        try {
            $users = Get-LocalUser -ErrorAction Stop | Select-Object Name, Enabled, SID, Description,
            @{n = 'LastLogon'; e = { if ($_.LastLogon) { $_.LastLogon.ToString('yyyy-MM-dd HH:mm:ss') } else { 'Never' } } },
            @{n = 'PasswordLastSet'; e = { if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString('yyyy-MM-dd HH:mm:ss') } else { 'Never' } } },
            PasswordRequired, PasswordExpires, UserMayChangePassword,
            @{n = 'AccountExpires'; e = { if ($_.AccountExpires) { $_.AccountExpires.ToString('yyyy-MM-dd') } else { 'Never' } } }
        }
        catch {
            $users = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction Stop |
                Select-Object Name, @{n = 'Enabled'; e = { -not $_.Disabled } }, SID, Description,
                @{n = 'LastLogon'; e = { '' } }, @{n = 'PasswordLastSet'; e = { '' } },
                @{n = 'PasswordRequired'; e = { $_.PasswordRequired } },
                @{n = 'PasswordExpires'; e = { $_.PasswordExpires } },
                @{n = 'UserMayChangePassword'; e = { $_.PasswordChangeable } },
                @{n = 'AccountExpires'; e = { '' } }
        }
        $users
    } | Out-Null

    Invoke-Collection -Category 'Users' -Name 'local_group_membership' -Format 'Csv' -Description 'Members of every local group (privilege mapping)' -Script {
        $rows = @()
        try {
            foreach ($g in (Get-LocalGroup -ErrorAction Stop)) {
                $members = @()
                try { $members = Get-LocalGroupMember -Group $g.Name -ErrorAction Stop } catch { }
                if ($members.Count -eq 0) {
                    $rows += [PSCustomObject]@{ Group = $g.Name; Member = '(none)'; ObjectClass = ''; PrincipalSource = ''; SID = '' }
                }
                foreach ($m in $members) {
                    $rows += [PSCustomObject]@{
                        Group           = $g.Name
                        Member          = $m.Name
                        ObjectClass     = [string]$m.ObjectClass
                        PrincipalSource = [string]$m.PrincipalSource
                        SID             = [string]$m.SID
                    }
                }
            }
        }
        catch {
            $rows += [PSCustomObject]@{ Group = 'ERROR'; Member = $_.Exception.Message; ObjectClass = ''; PrincipalSource = ''; SID = '' }
        }
        $rows
    } | Out-Null

    Invoke-Collection -Category 'Users' -Name 'user_profiles' -Format 'Csv' -Description 'Profiles present on disk with SID mapping' -Script {
        Get-UserProfileList
    } | Out-Null

    Invoke-Collection -Category 'Users' -Name 'logged_on_sessions' -Format 'Txt' -Description 'Current interactive and remote sessions' -Script {
        $out = @()
        $out += '--- query user ---'
        $out += (& query.exe user 2>&1 | Out-String)
        $out += '--- query session ---'
        $out += (& query.exe session 2>&1 | Out-String)
        $out += '--- Win32_LogonSession (interactive/remote) ---'
        try {
            $out += (Get-CimInstance Win32_LogonSession -ErrorAction Stop |
                    Select-Object LogonId, LogonType, AuthenticationPackage,
                    @{n = 'StartTimeUtc'; e = { if ($_.StartTime) { $_.StartTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } else { '' } } } |
                    Out-String -Width 300)
        }
        catch { $out += "Error: $($_.Exception.Message)" }
        $out += '--- Logged on users (Win32_LoggedOnUser) ---'
        try {
            $out += (Get-CimInstance Win32_LoggedOnUser -ErrorAction Stop | Select-Object -ExpandProperty Antecedent |
                    Select-Object Domain, Name -Unique | Out-String)
        }
        catch { }
        $out
    } | Out-Null

    Invoke-Collection -Category 'Users' -Name 'password_and_lockout_policy' -Format 'Txt' -Description 'Local account policy (net accounts)' -Script {
        & net.exe accounts 2>&1 | Out-String
    } | Out-Null

    Invoke-Collection -Category 'Users' -Name 'user_rights_and_secpol' -Format 'Txt' -Description 'Security policy export (secedit)' -RequiresElevation -Script {
        $tmp = Join-Path $env:TEMP ("winfoton_secpol_{0}.inf" -f ([guid]::NewGuid().ToString('N')))
        $null = & secedit.exe /export /cfg "$tmp" /quiet 2>&1
        if (Test-Path -LiteralPath $tmp) {
            $content = Get-Content -LiteralPath $tmp -Raw -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
            $content
        }
        else { 'secedit export unavailable (requires elevation).' }
    } | Out-Null

    Invoke-Collection -Category 'Users' -Name 'rdp_configuration' -Description 'Remote Desktop enablement and NLA state' -Script {
        $rdpUsers = 'unavailable'
        try { $rdpUsers = ((Get-LocalGroupMember -Group 'Remote Desktop Users' -ErrorAction Stop | Select-Object -ExpandProperty Name) -join '; ') } catch { }
        $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        $rdpTcp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        [PSCustomObject]@{
            DenyTSConnections    = (Get-RegValueSafe $ts 'fDenyTSConnections')
            RdpEnabled           = ((Get-RegValueSafe $ts 'fDenyTSConnections') -eq 0)
            UserAuthentication   = (Get-RegValueSafe $rdpTcp 'UserAuthentication')
            SecurityLayer        = (Get-RegValueSafe $rdpTcp 'SecurityLayer')
            PortNumber           = (Get-RegValueSafe $rdpTcp 'PortNumber')
            AllowRemoteRPC       = (Get-RegValueSafe 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'AllowRemoteRPC')
            RemoteDesktopUsers   = $rdpUsers
            ShadowSetting        = (Get-RegValueSafe $rdpTcp 'Shadow')
        }
    } | Out-Null

    Invoke-Collection -Category 'Users' -Name 'stored_credentials_and_trusts' -Format 'Txt' -Description 'Credential manager entries and domain trust state' -Script {
        $out = @()
        $out += '--- cmdkey /list ---'
        $out += (& cmdkey.exe /list 2>&1 | Out-String)
        $out += '--- nltest /domain_trusts ---'
        $out += (& nltest.exe /domain_trusts 2>&1 | Out-String)
        $out += '--- Vault directories present ---'
        foreach ($p in @("$env:LOCALAPPDATA\Microsoft\Vault", "$env:APPDATA\Microsoft\Credentials", "$env:LOCALAPPDATA\Microsoft\Credentials")) {
            if (Test-Path -LiteralPath $p) {
                $out += "PATH: $p"
                $out += (Get-ChildItem -LiteralPath $p -Force -Recurse -ErrorAction SilentlyContinue |
                        Select-Object FullName, Length, LastWriteTimeUtc | Out-String -Width 300)
            }
        }
        $out
    } | Out-Null
}

# ==============================================================================
#  SECTION 3 - PROCESSES AND VOLATILE STATE
# ==============================================================================

function Invoke-ProcessCollection {
    Write-Status 'Collecting running processes, modules, and volatile state' 'Step'

    Invoke-Collection -Category 'Processes' -Name 'running_processes' -Format 'Csv' -Description 'Processes with path, command line, parent, hash, signature' -Script {
        $procList = @{}
        try {
            foreach ($p in (Get-CimInstance Win32_Process -ErrorAction Stop)) { $procList[[int]$p.ProcessId] = $p }
        }
        catch { }

        $owners = @{}
        try {
            foreach ($p in $procList.Values) {
                try {
                    $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
                    if ($o -and $o.User) { $owners[[int]$p.ProcessId] = "$($o.Domain)\$($o.User)" }
                }
                catch { }
            }
        }
        catch { }

        $rows = @()
        foreach ($p in ($procList.Values | Sort-Object ProcessId)) {
            $path = $p.ExecutablePath
            $sig = Get-SignatureInfo -Path $path
            $parentName = ''
            if ($procList.ContainsKey([int]$p.ParentProcessId)) { $parentName = $procList[[int]$p.ParentProcessId].Name }
            $rows += [PSCustomObject]@{
                PID             = $p.ProcessId
                Name            = $p.Name
                ParentPID       = $p.ParentProcessId
                ParentName      = $parentName
                Owner           = if ($owners.ContainsKey([int]$p.ProcessId)) { $owners[[int]$p.ProcessId] } else { '' }
                Path            = $path
                CommandLine     = $p.CommandLine
                CreationTimeUtc = if ($p.CreationDate) { $p.CreationDate.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
                SessionId       = $p.SessionId
                SignatureStatus = $sig.Status
                Signer          = $sig.Signer
                IsOSBinary      = $sig.IsOSBinary
                SHA256          = (Get-SafeHash -Path $path)
                UserWritablePath = (Test-UserWritablePath -Path $path)
                SuspiciousCmdHits = (Test-SuspiciousCommand -Text $p.CommandLine)
            }
        }
        $rows
    } | Out-Null

    Invoke-Collection -Category 'Processes' -Name 'process_tree' -Format 'Txt' -Description 'Parent/child process tree rendering' -Script {
        $procs = @{}
        try { foreach ($p in (Get-CimInstance Win32_Process -ErrorAction Stop)) { $procs[[int]$p.ProcessId] = $p } } catch { return 'Unavailable' }
        $children = @{}
        foreach ($p in $procs.Values) {
            $ppid = [int]$p.ParentProcessId
            if (-not $children.ContainsKey($ppid)) { $children[$ppid] = @() }
            $children[$ppid] += $p
        }
        $lines = New-Object System.Collections.ArrayList
        function Write-Branch {
            param($ProcId, $Depth, $ChildMap, $ProcMap, $Sink)
            if ($Depth -gt 12) { return }
            foreach ($child in ($ChildMap[$ProcId] | Sort-Object ProcessId)) {
                $indent = '  ' * $Depth
                $null = $Sink.Add(("{0}[{1}] {2}  {3}" -f $indent, $child.ProcessId, $child.Name, $child.ExecutablePath))
                if ($ChildMap.ContainsKey([int]$child.ProcessId)) {
                    Write-Branch -ProcId ([int]$child.ProcessId) -Depth ($Depth + 1) -ChildMap $ChildMap -ProcMap $ProcMap -Sink $Sink
                }
            }
        }
        foreach ($rootPid in ($children.Keys | Sort-Object)) {
            if (-not $procs.ContainsKey($rootPid)) {
                $null = $lines.Add("[$rootPid] (parent no longer running)")
                Write-Branch -ProcId $rootPid -Depth 1 -ChildMap $children -ProcMap $procs -Sink $lines
            }
        }
        $null = $lines.Add('')
        $null = $lines.Add('--- Tree from System (PID 4) ---')
        Write-Branch -ProcId 4 -Depth 1 -ChildMap $children -ProcMap $procs -Sink $lines
        $lines
    } | Out-Null

    Invoke-Collection -Category 'Processes' -Name 'loaded_modules_nonstandard' -Format 'Csv' -Description 'Loaded DLLs outside System32/Program Files' -Script {
        $rows = @()
        foreach ($proc in (Get-Process -ErrorAction SilentlyContinue)) {
            try {
                foreach ($m in $proc.Modules) {
                    $fn = $m.FileName
                    if ($fn -match '\\Windows\\System32\\' -or $fn -match '\\Windows\\SysWOW64\\' -or
                        $fn -match '\\Windows\\WinSxS\\' -or $fn -match '\\Program Files') { continue }
                    $rows += [PSCustomObject]@{
                        ProcessName = $proc.ProcessName
                        PID         = $proc.Id
                        Module      = $m.ModuleName
                        Path        = $fn
                        Company     = $m.FileVersionInfo.CompanyName
                        SHA256      = (Get-SafeHash -Path $fn)
                    }
                }
            }
            catch { }
        }
        $rows | Sort-Object Path -Unique
    } | Out-Null

    Invoke-Collection -Category 'Processes' -Name 'powershell_console_history' -Format 'Csv' -Description 'PSReadLine history for every profile (analyst-critical)' -Script {
        $rows = @()
        foreach ($userProfile in (Get-UserProfileList)) {
            $hist = Join-Path $userProfile.ProfilePath 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
            if (-not (Test-Path -LiteralPath $hist)) { continue }
            $lineNo = 0
            try {
                foreach ($line in (Get-Content -LiteralPath $hist -ErrorAction Stop)) {
                    $lineNo++
                    $rows += [PSCustomObject]@{
                        User           = $userProfile.UserName
                        HistoryFile    = $hist
                        LineNumber     = $lineNo
                        Command        = $line
                        SuspiciousHits = (Test-SuspiciousCommand -Text $line)
                    }
                }
            }
            catch { }
        }
        $rows
    } | Out-Null

    Invoke-Collection -Category 'Processes' -Name 'clipboard_and_recent_docs' -Format 'Txt' -Description 'Recent document MRU keys' -Script {
        $out = @()
        foreach ($root in (Get-UserHiveRoots)) {
            $mru = "$($root.Root)\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
            if (Test-Path -LiteralPath $mru) {
                $out += "=== RecentDocs for $($root.UserName) ==="
                $out += (Get-ChildItem -LiteralPath $mru -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Out-String)
            }
        }
        if ($out.Count -eq 0) { $out += 'No RecentDocs keys accessible.' }
        $out
    } | Out-Null
}

# ==============================================================================
#  SECTION 4 - NETWORK
# ==============================================================================

function Invoke-NetworkCollection {
    Write-Status 'Collecting network configuration, connections, and DNS state' 'Step'

    Invoke-Collection -Category 'Network' -Name 'active_connections' -Format 'Csv' -Description 'TCP connections mapped to owning process' -Script {
        $procs = @{}
        try { foreach ($p in (Get-CimInstance Win32_Process -ErrorAction Stop)) { $procs[[int]$p.ProcessId] = $p } } catch { }
        $rows = @()
        try {
            foreach ($c in (Get-NetTCPConnection -ErrorAction Stop)) {
                $proc = $null
                if ($procs.ContainsKey([int]$c.OwningProcess)) { $proc = $procs[[int]$c.OwningProcess] }
                $remote = [string]$c.RemoteAddress
                $isExternal = $true
                if ($remote -match '^(127\.|0\.0\.0\.0|::1|::$|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|fe80:|ff00:)') { $isExternal = $false }
                $rows += [PSCustomObject]@{
                    LocalAddress  = [string]$c.LocalAddress
                    LocalPort     = $c.LocalPort
                    RemoteAddress = $remote
                    RemotePort    = $c.RemotePort
                    State         = [string]$c.State
                    OwningPID     = $c.OwningProcess
                    ProcessName   = if ($proc) { $proc.Name } else { '' }
                    ProcessPath   = if ($proc) { $proc.ExecutablePath } else { '' }
                    CommandLine   = if ($proc) { $proc.CommandLine } else { '' }
                    RemoteIsExternal = $isExternal
                    UserWritablePath = if ($proc) { (Test-UserWritablePath -Path $proc.ExecutablePath) } else { $false }
                    CreationTimeUtc = if ($c.CreationTime) { $c.CreationTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
                }
            }
        }
        catch {
            $rows += [PSCustomObject]@{ LocalAddress = 'ERROR'; LocalPort = 0; RemoteAddress = $_.Exception.Message; RemotePort = 0; State = ''; OwningPID = 0; ProcessName = ''; ProcessPath = ''; CommandLine = ''; RemoteIsExternal = $false; UserWritablePath = $false; CreationTimeUtc = '' }
        }
        $rows
    } | Out-Null

    Invoke-Collection -Category 'Network' -Name 'listening_ports' -Format 'Csv' -Description 'Listening TCP/UDP endpoints with owning process' -Script {
        $procs = @{}
        try { foreach ($p in (Get-CimInstance Win32_Process -ErrorAction Stop)) { $procs[[int]$p.ProcessId] = $p } } catch { }
        $rows = @()
        try {
            foreach ($c in (Get-NetTCPConnection -State Listen -ErrorAction Stop)) {
                $proc = $null
                if ($procs.ContainsKey([int]$c.OwningProcess)) { $proc = $procs[[int]$c.OwningProcess] }
                $rows += [PSCustomObject]@{
                    Protocol = 'TCP'; LocalAddress = [string]$c.LocalAddress; LocalPort = $c.LocalPort
                    OwningPID = $c.OwningProcess
                    ProcessName = if ($proc) { $proc.Name } else { '' }
                    ProcessPath = if ($proc) { $proc.ExecutablePath } else { '' }
                }
            }
        }
        catch { }
        try {
            foreach ($u in (Get-NetUDPEndpoint -ErrorAction Stop)) {
                $proc = $null
                if ($procs.ContainsKey([int]$u.OwningProcess)) { $proc = $procs[[int]$u.OwningProcess] }
                $rows += [PSCustomObject]@{
                    Protocol = 'UDP'; LocalAddress = [string]$u.LocalAddress; LocalPort = $u.LocalPort
                    OwningPID = $u.OwningProcess
                    ProcessName = if ($proc) { $proc.Name } else { '' }
                    ProcessPath = if ($proc) { $proc.ExecutablePath } else { '' }
                }
            }
        }
        catch { }
        $rows | Sort-Object Protocol, LocalPort
    } | Out-Null

    Invoke-Collection -Category 'Network' -Name 'ip_configuration' -Format 'Txt' -Description 'Adapters, addresses, routes, ARP cache' -Script {
        $out = @()
        $out += '--- ipconfig /all ---'
        $out += (& ipconfig.exe /all 2>&1 | Out-String)
        $out += '--- route print ---'
        $out += (& route.exe print 2>&1 | Out-String)
        $out += '--- arp -a ---'
        $out += (& arp.exe -a 2>&1 | Out-String)
        $out += '--- netsh interface show interface ---'
        $out += (& netsh.exe interface show interface 2>&1 | Out-String)
        $out
    } | Out-Null

    Invoke-Collection -Category 'Network' -Name 'dns_cache' -Format 'Csv' -Description 'Resolved DNS entries currently cached' -Script {
        try {
            Get-DnsClientCache -ErrorAction Stop | Select-Object Entry, Name, Type, Status, TimeToLive, Data
        }
        catch {
            (& ipconfig.exe /displaydns 2>&1 | Out-String)
        }
    } | Out-Null

    Invoke-Collection -Category 'Network' -Name 'dns_client_servers' -Format 'Csv' -Description 'Configured DNS servers per interface' -Script {
        Get-DnsClientServerAddress -ErrorAction Stop |
            Select-Object InterfaceAlias, InterfaceIndex, AddressFamily, @{n = 'ServerAddresses'; e = { $_.ServerAddresses -join ', ' } }
    } | Out-Null

    Invoke-Collection -Category 'Network' -Name 'hosts_file' -Format 'Txt' -Description 'hosts file contents (redirection indicator)' -Script {
        $p = "$env:SystemRoot\System32\drivers\etc\hosts"
        if (Test-Path -LiteralPath $p) { Get-Content -LiteralPath $p -ErrorAction Stop } else { 'hosts file not found' }
    } | Out-Null

    Invoke-Collection -Category 'Network' -Name 'firewall_profiles' -Format 'Csv' -Description 'Firewall profile enablement and default actions' -Script {
        Get-NetFirewallProfile -ErrorAction Stop |
            Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked, LogFileName
    } | Out-Null

    Invoke-Collection -Category 'Network' -Name 'firewall_rules_inbound_allow' -Format 'Csv' -Description 'Enabled inbound allow rules (exposure surface)' -Script {
        $rows = @()
        try {
            $filters = @{}
            foreach ($pf in (Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)) {
                $filters[$pf.InstanceID] = $pf
            }
            foreach ($r in (Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop)) {
                $ports = ''
                $proto = ''
                if ($filters.ContainsKey($r.InstanceID)) {
                    $ports = ($filters[$r.InstanceID].LocalPort -join ',')
                    $proto = $filters[$r.InstanceID].Protocol
                }
                $rows += [PSCustomObject]@{
                    Name        = $r.DisplayName
                    Profile     = [string]$r.Profile
                    Protocol    = $proto
                    LocalPort   = $ports
                    Program     = ''
                    Group       = $r.DisplayGroup
                    Description = $r.Description
                }
            }
        }
        catch { }
        $rows
    } | Out-Null

    Invoke-Collection -Category 'Network' -Name 'shares_and_sessions' -Format 'Txt' -Description 'SMB shares, permissions, open sessions and files' -Script {
        $out = @()
        $out += '--- net share ---'
        $out += (& net.exe share 2>&1 | Out-String)
        $out += '--- Get-SmbShare ---'
        try { $out += (Get-SmbShare -ErrorAction Stop | Select-Object Name, Path, Description, ShareType | Out-String -Width 300) } catch { }
        $out += '--- Get-SmbShareAccess ---'
        try {
            foreach ($s in (Get-SmbShare -ErrorAction Stop)) {
                $out += (Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue | Out-String -Width 300)
            }
        }
        catch { }
        $out += '--- net session ---'
        $out += (& net.exe session 2>&1 | Out-String)
        $out += '--- Get-SmbOpenFile ---'
        try { $out += (Get-SmbOpenFile -ErrorAction Stop | Select-Object ClientUserName, ClientComputerName, Path | Out-String -Width 300) } catch { }
        $out += '--- net use ---'
        $out += (& net.exe use 2>&1 | Out-String)
        $out
    } | Out-Null

    Invoke-Collection -Category 'Network' -Name 'proxy_and_winhttp' -Format 'Txt' -Description 'User and system proxy configuration' -Script {
        $out = @()
        $out += '--- netsh winhttp show proxy ---'
        $out += (& netsh.exe winhttp show proxy 2>&1 | Out-String)
        foreach ($root in (Get-UserHiveRoots)) {
            $key = "$($root.Root)\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            if (Test-Path -LiteralPath $key) {
                $out += "=== Internet Settings for $($root.UserName) ==="
                $out += (Get-RegValueList -Path $key | Where-Object { $_.Name -match 'Proxy|AutoConfig' } | Out-String -Width 300)
            }
        }
        $out
    } | Out-Null

    Invoke-Collection -Category 'Network' -Name 'wifi_profiles' -Format 'Txt' -Description 'Saved wireless profiles' -Script {
        & netsh.exe wlan show profiles 2>&1 | Out-String
    } | Out-Null
}

# ==============================================================================
#  SECTION 5 - PERSISTENCE
# ==============================================================================

function Invoke-PersistenceCollection {
    Write-Status 'Collecting persistence mechanisms (autoruns, tasks, services, WMI)' 'Step'

    Invoke-Collection -Category 'Persistence' -Name 'autorun_registry_keys' -Format 'Csv' -Description 'Run/RunOnce and policy autostart keys, machine and per-user' -Script {
        $rows = @()
        $machineKeys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
            'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components'
        )
        foreach ($k in $machineKeys) {
            foreach ($v in (Get-RegValueList -Path $k)) {
                $rows += [PSCustomObject]@{
                    Scope = 'Machine'; User = 'N/A'; Key = $v.Key; ValueName = $v.Name; Command = $v.Value
                    SuspiciousHits = (Test-SuspiciousCommand -Text $v.Value)
                    UserWritableTarget = (Test-UserWritablePath -Path $v.Value)
                }
            }
        }
        $userSubKeys = @(
            'Software\Microsoft\Windows\CurrentVersion\Run',
            'Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'Software\Microsoft\Windows\CurrentVersion\RunServices',
            'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
            'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
        )
        foreach ($root in (Get-UserHiveRoots)) {
            foreach ($sub in $userSubKeys) {
                $full = Join-Path $root.Root $sub
                foreach ($v in (Get-RegValueList -Path $full)) {
                    $rows += [PSCustomObject]@{
                        Scope = 'User'; User = $root.UserName; Key = $v.Key; ValueName = $v.Name; Command = $v.Value
                        SuspiciousHits = (Test-SuspiciousCommand -Text $v.Value)
                        UserWritableTarget = (Test-UserWritablePath -Path $v.Value)
                    }
                }
            }
        }
        $rows
    } | Out-Null

    Invoke-Collection -Category 'Persistence' -Name 'startup_folder_items' -Format 'Csv' -Description 'Files in machine and per-user Startup folders' -Script {
        $rows = @()
        $paths = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
        foreach ($userProfile in (Get-UserProfileList)) {
            $paths += (Join-Path $userProfile.ProfilePath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')
        }
        foreach ($p in $paths) {
            if (-not (Test-PathAccessible -Path $p)) { continue }
            foreach ($f in (Get-ChildItem -LiteralPath $p -Force -ErrorAction SilentlyContinue)) {
                if ($f.Name -eq 'desktop.ini') { continue }
                $sig = Get-SignatureInfo -Path $f.FullName
                $rows += [PSCustomObject]@{
                    StartupFolder   = $p
                    Name            = $f.Name
                    FullName        = $f.FullName
                    SizeBytes       = $f.Length
                    CreatedUtc      = $f.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                    ModifiedUtc     = $f.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                    SignatureStatus = $sig.Status
                    SHA256          = (Get-SafeHash -Path $f.FullName)
                }
            }
        }
        $rows
    } | Out-Null

    Invoke-Collection -Category 'Persistence' -Name 'scheduled_tasks' -Format 'Csv' -Description 'Scheduled tasks with actions, principals, and last run state' -Script {
        $rows = @()
        try {
            foreach ($t in (Get-ScheduledTask -ErrorAction Stop)) {
                $info = $null
                try { $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop } catch { }
                $actions = @()
                foreach ($a in $t.Actions) {
                    if ($a.Execute) { $actions += ("{0} {1}" -f $a.Execute, $a.Arguments) }
                    elseif ($a.ClassId) { $actions += ("COM:{0}" -f $a.ClassId) }
                }
                $actionText = ($actions -join ' | ')
                $exePath = ''
                if ($t.Actions -and $t.Actions[0].Execute) {
                    $exePath = [Environment]::ExpandEnvironmentVariables($t.Actions[0].Execute.Trim('"'))
                }
                $triggers = @()
                foreach ($tr in $t.Triggers) { $triggers += $tr.CimClass.CimClassName }
                $rows += [PSCustomObject]@{
                    TaskPath       = $t.TaskPath
                    TaskName       = $t.TaskName
                    State          = [string]$t.State
                    Author         = $t.Author
                    RunAsUser      = $t.Principal.UserId
                    RunLevel       = [string]$t.Principal.RunLevel
                    Triggers       = ($triggers -join ', ')
                    Actions        = $actionText
                    LastRunTime    = if ($info) { [string]$info.LastRunTime } else { '' }
                    LastResult     = if ($info) { $info.LastTaskResult } else { '' }
                    NextRunTime    = if ($info) { [string]$info.NextRunTime } else { '' }
                    Description    = $t.Description
                    SuspiciousHits = (Test-SuspiciousCommand -Text $actionText)
                    UserWritableTarget = (Test-UserWritablePath -Path $exePath)
                    SHA256         = (Get-SafeHash -Path $exePath)
                }
            }
        }
        catch {
            $rows += [PSCustomObject]@{ TaskPath = 'ERROR'; TaskName = $_.Exception.Message; State = ''; Author = ''; RunAsUser = ''; RunLevel = ''; Triggers = ''; Actions = ''; LastRunTime = ''; LastResult = ''; NextRunTime = ''; Description = ''; SuspiciousHits = ''; UserWritableTarget = $false; SHA256 = '' }
        }
        $rows
    } | Out-Null

    Invoke-Collection -Category 'Persistence' -Name 'scheduled_task_files' -Format 'Csv' -Description 'Task XML files on disk with timestamps (creation-time pivot)' -Script {
        $base = "$env:SystemRoot\System32\Tasks"
        if (-not (Test-Path -LiteralPath $base)) { return @() }
        Get-ChildItem -LiteralPath $base -Recurse -File -Force -ErrorAction SilentlyContinue |
            Select-Object FullName,
            @{n = 'CreatedUtc'; e = { $_.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss') } },
            @{n = 'ModifiedUtc'; e = { $_.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss') } },
            Length |
            Sort-Object ModifiedUtc -Descending
    } | Out-Null

    Invoke-Collection -Category 'Persistence' -Name 'services' -Format 'Csv' -Description 'All services with binary path, signature, hash, unquoted-path flag' -Script {
        $rows = @()
        foreach ($s in (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
            $pathName = $s.PathName
            $exe = ''
            if ($pathName) {
                if ($pathName.StartsWith('"')) { $exe = $pathName.Split('"')[1] }
                else {
                    $m = [regex]::Match($pathName, '^(.*?\.exe)', 'IgnoreCase')
                    if ($m.Success) { $exe = $m.Groups[1].Value } else { $exe = $pathName.Split(' ')[0] }
                }
                $exe = [Environment]::ExpandEnvironmentVariables($exe)
            }
            $unquoted = $false
            if ($pathName -and -not $pathName.StartsWith('"') -and $pathName -match ' ' -and $exe -match ' ') { $unquoted = $true }
            $sig = Get-SignatureInfo -Path $exe
            $rows += [PSCustomObject]@{
                Name            = $s.Name
                DisplayName     = $s.DisplayName
                State           = $s.State
                StartMode       = $s.StartMode
                StartName       = $s.StartName
                ProcessId       = $s.ProcessId
                PathName        = $pathName
                ResolvedExe     = $exe
                ServiceType     = $s.ServiceType
                UnquotedPath    = $unquoted
                UserWritablePath = (Test-UserWritablePath -Path $exe)
                SignatureStatus = $sig.Status
                Signer          = $sig.Signer
                SHA256          = (Get-SafeHash -Path $exe)
                Description     = $s.Description
            }
        }
        $rows | Sort-Object Name
    } | Out-Null

    Invoke-Collection -Category 'Persistence' -Name 'wmi_event_subscriptions' -Format 'Txt' -Description 'WMI filters, consumers, and bindings (fileless persistence)' -Script {
        $out = @()
        foreach ($class in @('__EventFilter', '__EventConsumer', '__FilterToConsumerBinding')) {
            $out += "=== $class ==="
            try {
                $items = Get-CimInstance -Namespace 'root\subscription' -ClassName $class -ErrorAction Stop
                if ($items) { $out += ($items | Format-List * | Out-String -Width 400) }
                else { $out += '(none)' }
            }
            catch { $out += "Error: $($_.Exception.Message)" }
        }
        $out
    } | Out-Null

    Invoke-Collection -Category 'Persistence' -Name 'winlogon_lsa_and_dll_hijacks' -Format 'Csv' -Description 'Winlogon Shell/Userinit, AppInit_DLLs, LSA packages, IFEO debuggers' -Script {
        $rows = @()
        $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        foreach ($n in @('Shell', 'Userinit', 'Taskman', 'AppSetup', 'GinaDLL', 'UserInitMprLogonScript')) {
            $val = Get-RegValueSafe $winlogon $n
            if ($val) { $rows += [PSCustomObject]@{ Mechanism = 'Winlogon'; Location = $winlogon; Name = $n; Value = [string]$val } }
        }
        foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
            foreach ($n in @('AppInit_DLLs', 'LoadAppInit_DLLs', 'Load', 'Run', 'IconServiceLib')) {
                $val = Get-RegValueSafe $k $n
                if ($null -ne $val -and "$val" -ne '') { $rows += [PSCustomObject]@{ Mechanism = 'AppInit/Windows'; Location = $k; Name = $n; Value = [string]$val } }
            }
        }
        $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        foreach ($n in @('Authentication Packages', 'Notification Packages', 'Security Packages')) {
            $val = Get-RegValueSafe $lsa $n
            if ($val) { $rows += [PSCustomObject]@{ Mechanism = 'LSA Package'; Location = $lsa; Name = $n; Value = ($val -join ', ') } }
        }
        $val = Get-RegValueSafe 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders' 'SecurityProviders'
        if ($val) { $rows += [PSCustomObject]@{ Mechanism = 'SecurityProviders'; Location = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders'; Name = 'SecurityProviders'; Value = [string]$val } }

        $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        if (Test-Path -LiteralPath $ifeo) {
            foreach ($sub in (Get-ChildItem -LiteralPath $ifeo -ErrorAction SilentlyContinue)) {
                foreach ($n in @('Debugger', 'GlobalFlag', 'MonitorProcess')) {
                    $v = Get-RegValueSafe $sub.PSPath $n
                    if ($v) { $rows += [PSCustomObject]@{ Mechanism = 'IFEO'; Location = $sub.Name; Name = $n; Value = [string]$v } }
                }
            }
        }
        foreach ($n in @('AppCertDlls')) {
            foreach ($v in (Get-RegValueList -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls')) {
                $rows += [PSCustomObject]@{ Mechanism = 'AppCertDlls'; Location = $v.Key; Name = $v.Name; Value = $v.Value }
            }
        }
        foreach ($v in (Get-RegValueList -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager')) {
            if ($v.Name -in @('BootExecute', 'SetupExecute', 'Execute', 'S0InitialCommand', 'PendingFileRenameOperations')) {
                $rows += [PSCustomObject]@{ Mechanism = 'SessionManager'; Location = $v.Key; Name = $v.Name; Value = $v.Value }
            }
        }
        foreach ($v in (Get-RegValueList -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors')) {
            $rows += [PSCustomObject]@{ Mechanism = 'PrintMonitor'; Location = $v.Key; Name = $v.Name; Value = $v.Value }
        }
        foreach ($v in (Get-RegValueList -Path 'HKLM:\SOFTWARE\Microsoft\Netsh')) {
            $rows += [PSCustomObject]@{ Mechanism = 'NetshHelper'; Location = $v.Key; Name = $v.Name; Value = $v.Value }
        }
        foreach ($root in (Get-UserHiveRoots)) {
            $env_ = Join-Path $root.Root 'Environment'
            foreach ($n in @('UserInitMprLogonScript')) {
                $v = Get-RegValueSafe $env_ $n
                if ($v) { $rows += [PSCustomObject]@{ Mechanism = 'LogonScript'; Location = "$($root.UserName): $env_"; Name = $n; Value = [string]$v } }
            }
        }
        $rows
    } | Out-Null

    Invoke-Collection -Category 'Persistence' -Name 'accessibility_binary_integrity' -Format 'Csv' -Description 'Sticky-keys style backdoor check on accessibility binaries' -Script {
        $targets = @('sethc.exe', 'utilman.exe', 'osk.exe', 'Magnify.exe', 'Narrator.exe', 'DisplaySwitch.exe', 'AtBroker.exe')
        $rows = @()
        foreach ($t in $targets) {
            $p = Join-Path "$env:SystemRoot\System32" $t
            if (-not (Test-Path -LiteralPath $p)) { continue }
            $item = Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
            $sig = Get-SignatureInfo -Path $p
            $ifeoDebugger = Get-RegValueSafe ("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$t") 'Debugger'
            $rows += [PSCustomObject]@{
                Binary          = $t
                Path            = $p
                SizeBytes       = $item.Length
                ModifiedUtc     = $item.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                SignatureStatus = $sig.Status
                IsOSBinary      = $sig.IsOSBinary
                IFEODebugger    = [string]$ifeoDebugger
                SHA256          = (Get-SafeHash -Path $p)
            }
        }
        $rows
    } | Out-Null

    Invoke-Collection -Category 'Persistence' -Name 'com_hijack_candidates' -Format 'Csv' -Description 'Per-user COM CLSID overrides pointing to user-writable DLLs' -Script {
        $rows = @()
        foreach ($root in (Get-UserHiveRoots)) {
            $clsidRoot = Join-Path $root.Root 'Software\Classes\CLSID'
            if (-not (Test-Path -LiteralPath $clsidRoot)) { continue }
            foreach ($clsid in (Get-ChildItem -LiteralPath $clsidRoot -ErrorAction SilentlyContinue)) {
                foreach ($server in @('InprocServer32', 'LocalServer32', 'InprocHandler32')) {
                    $sp = Join-Path $clsid.PSPath $server
                    if (-not (Test-Path -LiteralPath $sp)) { continue }
                    $default = Get-RegValueSafe $sp '(default)'
                    if (-not $default) { continue }
                    $rows += [PSCustomObject]@{
                        User        = $root.UserName
                        CLSID       = (Split-Path $clsid.Name -Leaf)
                        ServerType  = $server
                        Target      = [string]$default
                        UserWritableTarget = (Test-UserWritablePath -Path ([string]$default))
                    }
                }
            }
        }
        $rows
    } | Out-Null

    Invoke-Collection -Category 'Persistence' -Name 'bits_jobs' -Format 'Txt' -Description 'Background Intelligent Transfer jobs (download persistence)' -Script {
        $out = @()
        try {
            $jobs = Get-BitsTransfer -AllUsers -ErrorAction Stop
            if ($jobs) { $out += ($jobs | Select-Object JobId, DisplayName, JobState, OwnerAccount, TransferType, CreationTime, FileList | Format-List | Out-String -Width 400) }
            else { $out += '(no BITS jobs)' }
        }
        catch { $out += "Get-BitsTransfer unavailable: $($_.Exception.Message)" }
        $out += '--- bitsadmin /list /allusers /verbose ---'
        $out += (& bitsadmin.exe /list /allusers /verbose 2>&1 | Out-String)
        $out
    } | Out-Null

    Invoke-Collection -Category 'Persistence' -Name 'office_addins_and_templates' -Format 'Csv' -Description 'Office add-ins and startup template locations' -Script {
        $rows = @()
        foreach ($root in (Get-UserHiveRoots)) {
            $base = Join-Path $root.Root 'Software\Microsoft\Office'
            if (-not (Test-Path -LiteralPath $base)) { continue }
            foreach ($addin in (Get-ChildItem -LiteralPath $base -Recurse -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -match 'Addins|Resiliency|Security\\Trusted Locations' })) {
                foreach ($v in (Get-RegValueList -Path $addin.PSPath)) {
                    $rows += [PSCustomObject]@{ User = $root.UserName; Key = $v.Key; Name = $v.Name; Value = $v.Value }
                }
            }
        }
        foreach ($userProfile in (Get-UserProfileList)) {
            $startup = Join-Path $userProfile.ProfilePath 'AppData\Roaming\Microsoft\Word\STARTUP'
            if (Test-Path -LiteralPath $startup) {
                foreach ($f in (Get-ChildItem -LiteralPath $startup -Force -ErrorAction SilentlyContinue)) {
                    $rows += [PSCustomObject]@{ User = $userProfile.UserName; Key = 'Word STARTUP folder'; Name = $f.Name; Value = $f.FullName }
                }
            }
        }
        $rows
    } | Out-Null
}

# ==============================================================================
#  SECTION 6 - SECURITY POSTURE
# ==============================================================================

function Invoke-SecurityCollection {
    Write-Status 'Collecting security posture, AV state, logging and hardening configuration' 'Step'

    Invoke-Collection -Category 'Security' -Name 'defender_status' -Description 'Microsoft Defender engine, signature, and protection state' -Script {
        $s = Get-MpComputerStatus -ErrorAction Stop
        [PSCustomObject]@{
            AMServiceEnabled            = $s.AMServiceEnabled
            AntispywareEnabled          = $s.AntispywareEnabled
            AntivirusEnabled            = $s.AntivirusEnabled
            RealTimeProtectionEnabled   = $s.RealTimeProtectionEnabled
            BehaviorMonitorEnabled      = $s.BehaviorMonitorEnabled
            IoavProtectionEnabled       = $s.IoavProtectionEnabled
            OnAccessProtectionEnabled   = $s.OnAccessProtectionEnabled
            NISEnabled                  = $s.NISEnabled
            TamperProtectionSource      = $s.TamperProtectionSource
            IsTamperProtected           = $s.IsTamperProtected
            AntivirusSignatureVersion   = $s.AntivirusSignatureVersion
            AntivirusSignatureLastUpdated = [string]$s.AntivirusSignatureLastUpdated
            AntivirusSignatureAgeDays   = $s.AntivirusSignatureAge
            QuickScanAge                = $s.QuickScanAge
            FullScanAge                 = $s.FullScanAge
            LastQuickScanTime           = [string]$s.QuickScanEndTime
            AMEngineVersion             = $s.AMEngineVersion
            AMProductVersion            = $s.AMProductVersion
        }
    } | Out-Null

    Invoke-Collection -Category 'Security' -Name 'defender_preferences_and_exclusions' -Description 'Defender preferences, including exclusion paths/processes/extensions' -Script {
        $p = Get-MpPreference -ErrorAction Stop
        [PSCustomObject]@{
            ExclusionPath                 = @($p.ExclusionPath)
            ExclusionProcess              = @($p.ExclusionProcess)
            ExclusionExtension            = @($p.ExclusionExtension)
            ExclusionIpAddress            = @($p.ExclusionIpAddress)
            DisableRealtimeMonitoring     = $p.DisableRealtimeMonitoring
            DisableBehaviorMonitoring     = $p.DisableBehaviorMonitoring
            DisableScriptScanning         = $p.DisableScriptScanning
            DisableArchiveScanning        = $p.DisableArchiveScanning
            DisableIOAVProtection         = $p.DisableIOAVProtection
            DisableIntrusionPreventionSystem = $p.DisableIntrusionPreventionSystem
            DisableBlockAtFirstSeen       = $p.DisableBlockAtFirstSeen
            MAPSReporting                 = [string]$p.MAPSReporting
            SubmitSamplesConsent          = [string]$p.SubmitSamplesConsent
            PUAProtection                 = [string]$p.PUAProtection
            EnableControlledFolderAccess  = [string]$p.EnableControlledFolderAccess
            AttackSurfaceReductionRules_Ids = @($p.AttackSurfaceReductionRules_Ids)
            AttackSurfaceReductionRules_Actions = @($p.AttackSurfaceReductionRules_Actions)
        }
    } | Out-Null

    Invoke-Collection -Category 'Security' -Name 'defender_detections' -Format 'Csv' -Description 'Defender threat detection history' -Script {
        $rows = @()
        try {
            $threats = Get-MpThreatDetection -ErrorAction Stop
            foreach ($t in $threats) {
                $rows += [PSCustomObject]@{
                    DetectionID       = $t.DetectionID
                    ThreatID          = $t.ThreatID
                    InitialDetectionTimeUtc = if ($t.InitialDetectionTime) { $t.InitialDetectionTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
                    LastThreatStatusChangeTime = [string]$t.LastThreatStatusChangeTime
                    ThreatStatus      = [string]$t.ThreatStatusID
                    CleaningAction    = [string]$t.CleaningActionID
                    Resources         = ($t.Resources -join ' | ')
                    ProcessName       = $t.ProcessName
                    DomainUser        = $t.DomainUser
                }
            }
        }
        catch { }
        try {
            foreach ($t in (Get-MpThreat -ErrorAction Stop)) {
                $rows += [PSCustomObject]@{
                    DetectionID       = 'MpThreat'
                    ThreatID          = $t.ThreatID
                    InitialDetectionTimeUtc = ''
                    LastThreatStatusChangeTime = ''
                    ThreatStatus      = $t.ThreatName
                    CleaningAction    = [string]$t.SeverityID
                    Resources         = ($t.Resources -join ' | ')
                    ProcessName       = ''
                    DomainUser        = ''
                }
            }
        }
        catch { }
        $rows
    } | Out-Null

    Invoke-Collection -Category 'Security' -Name 'installed_av_products' -Format 'Csv' -Description 'Registered AV products from Security Center' -Script {
        Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop |
            Select-Object displayName, productState, pathToSignedProductExe, pathToSignedReportingExe, timestamp
    } | Out-Null

    Invoke-Collection -Category 'Security' -Name 'hardening_registry_settings' -Format 'Csv' -Description 'UAC, LSA, WDigest, SMB, and credential protection settings' -Script {
        $checks = @(
            @{ Name = 'EnableLUA'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Expected = '1'; Note = 'UAC enabled' },
            @{ Name = 'ConsentPromptBehaviorAdmin'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Expected = '5'; Note = 'UAC prompt behavior' },
            @{ Name = 'LocalAccountTokenFilterPolicy'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Expected = '0'; Note = '1 enables local admin lateral movement' },
            @{ Name = 'FilterAdministratorToken'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Expected = '1'; Note = 'Built-in admin approval mode' },
            @{ Name = 'EnableInstallerDetection'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Expected = '1'; Note = 'Installer elevation detection' },
            @{ Name = 'AlwaysInstallElevated'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'; Expected = '0'; Note = '1 is a local privilege escalation path' },
            @{ Name = 'RunAsPPL'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Expected = '1'; Note = 'LSASS protected process' },
            @{ Name = 'LsaCfgFlags'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Expected = '1'; Note = 'Credential Guard' },
            @{ Name = 'RestrictAnonymous'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Expected = '1'; Note = 'Anonymous enumeration restriction' },
            @{ Name = 'RestrictAnonymousSAM'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Expected = '1'; Note = 'SAM enumeration restriction' },
            @{ Name = 'NoLMHash'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Expected = '1'; Note = 'LM hash storage disabled' },
            @{ Name = 'LmCompatibilityLevel'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Expected = '5'; Note = 'NTLM compatibility level' },
            @{ Name = 'UseLogonCredential'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; Expected = '0'; Note = '1 stores cleartext credentials in memory' },
            @{ Name = 'SMB1'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Expected = '0'; Note = 'SMBv1 server' },
            @{ Name = 'RequireSecuritySignature'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Expected = '1'; Note = 'SMB signing required' },
            @{ Name = 'EnableSecuritySignature'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Expected = '1'; Note = 'SMB signing enabled' },
            @{ Name = 'AutoShareWks'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Expected = '0'; Note = 'Admin shares' },
            @{ Name = 'CachedLogonsCount'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Expected = '4'; Note = 'Cached domain credentials' },
            @{ Name = 'AutoAdminLogon'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Expected = '0'; Note = '1 with DefaultPassword stores cleartext creds' },
            @{ Name = 'DefaultUserName'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Expected = ''; Note = 'Autologon account' },
            @{ Name = 'DisableAntiSpyware'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'; Expected = '0'; Note = '1 disables Defender via policy' },
            @{ Name = 'DisableRealtimeMonitoring'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Expected = '0'; Note = 'Policy-level RTP disable' },
            @{ Name = 'EnableScriptBlockLogging'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Expected = '1'; Note = 'PowerShell script block logging' },
            @{ Name = 'EnableModuleLogging'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; Expected = '1'; Note = 'PowerShell module logging' },
            @{ Name = 'EnableTranscripting'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Expected = '1'; Note = 'PowerShell transcription' },
            @{ Name = 'fDenyTSConnections'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'; Expected = '1'; Note = '0 means RDP is enabled' },
            @{ Name = 'DisableTaskMgr'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Expected = '0'; Note = 'Task Manager lockout' },
            @{ Name = 'DisableRegistryTools'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Expected = '0'; Note = 'Regedit lockout' },
            @{ Name = 'DisableCMD'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Expected = '0'; Note = 'Command prompt lockout' }
        )
        $rows = @()
        foreach ($c in $checks) {
            $val = Get-RegValueSafe $c.Path $c.Name
            $rows += [PSCustomObject]@{
                Setting      = $c.Name
                Key          = $c.Path
                Value        = if ($null -eq $val) { '(not set)' } else { [string]$val }
                RecommendedValue = $c.Expected
                Meaning      = $c.Note
                MatchesRecommended = ($null -ne $val -and [string]$val -eq $c.Expected)
            }
        }
        $rows
    } | Out-Null

    Invoke-Collection -Category 'Security' -Name 'audit_policy' -Format 'Txt' -Description 'Advanced audit policy configuration (log coverage)' -RequiresElevation -Script {
        & auditpol.exe /get /category:* 2>&1 | Out-String
    } | Out-Null

    Invoke-Collection -Category 'Security' -Name 'smb_and_winrm_config' -Format 'Txt' -Description 'SMB server config, SMBv1 feature state, WinRM listeners' -Script {
        $out = @()
        $out += '--- Get-SmbServerConfiguration ---'
        try { $out += (Get-SmbServerConfiguration -ErrorAction Stop | Format-List | Out-String -Width 300) } catch { $out += "Error: $($_.Exception.Message)" }
        $out += '--- SMB1 optional feature ---'
        try { $out += (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop | Select-Object FeatureName, State | Out-String) } catch { $out += 'SMB1 feature query unavailable' }
        $out += '--- winrm enumerate winrm/config/listener ---'
        $winrmCmd = Join-Path $env:SystemRoot 'System32\winrm.cmd'
        if (-not (Test-Path -LiteralPath $winrmCmd)) {
            $winrmCmd = Join-Path $env:SystemRoot 'System32\winrm.exe'
        }
        if (Test-Path -LiteralPath $winrmCmd) {
            $out += (& $winrmCmd enumerate winrm/config/listener 2>&1 | Out-String)
        }
        else {
            $out += 'winrm client not present on PATH or System32 (common on some Windows editions). WinRM service status still recorded below.'
        }
        $out += '--- WinRM service ---'
        $out += (Get-Service WinRM -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType | Out-String)
        $out += '--- PSRemoting trusted hosts ---'
        try { $out += (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction Stop | Select-Object Name, Value | Out-String) } catch { }
        $out
    } | Out-Null

    Invoke-Collection -Category 'Security' -Name 'powershell_environment' -Description 'PowerShell versions, policy, and logging configuration' -Script {
        $psv2 = 'Unknown'
        try { $psv2 = [string](Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction Stop).State } catch { }
        [PSCustomObject]@{
            CurrentVersion        = $PSVersionTable.PSVersion.ToString()
            ExecutionPolicyList   = (Get-ExecutionPolicy -List | Out-String)
            PSv2FeatureState      = $psv2
            ScriptBlockLogging    = (Get-RegValueSafe 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging')
            ModuleLogging         = (Get-RegValueSafe 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging')
            Transcription         = (Get-RegValueSafe 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting')
            TranscriptOutputDir   = (Get-RegValueSafe 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'OutputDirectory')
            LanguageMode          = [string]$ExecutionContext.SessionState.LanguageMode
        }
    } | Out-Null

    Invoke-Collection -Category 'Security' -Name 'non_microsoft_root_certificates' -Format 'Csv' -Description 'Root/intermediate CAs not issued by Microsoft (rogue CA check)' -Script {
        $rows = @()
        foreach ($store in @('Cert:\LocalMachine\Root', 'Cert:\LocalMachine\CA', 'Cert:\LocalMachine\TrustedPublisher')) {
            try {
                foreach ($c in (Get-ChildItem -Path $store -ErrorAction Stop)) {
                    $rows += [PSCustomObject]@{
                        Store        = $store
                        Subject      = $c.Subject
                        Issuer       = $c.Issuer
                        Thumbprint   = $c.Thumbprint
                        NotBefore    = $c.NotBefore.ToString('yyyy-MM-dd')
                        NotAfter     = $c.NotAfter.ToString('yyyy-MM-dd')
                        SelfSigned   = ($c.Subject -eq $c.Issuer)
                        FriendlyName = $c.FriendlyName
                    }
                }
            }
            catch { }
        }
        $rows | Sort-Object Store, Subject
    } | Out-Null

    Invoke-Collection -Category 'Security' -Name 'applocker_wdac_and_policy' -Format 'Txt' -Description 'Application control policy and applied group policy summary' -Script {
        $out = @()
        $out += '--- AppLocker effective policy ---'
        try { $out += (Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop) } catch { $out += "AppLocker policy unavailable: $($_.Exception.Message)" }
        $out += '--- Device Guard / WDAC status ---'
        try {
            $out += (Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop |
                    Select-Object SecurityServicesConfigured, SecurityServicesRunning, VirtualizationBasedSecurityStatus, CodeIntegrityPolicyEnforcementStatus | Out-String)
        }
        catch { $out += 'DeviceGuard WMI class unavailable' }
        $out += '--- gpresult /r ---'
        $out += (& gpresult.exe /r 2>&1 | Out-String)
        $out
    } | Out-Null
}

# ==============================================================================
#  SECTION 7 - EVENT LOGS
# ==============================================================================

function Get-EventsSafe {
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

function ConvertTo-EventRow {
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

function Invoke-EventLogCollection {
    Write-Status "Collecting event logs (last $EventLogDays days, max $MaxEventsPerLog per query)" 'Step'
    $start = (Get-Date).AddDays(-1 * $EventLogDays)

    $queries = @(
        @{ Name = 'security_logon_events'; Log = 'Security'; Ids = @(4624, 4625, 4634, 4647, 4648, 4672, 4778, 4779); Desc = 'Logon success/failure, explicit credential use, privilege assignment' },
        @{ Name = 'security_account_management'; Log = 'Security'; Ids = @(4720, 4722, 4723, 4724, 4725, 4726, 4727, 4728, 4729, 4732, 4733, 4738, 4740, 4756, 4757, 4767, 4781); Desc = 'Account creation, modification, group membership changes' },
        @{ Name = 'security_process_creation'; Log = 'Security'; Ids = @(4688, 4689); Desc = 'Process creation/termination (requires audit policy enabled)' },
        @{ Name = 'security_policy_and_log_changes'; Log = 'Security'; Ids = @(1102, 4719, 4739, 4907, 4912); Desc = 'Audit log cleared and audit policy changes' },
        @{ Name = 'security_object_and_share_access'; Log = 'Security'; Ids = @(5140, 5142, 5143, 5144, 5145, 4663, 4656); Desc = 'Share and object access events' },
        @{ Name = 'security_scheduled_task_and_service'; Log = 'Security'; Ids = @(4697, 4698, 4699, 4700, 4701, 4702); Desc = 'Service installation and scheduled task changes' },
        @{ Name = 'security_kerberos_ntlm'; Log = 'Security'; Ids = @(4768, 4769, 4771, 4776); Desc = 'Kerberos/NTLM authentication events' },
        @{ Name = 'system_service_and_driver'; Log = 'System'; Ids = @(7045, 7040, 7034, 7031, 7036, 219, 41, 1001); Desc = 'Service install/state change, driver load, unexpected shutdown' },
        @{ Name = 'system_log_and_boot'; Log = 'System'; Ids = @(104, 6005, 6006, 6008, 6013, 1074); Desc = 'Log clearing, boot, shutdown events' },
        @{ Name = 'powershell_operational'; Log = 'Microsoft-Windows-PowerShell/Operational'; Ids = @(4103, 4104, 53504); Desc = 'PowerShell script block and module logging' },
        @{ Name = 'powershell_classic'; Log = 'Windows PowerShell'; Ids = @(400, 403, 600, 800); Desc = 'Classic PowerShell engine lifecycle and provider events' },
        @{ Name = 'defender_operational'; Log = 'Microsoft-Windows-Windows Defender/Operational'; Ids = @(1006, 1007, 1008, 1009, 1015, 1116, 1117, 1118, 1119, 5001, 5004, 5007, 5010, 5012); Desc = 'Defender detections, actions, and configuration changes' },
        @{ Name = 'task_scheduler_operational'; Log = 'Microsoft-Windows-TaskScheduler/Operational'; Ids = @(106, 129, 140, 141, 200, 201); Desc = 'Task registration, deletion, and execution' },
        @{ Name = 'terminal_services_local'; Log = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Ids = @(21, 22, 23, 24, 25, 39, 40); Desc = 'RDP session connect/disconnect/reconnect' },
        @{ Name = 'terminal_services_remote'; Log = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Ids = @(1149, 1148); Desc = 'RDP authentication attempts with source IP' },
        @{ Name = 'wmi_activity'; Log = 'Microsoft-Windows-WMI-Activity/Operational'; Ids = @(5857, 5858, 5859, 5860, 5861); Desc = 'WMI provider and permanent subscription activity' },
        @{ Name = 'windows_firewall'; Log = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'; Ids = @(2003, 2004, 2005, 2006, 2033); Desc = 'Firewall rule and profile changes' },
        @{ Name = 'bits_client'; Log = 'Microsoft-Windows-Bits-Client/Operational'; Ids = @(3, 4, 59, 60); Desc = 'BITS transfer jobs (download activity)' },
        @{ Name = 'app_crashes'; Log = 'Application'; Ids = @(1000, 1001, 1002); Desc = 'Application crash and hang reports' },
        @{ Name = 'sysmon_operational'; Log = 'Microsoft-Windows-Sysmon/Operational'; Ids = @(1, 3, 6, 7, 8, 10, 11, 12, 13, 15, 22, 23, 25); Desc = 'Sysmon telemetry if Sysmon is deployed' }
    )

    # GetNewClosure() copies *variables* into a private scope so each query keeps its own
    # $q, but it does not copy script functions. Capture the helpers here or the task
    # fails with "Get-EventsSafe is not recognized" (seen on Windows 11 / PS7).
    $fnGetEvents = ${function:Get-EventsSafe}
    $fnToRow = ${function:ConvertTo-EventRow}

    foreach ($q in $queries) {
        $needAdmin = $false
        if ($q.Log -eq 'Security') { $needAdmin = $true }
        $query = $q
        $windowStart = $start
        $maxEv = $MaxEventsPerLog
        Invoke-Collection -Category 'EventLogs' -Name $q.Name -Format 'Csv' -Description $q.Desc -RequiresElevation:$needAdmin -Script {
            $events = & $fnGetEvents -LogName $query.Log -EventIds $query.Ids -StartTime $windowStart -MaxEvents $maxEv
            if (-not $events) { return @() }
            $rows = @()
            foreach ($e in $events) { $rows += (& $fnToRow -EventRecord $e -LogLabel $query.Log) }
            $rows | Sort-Object TimeCreatedUtc -Descending
        }.GetNewClosure() | Out-Null
    }

    Invoke-Collection -Category 'EventLogs' -Name 'event_log_configuration' -Format 'Csv' -Description 'Log size, retention, and enablement (gap analysis)' -Script {
        $rows = @()
        $logs = @('Security', 'System', 'Application', 'Microsoft-Windows-PowerShell/Operational',
            'Microsoft-Windows-TaskScheduler/Operational', 'Microsoft-Windows-Sysmon/Operational',
            'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
            'Microsoft-Windows-Windows Defender/Operational', 'Microsoft-Windows-WMI-Activity/Operational')
        foreach ($l in $logs) {
            try {
                $cfg = Get-WinEvent -ListLog $l -ErrorAction Stop
                $rows += [PSCustomObject]@{
                    LogName        = $cfg.LogName
                    IsEnabled      = $cfg.IsEnabled
                    LogMode        = [string]$cfg.LogMode
                    MaximumSizeMB  = [math]::Round($cfg.MaximumSizeInBytes / 1MB, 2)
                    CurrentSizeMB  = [math]::Round($cfg.FileSize / 1MB, 2)
                    RecordCount    = $cfg.RecordCount
                    OldestRecordUtc = ''
                    LogFilePath    = $cfg.LogFilePath
                }
            }
            catch {
                $rows += [PSCustomObject]@{ LogName = $l; IsEnabled = 'NotPresent'; LogMode = ''; MaximumSizeMB = 0; CurrentSizeMB = 0; RecordCount = 0; OldestRecordUtc = ''; LogFilePath = '' }
            }
        }
        $rows
    } | Out-Null

    if (-not $SkipEvtxExport) {
        Write-Status 'Exporting raw EVTX files (time-filtered)' 'Step'
        $evtxDir = Join-Path $Script:Dirs['EventLogs'] 'evtx'
        New-Item -Path $evtxDir -ItemType Directory -Force | Out-Null
        $ms = [int64]$EventLogDays * 86400000
        $exportLogs = @('Security', 'System', 'Application',
            'Microsoft-Windows-PowerShell/Operational',
            'Microsoft-Windows-TaskScheduler/Operational',
            'Microsoft-Windows-Windows Defender/Operational',
            'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
            'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
            'Microsoft-Windows-WMI-Activity/Operational',
            'Microsoft-Windows-Sysmon/Operational')
        foreach ($log in $exportLogs) {
            if ((-not $Script:IsElevated) -and ($log -eq 'Security')) {
                Write-Status "EVTX export skipped for Security (not elevated)" 'Info'
                continue
            }
            $safeName = ($log -replace '[\\/ ]', '_') + '.evtx'
            $dest = Join-Path $evtxDir $safeName
            try {
                $query = "*[System[TimeCreated[timediff(@SystemTime) <= $ms]]]"
                $null = & wevtutil.exe epl "$log" "$dest" "/q:$query" /ow:true 2>&1
                if (Test-Path -LiteralPath $dest) {
                    Write-Status "Exported $log" 'Good'
                }
                else {
                    Write-Status "No EVTX export produced for $log" 'Info'
                }
            }
            catch { Write-Status "EVTX export failed for $log : $($_.Exception.Message)" 'Warn' }
        }
    }
    else {
        Write-Status 'EVTX export skipped by parameter' 'Info'
    }
}

# ==============================================================================
#  SECTION 8 - FILESYSTEM
# ==============================================================================

function Invoke-FilesystemCollection {
    Write-Status 'Collecting filesystem artifacts, execution evidence, and device history' 'Step'

    Invoke-Collection -Category 'Filesystem' -Name 'executables_in_user_writable_paths' -Format 'Csv' -Description 'Executable content in temp/appdata/programdata/public paths' -Script {
        $roots = @("$env:SystemRoot\Temp", "$env:ProgramData", "$env:PUBLIC")
        foreach ($userProfile in (Get-UserProfileList)) {
            if (-not $userProfile.Exists) { continue }
            $roots += (Join-Path $userProfile.ProfilePath 'AppData\Local\Temp')
            $roots += (Join-Path $userProfile.ProfilePath 'AppData\Roaming')
            $roots += (Join-Path $userProfile.ProfilePath 'Downloads')
            $roots += (Join-Path $userProfile.ProfilePath 'Desktop')
        }
        $depth = 3
        if ($IncludeFileTimeline) { $depth = 6 }
        $exts = @('.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.jse', '.wsf', '.hta', '.scr', '.jar', '.lnk', '.msi', '.sys', '.com', '.pif')
        $rows = @()
        foreach ($r in ($roots | Sort-Object -Unique)) {
            if (-not (Test-PathAccessible -Path $r)) { continue }
            try {
                $files = Get-ChildItem -LiteralPath $r -Recurse -File -Force -Depth $depth -ErrorAction SilentlyContinue |
                    Where-Object { $exts -contains $_.Extension.ToLower() }
                foreach ($f in $files) {
                    $sig = Get-SignatureInfo -Path $f.FullName
                    $rows += [PSCustomObject]@{
                        Path            = $f.FullName
                        SizeBytes       = $f.Length
                        CreatedUtc      = $f.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                        ModifiedUtc     = $f.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                        AccessedUtc     = $f.LastAccessTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                        Extension       = $f.Extension
                        SignatureStatus = $sig.Status
                        Signer          = $sig.Signer
                        SHA256          = (Get-SafeHash -Path $f.FullName)
                    }
                }
            }
            catch { }
        }
        $rows | Sort-Object ModifiedUtc -Descending
    } | Out-Null

    Invoke-Collection -Category 'Filesystem' -Name 'recently_modified_system_files' -Format 'Csv' -Description 'System32/SysWOW64 binaries modified inside the collection window' -Script {
        $cutoff = (Get-Date).AddDays(-1 * $EventLogDays)
        $rows = @()
        foreach ($dir in @("$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64", "$env:SystemRoot")) {
            if (-not (Test-Path -LiteralPath $dir)) { continue }
            try {
                Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -gt $cutoff -and $_.Extension -match '\.(exe|dll|sys|ps1|bat|cmd)$' } |
                    ForEach-Object {
                        $sig = Get-SignatureInfo -Path $_.FullName
                        $rows += [PSCustomObject]@{
                            Path            = $_.FullName
                            SizeBytes       = $_.Length
                            ModifiedUtc     = $_.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                            CreatedUtc      = $_.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                            SignatureStatus = $sig.Status
                            SHA256          = (Get-SafeHash -Path $_.FullName)
                        }
                    }
            }
            catch { }
        }
        $rows | Sort-Object ModifiedUtc -Descending
    } | Out-Null

    Invoke-Collection -Category 'Filesystem' -Name 'prefetch_listing' -Format 'Csv' -Description 'Prefetch entries (execution evidence, names and timestamps only)' -RequiresElevation -Script {
        $pf = "$env:SystemRoot\Prefetch"
        if (-not (Test-Path -LiteralPath $pf)) { return @() }
        Get-ChildItem -LiteralPath $pf -Filter '*.pf' -Force -ErrorAction SilentlyContinue |
            Select-Object Name, Length,
            @{n = 'CreatedUtc'; e = { $_.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss') } },
            @{n = 'LastRunUtc_FileWrite'; e = { $_.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss') } } |
            Sort-Object LastRunUtc_FileWrite -Descending
    } | Out-Null

    Invoke-Collection -Category 'Filesystem' -Name 'alternate_data_streams' -Format 'Csv' -Description 'Non-default NTFS streams in user paths (Zone.Identifier and beyond)' -Script {
        $rows = @()
        $roots = @("$env:PUBLIC")
        foreach ($userProfile in (Get-UserProfileList)) {
            if (-not $userProfile.Exists) { continue }
            $roots += (Join-Path $userProfile.ProfilePath 'Downloads')
            $roots += (Join-Path $userProfile.ProfilePath 'Desktop')
            $roots += (Join-Path $userProfile.ProfilePath 'AppData\Local\Temp')
        }
        foreach ($r in ($roots | Sort-Object -Unique)) {
            if (-not (Test-PathAccessible -Path $r)) { continue }
            try {
                foreach ($f in (Get-ChildItem -LiteralPath $r -Recurse -File -Force -Depth 3 -ErrorAction SilentlyContinue)) {
                    try {
                        foreach ($s in (Get-Item -LiteralPath $f.FullName -Stream * -ErrorAction Stop)) {
                            if ($s.Stream -eq ':$DATA') { continue }
                            $content = ''
                            if ($s.Length -lt 4096) {
                                try { $content = ((Get-Content -LiteralPath $f.FullName -Stream $s.Stream -ErrorAction Stop) -join ' | ') } catch { }
                            }
                            $rows += [PSCustomObject]@{
                                File       = $f.FullName
                                Stream     = $s.Stream
                                LengthBytes = $s.Length
                                Content    = $content
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
        $rows
    } | Out-Null

    Invoke-Collection -Category 'Filesystem' -Name 'recycle_bin_contents' -Format 'Csv' -Description 'Deleted items still present in $Recycle.Bin per SID' -Script {
        $rows = @()
        foreach ($drive in (Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue)) {
            $rb = Join-Path $drive.Root '$Recycle.Bin'
            if (-not (Test-Path -LiteralPath $rb)) { continue }
            try {
                foreach ($f in (Get-ChildItem -LiteralPath $rb -Recurse -File -Force -ErrorAction SilentlyContinue)) {
                    $rows += [PSCustomObject]@{
                        Drive       = $drive.Root
                        SidFolder   = (Split-Path (Split-Path $f.FullName -Parent) -Leaf)
                        FileName    = $f.Name
                        SizeBytes   = $f.Length
                        DeletedUtc  = $f.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                        FullName    = $f.FullName
                    }
                }
            }
            catch { }
        }
        $rows | Sort-Object DeletedUtc -Descending
    } | Out-Null

    Invoke-Collection -Category 'Filesystem' -Name 'usb_device_history' -Format 'Csv' -Description 'USBSTOR entries and mounted device history (exfiltration pivot)' -Script {
        $rows = @()
        $usbstor = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
        if (Test-Path -LiteralPath $usbstor) {
            foreach ($dev in (Get-ChildItem -LiteralPath $usbstor -ErrorAction SilentlyContinue)) {
                foreach ($inst in (Get-ChildItem -LiteralPath $dev.PSPath -ErrorAction SilentlyContinue)) {
                    $friendly = Get-RegValueSafe $inst.PSPath 'FriendlyName'
                    $rows += [PSCustomObject]@{
                        Source       = 'USBSTOR'
                        Device       = (Split-Path $dev.Name -Leaf)
                        SerialOrId   = (Split-Path $inst.Name -Leaf)
                        FriendlyName = [string]$friendly
                        Value        = ''
                    }
                }
            }
        }
        foreach ($v in (Get-RegValueList -Path 'HKLM:\SYSTEM\MountedDevices')) {
            $rows += [PSCustomObject]@{ Source = 'MountedDevices'; Device = $v.Name; SerialOrId = ''; FriendlyName = ''; Value = $v.Value }
        }
        $rows
    } | Out-Null

    Invoke-Collection -Category 'Filesystem' -Name 'shortcut_and_jumplist_inventory' -Format 'Csv' -Description 'Recent LNK and jump list files (file access evidence)' -Script {
        $rows = @()
        foreach ($userProfile in (Get-UserProfileList)) {
            if (-not $userProfile.Exists) { continue }
            $paths = @(
                (Join-Path $userProfile.ProfilePath 'AppData\Roaming\Microsoft\Windows\Recent'),
                (Join-Path $userProfile.ProfilePath 'AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations'),
                (Join-Path $userProfile.ProfilePath 'AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations')
            )
            foreach ($p in $paths) {
                if (-not (Test-PathAccessible -Path $p)) { continue }
                foreach ($f in (Get-ChildItem -LiteralPath $p -File -Force -ErrorAction SilentlyContinue)) {
                    $rows += [PSCustomObject]@{
                        User        = $userProfile.UserName
                        Folder      = (Split-Path $p -Leaf)
                        Name        = $f.Name
                        SizeBytes   = $f.Length
                        ModifiedUtc = $f.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                        FullName    = $f.FullName
                    }
                }
            }
        }
        $rows | Sort-Object ModifiedUtc -Descending
    } | Out-Null

    Invoke-Collection -Category 'Filesystem' -Name 'hidden_or_odd_root_items' -Format 'Csv' -Description 'Hidden or unexpected items at drive roots and ProgramData' -Script {
        $rows = @()
        foreach ($drive in (Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue)) {
            try {
                foreach ($i in (Get-ChildItem -LiteralPath $drive.Root -Force -ErrorAction SilentlyContinue)) {
                    $isHidden = ($i.Attributes -band [IO.FileAttributes]::Hidden) -ne 0
                    if (-not $isHidden) { continue }
                    $rows += [PSCustomObject]@{
                        Location    = $drive.Root
                        Name        = $i.Name
                        IsDirectory = $i.PSIsContainer
                        Attributes  = [string]$i.Attributes
                        ModifiedUtc = $i.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                    }
                }
            }
            catch { }
        }
        $rows
    } | Out-Null
}

# ==============================================================================
#  SECTION 9 - SOFTWARE AND DRIVERS
# ==============================================================================

function Invoke-SoftwareCollection {
    Write-Status 'Collecting installed software, drivers, and browser extensions' 'Step'

    Invoke-Collection -Category 'Software' -Name 'installed_software' -Format 'Csv' -Description 'Installed programs from all registry views' -Script {
        $rows = @()
        $paths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        foreach ($p in $paths) {
            try {
                Get-ItemProperty -Path $p -ErrorAction SilentlyContinue | ForEach-Object {
                    if (-not $_.DisplayName) { return }
                    $rows += [PSCustomObject]@{
                        Scope           = 'Machine'
                        User            = ''
                        DisplayName     = $_.DisplayName
                        DisplayVersion  = $_.DisplayVersion
                        Publisher       = $_.Publisher
                        InstallDate     = $_.InstallDate
                        InstallLocation = $_.InstallLocation
                        UninstallString = $_.UninstallString
                    }
                }
            }
            catch { }
        }
        foreach ($root in (Get-UserHiveRoots)) {
            $up = Join-Path $root.Root 'Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
            try {
                Get-ItemProperty -Path $up -ErrorAction SilentlyContinue | ForEach-Object {
                    if (-not $_.DisplayName) { return }
                    $rows += [PSCustomObject]@{
                        Scope           = 'User'
                        User            = $root.UserName
                        DisplayName     = $_.DisplayName
                        DisplayVersion  = $_.DisplayVersion
                        Publisher       = $_.Publisher
                        InstallDate     = $_.InstallDate
                        InstallLocation = $_.InstallLocation
                        UninstallString = $_.UninstallString
                    }
                }
            }
            catch { }
        }
        $rows | Sort-Object DisplayName
    } | Out-Null

    Invoke-Collection -Category 'Software' -Name 'drivers' -Format 'Csv' -Description 'Kernel and file system drivers with signature state' -Script {
        $rows = @()
        foreach ($d in (Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue)) {
            $path = $d.PathName
            if ($path) { $path = [Environment]::ExpandEnvironmentVariables($path.Trim('"')) }
            $sig = Get-SignatureInfo -Path $path
            $rows += [PSCustomObject]@{
                Name            = $d.Name
                DisplayName     = $d.DisplayName
                State           = $d.State
                StartMode       = $d.StartMode
                PathName        = $path
                SignatureStatus = $sig.Status
                Signer          = $sig.Signer
                SHA256          = (Get-SafeHash -Path $path)
            }
        }
        $rows | Sort-Object Name
    } | Out-Null

    Invoke-Collection -Category 'Software' -Name 'browser_extensions' -Format 'Csv' -Description 'Chromium-family extension folders and Firefox profile add-ons' -Script {
        $rows = @()
        $browsers = @(
            @{ Name = 'Chrome'; Sub = 'AppData\Local\Google\Chrome\User Data' },
            @{ Name = 'Edge'; Sub = 'AppData\Local\Microsoft\Edge\User Data' },
            @{ Name = 'Brave'; Sub = 'AppData\Local\BraveSoftware\Brave-Browser\User Data' }
        )
        foreach ($userProfile in (Get-UserProfileList)) {
            if (-not $userProfile.Exists) { continue }
            foreach ($b in $browsers) {
                $base = Join-Path $userProfile.ProfilePath $b.Sub
                if (-not (Test-Path -LiteralPath $base)) { continue }
                foreach ($bp in (Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue)) {
                    $extDir = Join-Path $bp.FullName 'Extensions'
                    if (-not (Test-Path -LiteralPath $extDir)) { continue }
                    foreach ($ext in (Get-ChildItem -LiteralPath $extDir -Directory -ErrorAction SilentlyContinue)) {
                        $name = ''
                        $version = ''
                        $perms = ''
                        try {
                            $manifest = Get-ChildItem -LiteralPath $ext.FullName -Recurse -Filter 'manifest.json' -ErrorAction SilentlyContinue | Select-Object -First 1
                            if ($manifest) {
                                $json = Get-Content -LiteralPath $manifest.FullName -Raw -ErrorAction Stop | ConvertFrom-Json
                                $name = [string]$json.name
                                $version = [string]$json.version
                                if ($json.permissions) { $perms = ($json.permissions -join ', ') }
                            }
                        }
                        catch { }
                        $rows += [PSCustomObject]@{
                            User          = $userProfile.UserName
                            Browser       = $b.Name
                            BrowserProfile = $bp.Name
                            ExtensionId   = $ext.Name
                            Name          = $name
                            Version       = $version
                            Permissions   = $perms
                            InstalledUtc  = $ext.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                        }
                    }
                }
            }
            $ffBase = Join-Path $userProfile.ProfilePath 'AppData\Roaming\Mozilla\Firefox\Profiles'
            if (Test-Path -LiteralPath $ffBase) {
                foreach ($fp in (Get-ChildItem -LiteralPath $ffBase -Directory -ErrorAction SilentlyContinue)) {
                    $extPath = Join-Path $fp.FullName 'extensions'
                    if (-not (Test-Path -LiteralPath $extPath)) { continue }
                    foreach ($x in (Get-ChildItem -LiteralPath $extPath -ErrorAction SilentlyContinue)) {
                        $rows += [PSCustomObject]@{
                            User = $userProfile.UserName; Browser = 'Firefox'; BrowserProfile = $fp.Name
                            ExtensionId = $x.Name; Name = ''; Version = ''; Permissions = ''
                            InstalledUtc = $x.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                        }
                    }
                }
            }
        }
        $rows
    } | Out-Null

    Invoke-Collection -Category 'Software' -Name 'remote_access_tool_indicators' -Format 'Csv' -Description 'Presence of common remote access / tunneling tooling' -Script {
        $known = @('teamviewer', 'anydesk', 'ammyy', 'atera', 'screenconnect', 'connectwise', 'logmein', 'gotoassist',
            'splashtop', 'radmin', 'vnc', 'ngrok', 'chrome remote desktop', 'supremo', 'dwservice', 'rustdesk',
            'netsupport', 'remoteutilities', 'zoho assist', 'pulseway', 'level.io', 'tacticalrmm', 'psexec',
            'rclone', 'megasync', 'filezilla', 'winscp', 'putty', 'tor browser', 'advanced ip scanner', 'angry ip')
        $rows = @()
        $installed = $Script:Data['installed_software']
        foreach ($app in $installed) {
            $n = ("{0} {1}" -f $app.DisplayName, $app.Publisher).ToLower()
            foreach ($k in $known) {
                if ($n.Contains($k)) {
                    $rows += [PSCustomObject]@{
                        Source = 'InstalledSoftware'; Match = $k; Detail = $app.DisplayName
                        Publisher = $app.Publisher; Extra = $app.InstallLocation
                    }
                    break
                }
            }
        }
        $procs = $Script:Data['running_processes']
        foreach ($p in $procs) {
            $n = ("{0} {1}" -f $p.Name, $p.Path).ToLower()
            foreach ($k in $known) {
                if ($n.Contains($k)) {
                    $rows += [PSCustomObject]@{
                        Source = 'RunningProcess'; Match = $k; Detail = $p.Name
                        Publisher = $p.Signer; Extra = $p.Path
                    }
                    break
                }
            }
        }
        $svcs = $Script:Data['services']
        foreach ($s in $svcs) {
            $n = ("{0} {1} {2}" -f $s.Name, $s.DisplayName, $s.PathName).ToLower()
            foreach ($k in $known) {
                if ($n.Contains($k)) {
                    $rows += [PSCustomObject]@{
                        Source = 'Service'; Match = $k; Detail = $s.DisplayName
                        Publisher = $s.Signer; Extra = $s.PathName
                    }
                    break
                }
            }
        }
        $rows
    } | Out-Null

    Invoke-Collection -Category 'Software' -Name 'appx_packages' -Format 'Csv' -Description 'Installed Store/AppX packages' -Script {
        # -AllUsers requires elevation. Standard-user coverage is this token's packages only.
        if ($Script:IsElevated) {
            Get-AppxPackage -AllUsers -ErrorAction Stop |
                Select-Object Name, PackageFullName, Publisher, Version, InstallLocation, SignatureKind, Status
        }
        else {
            Get-AppxPackage -ErrorAction Stop |
                Select-Object Name, PackageFullName, Publisher, Version, InstallLocation, SignatureKind, Status
        }
    } | Out-Null
}

# ==============================================================================
#  FINDINGS ENGINE
#  Heuristics only. Every finding cites the artifact it came from and is tiered
#  by evidentiary strength. Nothing here is a conclusion.
# ==============================================================================

function Format-Sample {
    param($Items, [int]$Max = 5)
    if (-not $Items) { return '' }
    $arr = @($Items)
    $shown = $arr | Select-Object -First $Max
    $text = ($shown -join ' ; ')
    if ($arr.Count -gt $Max) { $text += (" ... (+{0} more, see artifact)" -f ($arr.Count - $Max)) }
    return $text
}

function Invoke-FindingsAnalysis {
    Write-Status 'Evaluating collected artifacts against triage heuristics' 'Step'

    # ---------- Baseline context (always present, Tier 1) ----------
    $osInfo = $Script:Data['os_info']
    if ($osInfo) {
        Add-Finding -Severity 'Info' -Category 'System' -Tier 1 -Title 'Host and collection baseline' `
            -Observation ("{0} running {1} (build {2}), uptime {3} days, time zone {4} (offset {5})." -f `
                $osInfo.Hostname, $osInfo.Caption, $osInfo.BuildNumber, $osInfo.UptimeDays, $osInfo.TimeZone, $osInfo.UtcOffset) `
            -WhyItMatters 'All timestamps in this package are recorded in UTC. Confirm the host clock was accurate before building any timeline (see time_sync.txt).' `
            -Artifact (Get-ArtifactPath 'System' 'os_info' 'json')
    }

    $cov = $Script:Data['collection_coverage']
    if ($cov -and $cov.Elevated -eq $false) {
        Add-Finding -Severity 'Info' -Category 'Collection' -Tier 1 -Title 'Collection ran without Administrator rights' `
            -Observation ("Coverage profile {0} as {1}. {2} task(s) were skipped because they require an elevated token (see collection_coverage.json)." -f `
                $cov.CoverageProfile, $cov.CollectionAccount, $cov.SkippedTaskCount) `
            -WhyItMatters 'Standard-user collection still captures the current user''s process list, readable network state, HKCU persistence, and profile artifacts. It does not capture the Security log, Prefetch, VSS, audit policy export, or other users'' files. Missing those artifacts is a visibility gap, not evidence they were empty. Re-run elevated when the host owner can grant it.' `
            -Artifact (Get-ArtifactPath 'Collection' 'collection_coverage' 'json') `
            -NextStep 'If this is an incident, obtain an elevated collection or a disk/memory image. If this is a self-audit on a locked-down work PC, treat skipped tasks as out of scope and verify remaining artifacts against that user''s activity only.'
    }

    # ---------- Defender / AV ----------
    $def = $Script:Data['defender_status']
    if ($def) {
        if ($def.RealTimeProtectionEnabled -eq $false) {
            Add-Finding -Severity 'High' -Category 'Security' -Tier 1 -Title 'Defender real-time protection is disabled' `
                -Observation 'Get-MpComputerStatus reports RealTimeProtectionEnabled = False.' `
                -WhyItMatters 'Real-time protection off is both a common attacker action after gaining privilege and a common administrator misconfiguration. Correlate with Defender event IDs 5001/5007 to establish when and by what it was changed.' `
                -Artifact (Get-ArtifactPath 'Security' 'defender_status' 'json') `
                -NextStep 'Check defender_operational.csv for configuration-change events around the disable time, and confirm whether a third-party AV legitimately took over.'
        }
        if ($def.AntivirusEnabled -eq $false -or $def.AMServiceEnabled -eq $false) {
            Add-Finding -Severity 'High' -Category 'Security' -Tier 1 -Title 'Defender antimalware service is not running' `
                -Observation ("AMServiceEnabled = {0}, AntivirusEnabled = {1}." -f $def.AMServiceEnabled, $def.AntivirusEnabled) `
                -WhyItMatters 'A stopped antimalware service leaves the endpoint without on-access detection. This may be legitimate if a third-party product is installed; confirm against installed_av_products.csv.' `
                -Artifact (Get-ArtifactPath 'Security' 'defender_status' 'json')
        }
        if ($def.IsTamperProtected -eq $false) {
            Add-Finding -Severity 'Low' -Category 'Security' -Tier 1 -Title 'Defender tamper protection is off' `
                -Observation 'IsTamperProtected = False.' `
                -WhyItMatters 'Without tamper protection, Defender settings can be modified by any process running with local administrator rights.' `
                -Artifact (Get-ArtifactPath 'Security' 'defender_status' 'json')
        }
        if ($null -ne $def.AntivirusSignatureAgeDays -and $def.AntivirusSignatureAgeDays -gt 7) {
            Add-Finding -Severity 'Medium' -Category 'Security' -Tier 1 -Title 'Antivirus signatures are stale' `
                -Observation ("Signature age is {0} days (version {1})." -f $def.AntivirusSignatureAgeDays, $def.AntivirusSignatureVersion) `
                -WhyItMatters 'Stale signatures reduce detection coverage and can indicate the host has been offline, or that update channels are blocked.' `
                -Artifact (Get-ArtifactPath 'Security' 'defender_status' 'json')
        }
    }

    $pref = $Script:Data['defender_preferences_and_exclusions']
    if ($pref) {
        $exPaths = @($pref.ExclusionPath) | Where-Object { $_ }
        $exProcs = @($pref.ExclusionProcess) | Where-Object { $_ }
        if ($exPaths.Count -gt 0 -or $exProcs.Count -gt 0) {
            $risky = @()
            foreach ($p in $exPaths) {
                if ((Test-UserWritablePath -Path $p) -or $p -match '^[A-Za-z]:\\?$' -or $p -match '^[A-Za-z]:\\Users\\?$' -or $p -match '^[A-Za-z]:\\Windows\\?$') { $risky += $p }
            }
            $sev = 'Medium'
            if ($risky.Count -gt 0) { $sev = 'High' }
            Add-Finding -Severity $sev -Category 'Security' -Tier 2 -Title 'Defender exclusions are configured' `
                -Observation ("{0} path exclusion(s) and {1} process exclusion(s) are set. Paths: {2}. Processes: {3}." -f `
                    $exPaths.Count, $exProcs.Count, (Format-Sample $exPaths), (Format-Sample $exProcs)) `
                -WhyItMatters 'Exclusions are frequently added by attackers to create a safe staging directory, and are also routinely added by administrators for line-of-business software. Broad exclusions (drive roots, user-writable directories) are the ones worth scrutiny.' `
                -Artifact (Get-ArtifactPath 'Security' 'defender_preferences_and_exclusions' 'json') `
                -NextStep 'Determine who added each exclusion and when. Inspect the contents of every excluded path directly, since on-access scanning did not cover it.'
        }
        if ($pref.DisableScriptScanning -eq $true -or $pref.DisableBehaviorMonitoring -eq $true -or $pref.DisableIOAVProtection -eq $true) {
            Add-Finding -Severity 'High' -Category 'Security' -Tier 1 -Title 'Defender protection components are disabled by preference' `
                -Observation ("DisableScriptScanning={0}, DisableBehaviorMonitoring={1}, DisableIOAVProtection={2}." -f `
                    $pref.DisableScriptScanning, $pref.DisableBehaviorMonitoring, $pref.DisableIOAVProtection) `
                -WhyItMatters 'Selective component disabling is a targeted weakening of endpoint defenses rather than a broad on/off toggle.' `
                -Artifact (Get-ArtifactPath 'Security' 'defender_preferences_and_exclusions' 'json')
        }
    }

    $detections = $Script:Data['defender_detections']
    if ($detections -and @($detections).Count -gt 0) {
        Add-Finding -Severity 'High' -Category 'Security' -Tier 1 -Title 'Antivirus detection history is present' `
            -Observation ("{0} detection record(s) recorded. Sample: {1}." -f @($detections).Count, (Format-Sample (@($detections) | ForEach-Object { $_.Resources }) 3)) `
            -WhyItMatters 'Prior detections show what reached the endpoint. A detection that was only partially remediated, or that recurred, is a strong lead.' `
            -Artifact (Get-ArtifactPath 'Security' 'defender_detections' 'csv') `
            -NextStep 'For each detection, confirm the remediation action succeeded and check whether the same resource path appears in the filesystem or persistence artifacts.'
    }

    # ---------- Hardening settings ----------
    $hard = $Script:Data['hardening_registry_settings']
    if ($hard) {
        $map = @{}
        foreach ($h in $hard) { $map[$h.Setting] = $h.Value }

        if ($map['UseLogonCredential'] -eq '1') {
            Add-Finding -Severity 'High' -Category 'Security' -Tier 1 -Title 'WDigest cleartext credential storage is enabled' `
                -Observation 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 1.' `
                -WhyItMatters 'This forces plaintext credentials into LSASS memory. It is not a default setting and is a well-documented pre-credential-theft modification.' `
                -Artifact (Get-ArtifactPath 'Security' 'hardening_registry_settings' 'csv') `
                -NextStep 'Establish when this value was set and by which account. Treat credentials used on this host as potentially exposed.'
        }
        if ($map['EnableLUA'] -eq '0') {
            Add-Finding -Severity 'High' -Category 'Security' -Tier 1 -Title 'User Account Control is disabled' `
                -Observation 'EnableLUA = 0.' `
                -WhyItMatters 'With UAC off, any process launched by an administrator account runs fully elevated without prompting.' `
                -Artifact (Get-ArtifactPath 'Security' 'hardening_registry_settings' 'csv')
        }
        if ($map['AlwaysInstallElevated'] -eq '1') {
            Add-Finding -Severity 'High' -Category 'Security' -Tier 1 -Title 'AlwaysInstallElevated is enabled' `
                -Observation 'HKLM Installer policy AlwaysInstallElevated = 1.' `
                -WhyItMatters 'Any user can install an MSI package with SYSTEM privileges. This is a direct local privilege escalation path.' `
                -Artifact (Get-ArtifactPath 'Security' 'hardening_registry_settings' 'csv')
        }
        if ($map['AutoAdminLogon'] -eq '1') {
            Add-Finding -Severity 'High' -Category 'Security' -Tier 2 -Title 'Automatic logon is configured' `
                -Observation ("AutoAdminLogon = 1 for account '{0}'." -f $map['DefaultUserName']) `
                -WhyItMatters 'Autologon commonly accompanies a DefaultPassword value stored in cleartext in the registry, and it grants console access without authentication.' `
                -Artifact (Get-ArtifactPath 'Security' 'hardening_registry_settings' 'csv') `
                -NextStep 'Check for a DefaultPassword value in the Winlogon key and rotate that credential.'
        }
        if ($map['LocalAccountTokenFilterPolicy'] -eq '1') {
            Add-Finding -Severity 'Medium' -Category 'Security' -Tier 2 -Title 'LocalAccountTokenFilterPolicy is enabled' `
                -Observation 'LocalAccountTokenFilterPolicy = 1.' `
                -WhyItMatters 'Local administrator accounts can authenticate remotely with full token privileges, which enables pass-the-hash style lateral movement using local accounts.' `
                -Artifact (Get-ArtifactPath 'Security' 'hardening_registry_settings' 'csv')
        }
        if ($map['SMB1'] -eq '1') {
            Add-Finding -Severity 'Medium' -Category 'Security' -Tier 1 -Title 'SMBv1 server is enabled' `
                -Observation 'LanmanServer SMB1 = 1.' `
                -WhyItMatters 'SMBv1 is deprecated and carries known remote code execution exposure. It also lacks modern signing and encryption.' `
                -Artifact (Get-ArtifactPath 'Security' 'hardening_registry_settings' 'csv')
        }
        if ($map['EnableScriptBlockLogging'] -ne '1') {
            Add-Finding -Severity 'Low' -Category 'Security' -Tier 1 -Title 'PowerShell script block logging is not enabled' `
                -Observation 'EnableScriptBlockLogging is not set to 1.' `
                -WhyItMatters 'This is a visibility gap rather than a compromise indicator: PowerShell activity prior to collection may not be recoverable from logs. Absence of PowerShell events in this package cannot be read as absence of PowerShell activity.' `
                -Artifact (Get-ArtifactPath 'Security' 'powershell_environment' 'json')
        }
        if ($map['RunAsPPL'] -ne '1') {
            Add-Finding -Severity 'Low' -Category 'Security' -Tier 1 -Title 'LSASS is not running as a protected process' `
                -Observation 'RunAsPPL is not set to 1.' `
                -WhyItMatters 'Without PPL, LSASS memory can be read by any process with debug privilege, which is the standard credential-dumping path.' `
                -Artifact (Get-ArtifactPath 'Security' 'hardening_registry_settings' 'csv')
        }
    }

    # ---------- Firewall / RDP ----------
    $fw = $Script:Data['firewall_profiles']
    if ($fw) {
        $off = @($fw | Where-Object { $_.Enabled -eq $false -or $_.Enabled -eq 'False' })
        if ($off.Count -gt 0) {
            Add-Finding -Severity 'Medium' -Category 'Network' -Tier 1 -Title 'One or more firewall profiles are disabled' `
                -Observation ("Disabled profile(s): {0}." -f (Format-Sample ($off | ForEach-Object { $_.Name }))) `
                -WhyItMatters 'A disabled profile removes inbound filtering on networks using that profile and is a common post-compromise change to enable remote access.' `
                -Artifact (Get-ArtifactPath 'Network' 'firewall_profiles' 'csv')
        }
    }
    $rdp = $Script:Data['rdp_configuration']
    if ($rdp -and $rdp.RdpEnabled -eq $true) {
        $sev = 'Low'
        $note = 'RDP is enabled.'
        if ($rdp.UserAuthentication -eq 0) {
            $sev = 'Medium'
            $note = 'RDP is enabled and Network Level Authentication is disabled.'
        }
        Add-Finding -Severity $sev -Category 'Users' -Tier 1 -Title 'Remote Desktop is enabled' `
            -Observation ("{0} Listening port: {1}. Members of Remote Desktop Users: {2}." -f $note, $rdp.PortNumber, $rdp.RemoteDesktopUsers) `
            -WhyItMatters 'RDP is one of the most common initial access and lateral movement vectors. Whether this is expected depends on the endpoint role; confirm with the system owner.' `
            -Artifact (Get-ArtifactPath 'Users' 'rdp_configuration' 'json') `
            -NextStep 'Review terminal_services_remote.csv (event 1149) for the source IPs of successful RDP authentications.'
    }

    # ---------- Accounts ----------
    $users = $Script:Data['local_users']
    if ($users) {
        $guest = @($users | Where-Object { $_.Name -eq 'Guest' -and ($_.Enabled -eq $true -or $_.Enabled -eq 'True') })
        if ($guest.Count -gt 0) {
            Add-Finding -Severity 'Medium' -Category 'Users' -Tier 1 -Title 'Guest account is enabled' `
                -Observation 'The built-in Guest account is enabled.' `
                -WhyItMatters 'The Guest account is disabled by default. Enabling it creates an unauthenticated access path and is occasionally used to maintain low-visibility access.' `
                -Artifact (Get-ArtifactPath 'Users' 'local_users' 'csv')
        }
        $noPw = @($users | Where-Object { $_.PasswordRequired -eq $false -and ($_.Enabled -eq $true -or $_.Enabled -eq 'True') })
        if ($noPw.Count -gt 0) {
            Add-Finding -Severity 'Medium' -Category 'Users' -Tier 1 -Title 'Enabled accounts do not require a password' `
                -Observation ("Account(s): {0}." -f (Format-Sample ($noPw | ForEach-Object { $_.Name }))) `
                -WhyItMatters 'Accounts without a password requirement can be used for local logon and, depending on policy, remote authentication.' `
                -Artifact (Get-ArtifactPath 'Users' 'local_users' 'csv')
        }
    }

    $groups = $Script:Data['local_group_membership']
    if ($groups) {
        $admins = @($groups | Where-Object { $_.Group -eq 'Administrators' -and $_.Member -ne '(none)' })
        if ($admins.Count -gt 0) {
            $sev = 'Info'
            if ($admins.Count -gt 5) { $sev = 'Low' }
            Add-Finding -Severity $sev -Category 'Users' -Tier 1 -Title 'Local Administrators group membership' `
                -Observation ("{0} member(s): {1}." -f $admins.Count, (Format-Sample ($admins | ForEach-Object { $_.Member }) 8)) `
                -WhyItMatters 'Membership should be compared against the organization''s expected baseline. Unexpected members, especially local (non-domain) accounts, warrant follow-up.' `
                -Artifact (Get-ArtifactPath 'Users' 'local_group_membership' 'csv') `
                -NextStep 'Cross-reference with security_account_management.csv (event 4732) to see whether any member was added inside the collection window.'
        }
    }

    # ---------- Processes ----------
    $procs = $Script:Data['running_processes']
    if ($procs) {
        $unsignedUserPath = @($procs | Where-Object {
                $_.UserWritablePath -eq $true -and $_.SignatureStatus -ne 'Valid' -and $_.Path
            })
        if ($unsignedUserPath.Count -gt 0) {
            Add-Finding -Severity 'High' -Category 'Processes' -Tier 2 -Title 'Unsigned processes running from user-writable paths' `
                -Observation ("{0} process(es): {1}." -f $unsignedUserPath.Count, (Format-Sample ($unsignedUserPath | ForEach-Object { "$($_.Name) [PID $($_.PID)] $($_.Path)" }))) `
                -WhyItMatters 'Legitimate software is normally installed under Program Files and signed. Unsigned executables running from AppData, Temp, or ProgramData match common malware staging behavior, but also match some legitimate updaters and developer tooling.' `
                -Artifact (Get-ArtifactPath 'Processes' 'running_processes' 'csv') `
                -NextStep 'Submit the SHA-256 values in the artifact to threat intelligence, and check parent process and creation time for each.'
        }
        $suspCmd = @($procs | Where-Object { $_.SuspiciousCmdHits })
        if ($suspCmd.Count -gt 0) {
            Add-Finding -Severity 'High' -Category 'Processes' -Tier 2 -Title 'Running process command lines contain high-risk patterns' `
                -Observation ("{0} process(es) matched: {1}." -f $suspCmd.Count, (Format-Sample ($suspCmd | ForEach-Object { "$($_.Name) [$($_.SuspiciousCmdHits)]" }))) `
                -WhyItMatters 'Patterns such as encoded commands, in-memory download-and-execute, and shadow copy deletion are heavily used in intrusions. They also appear in legitimate management tooling, so each match needs to be read in context.' `
                -Artifact (Get-ArtifactPath 'Processes' 'running_processes' 'csv') `
                -NextStep 'Decode any base64 command lines and review the full CommandLine column in the artifact before drawing conclusions.'
        }
        $officeParents = @('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'msaccess.exe', 'onenote.exe', 'visio.exe')
        $childShells = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe')
        $odd = @($procs | Where-Object {
                $_.ParentName -and $_.Name -and
                ($officeParents -contains $_.ParentName.ToLower()) -and
                ($childShells -contains $_.Name.ToLower())
            })
        if ($odd.Count -gt 0) {
            Add-Finding -Severity 'High' -Category 'Processes' -Tier 2 -Title 'Office application spawned a scripting or shell process' `
                -Observation ("Observed: {0}." -f (Format-Sample ($odd | ForEach-Object { "$($_.ParentName) -> $($_.Name) [PID $($_.PID)]" }))) `
                -WhyItMatters 'Office applications spawning shells or script hosts is a classic macro or exploit execution chain. Some add-ins do this legitimately, so confirm the command line and the originating document.' `
                -Artifact (Get-ArtifactPath 'Processes' 'process_tree' 'txt')
        }
    }

    $psHist = $Script:Data['powershell_console_history']
    if ($psHist) {
        $flagged = @($psHist | Where-Object { $_.SuspiciousHits })
        if ($flagged.Count -gt 0) {
            Add-Finding -Severity 'High' -Category 'Processes' -Tier 2 -Title 'PowerShell console history contains high-risk commands' `
                -Observation ("{0} matching line(s) across profiles. Sample: {1}." -f $flagged.Count, (Format-Sample ($flagged | ForEach-Object { "$($_.User): $($_.Command)" }) 4)) `
                -WhyItMatters 'PSReadLine history persists across reboots and is not covered by event log retention, so it often preserves activity that logging missed. Note that history files are user-editable and carry no timestamps.' `
                -Artifact (Get-ArtifactPath 'Processes' 'powershell_console_history' 'csv') `
                -NextStep 'Correlate each command with PowerShell operational events (4104) and process creation events (4688) to establish execution and timing.'
        }
    }

    # ---------- Persistence ----------
    $autoruns = $Script:Data['autorun_registry_keys']
    if ($autoruns) {
        $badRuns = @($autoruns | Where-Object { $_.SuspiciousHits -or $_.UserWritableTarget -eq $true })
        if ($badRuns.Count -gt 0) {
            Add-Finding -Severity 'High' -Category 'Persistence' -Tier 2 -Title 'Autostart entries point to user-writable locations or contain risky patterns' `
                -Observation ("{0} of {1} autostart entries flagged. Sample: {2}." -f $badRuns.Count, @($autoruns).Count, (Format-Sample ($badRuns | ForEach-Object { "$($_.ValueName) = $($_.Command)" }) 4)) `
                -WhyItMatters 'Run keys are the most common persistence mechanism. Entries executing from AppData or Temp, or invoking script interpreters, deserve individual verification.' `
                -Artifact (Get-ArtifactPath 'Persistence' 'autorun_registry_keys' 'csv') `
                -NextStep 'For each flagged entry, hash the target binary, check its signature, and determine the registry key write time from a registry hive if available.'
        }
    }

    $tasks = $Script:Data['scheduled_tasks']
    if ($tasks) {
        $badTasks = @($tasks | Where-Object { $_.SuspiciousHits -or $_.UserWritableTarget -eq $true })
        if ($badTasks.Count -gt 0) {
            Add-Finding -Severity 'High' -Category 'Persistence' -Tier 2 -Title 'Scheduled tasks reference user-writable paths or risky commands' `
                -Observation ("{0} task(s) flagged. Sample: {1}." -f $badTasks.Count, (Format-Sample ($badTasks | ForEach-Object { "$($_.TaskPath)$($_.TaskName): $($_.Actions)" }) 4)) `
                -WhyItMatters 'Scheduled tasks provide reliable, privileged persistence and are frequently created with innocuous names in the root task folder.' `
                -Artifact (Get-ArtifactPath 'Persistence' 'scheduled_tasks' 'csv') `
                -NextStep 'Compare against scheduled_task_files.csv creation timestamps to identify tasks created inside the incident window.'
        }
        $sysTasks = @($tasks | Where-Object { $_.RunAsUser -match 'SYSTEM' -and $_.TaskPath -eq '\' })
        if ($sysTasks.Count -gt 0) {
            Add-Finding -Severity 'Low' -Category 'Persistence' -Tier 1 -Title 'SYSTEM-level tasks exist in the root task folder' `
                -Observation ("{0} task(s): {1}." -f $sysTasks.Count, (Format-Sample ($sysTasks | ForEach-Object { $_.TaskName }))) `
                -WhyItMatters 'Microsoft tasks are normally nested under \Microsoft\Windows\. Root-folder SYSTEM tasks are more often third-party software, but this is also where attacker-created tasks tend to land.' `
                -Artifact (Get-ArtifactPath 'Persistence' 'scheduled_tasks' 'csv')
        }
    }

    $svcs = $Script:Data['services']
    if ($svcs) {
        $svcUserPath = @($svcs | Where-Object { $_.UserWritablePath -eq $true -and $_.ResolvedExe })
        if ($svcUserPath.Count -gt 0) {
            Add-Finding -Severity 'High' -Category 'Persistence' -Tier 2 -Title 'Services execute binaries from user-writable paths' `
                -Observation ("{0} service(s): {1}." -f $svcUserPath.Count, (Format-Sample ($svcUserPath | ForEach-Object { "$($_.Name) -> $($_.PathName)" }) 4)) `
                -WhyItMatters 'A service binary in a user-writable directory can be replaced by a non-administrative user, and is also a common location for attacker-installed services.' `
                -Artifact (Get-ArtifactPath 'Persistence' 'services' 'csv')
        }
        $svcUnquoted = @($svcs | Where-Object { $_.UnquotedPath -eq $true })
        if ($svcUnquoted.Count -gt 0) {
            Add-Finding -Severity 'Medium' -Category 'Persistence' -Tier 1 -Title 'Services configured with unquoted paths containing spaces' `
                -Observation ("{0} service(s): {1}." -f $svcUnquoted.Count, (Format-Sample ($svcUnquoted | ForEach-Object { $_.Name }))) `
                -WhyItMatters 'Unquoted service paths are a privilege escalation vector if any parent directory is writable by a non-administrative user. This is a misconfiguration, not evidence of compromise.' `
                -Artifact (Get-ArtifactPath 'Persistence' 'services' 'csv')
        }
        $svcUnsigned = @($svcs | Where-Object { $_.ResolvedExe -and $_.SignatureStatus -notin @('Valid', 'FileNotFound', 'NotHashed') -and $_.State -eq 'Running' })
        if ($svcUnsigned.Count -gt 0) {
            Add-Finding -Severity 'Medium' -Category 'Persistence' -Tier 2 -Title 'Running services with unsigned or invalid-signature binaries' `
                -Observation ("{0} service(s): {1}." -f $svcUnsigned.Count, (Format-Sample ($svcUnsigned | ForEach-Object { "$($_.Name) [$($_.SignatureStatus)]" }))) `
                -WhyItMatters 'Unsigned service binaries are common in older or in-house software, so this is a prioritization signal rather than a detection.' `
                -Artifact (Get-ArtifactPath 'Persistence' 'services' 'csv')
        }
    }

    $winlogon = $Script:Data['winlogon_lsa_and_dll_hijacks']
    if ($winlogon) {
        $ifeo = @($winlogon | Where-Object { $_.Mechanism -eq 'IFEO' -and $_.Name -eq 'Debugger' })
        if ($ifeo.Count -gt 0) {
            Add-Finding -Severity 'High' -Category 'Persistence' -Tier 2 -Title 'Image File Execution Options debugger entries present' `
                -Observation ("{0} entry/entries: {1}." -f $ifeo.Count, (Format-Sample ($ifeo | ForEach-Object { "$($_.Location) -> $($_.Value)" }) 4)) `
                -WhyItMatters 'An IFEO Debugger value causes the named program to be replaced at launch by the specified binary. Legitimate uses exist (debuggers, some AV), but this is the mechanism behind sticky-keys style backdoors.' `
                -Artifact (Get-ArtifactPath 'Persistence' 'winlogon_lsa_and_dll_hijacks' 'csv')
        }
        $appInit = @($winlogon | Where-Object { $_.Name -eq 'AppInit_DLLs' -and $_.Value })
        if ($appInit.Count -gt 0) {
            Add-Finding -Severity 'High' -Category 'Persistence' -Tier 2 -Title 'AppInit_DLLs is populated' `
                -Observation ("Value(s): {0}." -f (Format-Sample ($appInit | ForEach-Object { $_.Value }))) `
                -WhyItMatters 'DLLs listed here load into most user-mode processes that link user32.dll, giving broad code injection with a single registry write.' `
                -Artifact (Get-ArtifactPath 'Persistence' 'winlogon_lsa_and_dll_hijacks' 'csv')
        }
        $shell = @($winlogon | Where-Object { $_.Mechanism -eq 'Winlogon' -and $_.Name -eq 'Shell' -and $_.Value -ne 'explorer.exe' })
        $userinit = @($winlogon | Where-Object { $_.Mechanism -eq 'Winlogon' -and $_.Name -eq 'Userinit' -and $_.Value -notmatch '^C:\\Windows\\system32\\userinit\.exe,?$' })
        if ($shell.Count -gt 0 -or $userinit.Count -gt 0) {
            Add-Finding -Severity 'High' -Category 'Persistence' -Tier 2 -Title 'Winlogon Shell or Userinit value is non-default' `
                -Observation ("Shell: {0}. Userinit: {1}." -f (Format-Sample ($shell | ForEach-Object { $_.Value })), (Format-Sample ($userinit | ForEach-Object { $_.Value }))) `
                -WhyItMatters 'These values control what launches at interactive logon. Appended commands here execute for every logon with the user''s privileges.' `
                -Artifact (Get-ArtifactPath 'Persistence' 'winlogon_lsa_and_dll_hijacks' 'csv')
        }
    }

    $access = $Script:Data['accessibility_binary_integrity']
    if ($access) {
        $tampered = @($access | Where-Object { $_.IFEODebugger -or ($_.SignatureStatus -ne 'Valid' -and $_.SignatureStatus -ne 'NotHashed') })
        if ($tampered.Count -gt 0) {
            Add-Finding -Severity 'High' -Category 'Persistence' -Tier 2 -Title 'Accessibility binaries show signs of replacement or hijack' `
                -Observation ("Affected: {0}." -f (Format-Sample ($tampered | ForEach-Object { "$($_.Binary) sig=$($_.SignatureStatus) debugger=$($_.IFEODebugger)" }))) `
                -WhyItMatters 'Replacing sethc.exe or utilman.exe, or attaching a debugger to them, yields a SYSTEM shell from the pre-authentication logon screen.' `
                -Artifact (Get-ArtifactPath 'Persistence' 'accessibility_binary_integrity' 'csv') `
                -NextStep 'Compare file hash and modification time against a known-good build of the same Windows version.'
        }
    }

    $com = $Script:Data['com_hijack_candidates']
    if ($com) {
        $comBad = @($com | Where-Object { $_.UserWritableTarget -eq $true })
        if ($comBad.Count -gt 0) {
            Add-Finding -Severity 'Medium' -Category 'Persistence' -Tier 2 -Title 'Per-user COM registrations target user-writable files' `
                -Observation ("{0} CLSID override(s): {1}." -f $comBad.Count, (Format-Sample ($comBad | ForEach-Object { "$($_.User) $($_.CLSID) -> $($_.Target)" }) 4)) `
                -WhyItMatters 'HKCU COM registrations take precedence over HKLM, so a per-user CLSID override pointing at a user-writable DLL can hijack legitimate component loads.' `
                -Artifact (Get-ArtifactPath 'Persistence' 'com_hijack_candidates' 'csv')
        }
    }

    $startupItems = $Script:Data['startup_folder_items']
    if ($startupItems) {
        $unsignedStartup = @($startupItems | Where-Object { $_.SignatureStatus -notin @('Valid', 'NotHashed') })
        if ($unsignedStartup.Count -gt 0) {
            Add-Finding -Severity 'Medium' -Category 'Persistence' -Tier 2 -Title 'Startup folder contains unsigned items' `
                -Observation ("{0} item(s): {1}." -f $unsignedStartup.Count, (Format-Sample ($unsignedStartup | ForEach-Object { $_.FullName }) 4)) `
                -WhyItMatters 'Startup folder placement requires no registry access and survives reboot. Shortcut (.lnk) items should be examined for their target and arguments.' `
                -Artifact (Get-ArtifactPath 'Persistence' 'startup_folder_items' 'csv')
        }
    }

    # ---------- Network ----------
    $conns = $Script:Data['active_connections']
    if ($conns) {
        $extSuspect = @($conns | Where-Object { $_.RemoteIsExternal -eq $true -and $_.UserWritablePath -eq $true })
        if ($extSuspect.Count -gt 0) {
            Add-Finding -Severity 'High' -Category 'Network' -Tier 2 -Title 'External connections from binaries in user-writable paths' `
                -Observation ("{0} connection(s): {1}." -f $extSuspect.Count, (Format-Sample ($extSuspect | ForEach-Object { "$($_.ProcessName) -> $($_.RemoteAddress):$($_.RemotePort)" }) 5)) `
                -WhyItMatters 'This pairing - a binary outside standard install locations holding an outbound session - is a common command-and-control pattern, and also a common pattern for legitimate portable applications.' `
                -Artifact (Get-ArtifactPath 'Network' 'active_connections' 'csv') `
                -NextStep 'Resolve and enrich the remote addresses, and confirm the process hash against threat intelligence before treating this as C2.'
        }
        $extAll = @($conns | Where-Object { $_.RemoteIsExternal -eq $true -and $_.State -eq 'Established' })
        if ($extAll.Count -gt 0) {
            Add-Finding -Severity 'Info' -Category 'Network' -Tier 1 -Title 'Established external connections at collection time' `
                -Observation ("{0} established external session(s). Sample: {1}." -f $extAll.Count, (Format-Sample ($extAll | ForEach-Object { "$($_.ProcessName) -> $($_.RemoteAddress):$($_.RemotePort)" }) 6)) `
                -WhyItMatters 'This is a point-in-time snapshot. Sessions that opened and closed before collection are not represented here.' `
                -Artifact (Get-ArtifactPath 'Network' 'active_connections' 'csv')
        }
    }

    $hosts = $Script:Data['hosts_file']
    if ($hosts) {
        $entries = @($hosts | Where-Object { $_ -and $_.Trim() -and -not $_.Trim().StartsWith('#') })
        if ($entries.Count -gt 0) {
            Add-Finding -Severity 'Medium' -Category 'Network' -Tier 1 -Title 'hosts file contains active entries' `
                -Observation ("{0} non-comment line(s): {1}." -f $entries.Count, (Format-Sample $entries 5)) `
                -WhyItMatters 'hosts entries override DNS. They are used both to block security vendor domains and to redirect traffic, and are also common in development environments.' `
                -Artifact (Get-ArtifactPath 'Network' 'hosts_file' 'txt')
        }
    }

    # ---------- Event log derived ----------
    $polChanges = $Script:Data['security_policy_and_log_changes']
    if ($polChanges) {
        $cleared = @($polChanges | Where-Object { $_.EventId -eq 1102 })
        if ($cleared.Count -gt 0) {
            Add-Finding -Severity 'High' -Category 'EventLogs' -Tier 1 -Title 'Security event log was cleared' `
                -Observation ("Event ID 1102 recorded {0} time(s). Most recent: {1} UTC." -f $cleared.Count, (@($cleared)[0].TimeCreatedUtc)) `
                -WhyItMatters 'Clearing the Security log destroys authentication and audit history. It is occasionally done during maintenance, but it is also a standard anti-forensic step.' `
                -Artifact (Get-ArtifactPath 'EventLogs' 'security_policy_and_log_changes' 'csv') `
                -NextStep 'Identify the account in the 1102 record and determine whether the clearing was authorized. Any event history before that timestamp is unavailable from this host.'
        }
    }
    $sysLog = $Script:Data['system_log_and_boot']
    if ($sysLog) {
        $logCleared = @($sysLog | Where-Object { $_.EventId -eq 104 })
        if ($logCleared.Count -gt 0) {
            Add-Finding -Severity 'High' -Category 'EventLogs' -Tier 1 -Title 'An event log was cleared (System log, event 104)' `
                -Observation ("Event ID 104 recorded {0} time(s). Most recent: {1} UTC." -f $logCleared.Count, (@($logCleared)[0].TimeCreatedUtc)) `
                -WhyItMatters 'Event 104 records which log was cleared and by whom. Coverage gaps created by clearing must be stated explicitly in any timeline built from this data.' `
                -Artifact (Get-ArtifactPath 'EventLogs' 'system_log_and_boot' 'csv')
        }
    }
    $svcEvents = $Script:Data['system_service_and_driver']
    if ($svcEvents) {
        $installs = @($svcEvents | Where-Object { $_.EventId -eq 7045 })
        if ($installs.Count -gt 0) {
            Add-Finding -Severity 'Medium' -Category 'EventLogs' -Tier 1 -Title 'Services were installed during the collection window' `
                -Observation ("{0} service install event(s) (ID 7045). Most recent: {1} UTC." -f $installs.Count, (@($installs)[0].TimeCreatedUtc)) `
                -WhyItMatters 'Remote execution tooling (PsExec and similar) and many malware families install a service. Compare each install against expected software deployment activity.' `
                -Artifact (Get-ArtifactPath 'EventLogs' 'system_service_and_driver' 'csv')
        }
    }
    $acctEvents = $Script:Data['security_account_management']
    if ($acctEvents) {
        $created = @($acctEvents | Where-Object { $_.EventId -eq 4720 })
        $adminAdd = @($acctEvents | Where-Object { $_.EventId -in @(4732, 4728, 4756) })
        if ($created.Count -gt 0 -or $adminAdd.Count -gt 0) {
            Add-Finding -Severity 'Medium' -Category 'EventLogs' -Tier 1 -Title 'Account creation or privileged group changes occurred in the window' `
                -Observation ("{0} account creation event(s) (4720) and {1} group addition event(s) (4728/4732/4756)." -f $created.Count, $adminAdd.Count) `
                -WhyItMatters 'New accounts and group additions are both routine IT activity and a standard persistence/privilege step. The distinguishing factor is whether they map to an approved change.' `
                -Artifact (Get-ArtifactPath 'EventLogs' 'security_account_management' 'csv') `
                -NextStep 'Match each event to a change ticket or known onboarding. Note the account that performed the change, not just the account affected.'
        }
    }
    $logons = $Script:Data['security_logon_events']
    if ($logons) {
        $failed = @($logons | Where-Object { $_.EventId -eq 4625 })
        if ($failed.Count -gt 25) {
            Add-Finding -Severity 'Medium' -Category 'EventLogs' -Tier 2 -Title 'Elevated volume of failed logon attempts' `
                -Observation ("{0} failed logon event(s) (4625) in the last {1} days." -f $failed.Count, $EventLogDays) `
                -WhyItMatters 'High 4625 volume is consistent with password spraying or brute force, and equally consistent with a stale service account or a mapped drive using an expired credential.' `
                -Artifact (Get-ArtifactPath 'EventLogs' 'security_logon_events' 'csv') `
                -NextStep 'Group the failures by target account, source workstation, and logon type before characterizing the activity.'
        }
        $explicit = @($logons | Where-Object { $_.EventId -eq 4648 })
        if ($explicit.Count -gt 0) {
            Add-Finding -Severity 'Low' -Category 'EventLogs' -Tier 1 -Title 'Explicit credential use recorded' `
                -Observation ("{0} event(s) with ID 4648 (logon using explicitly supplied credentials)." -f $explicit.Count) `
                -WhyItMatters '4648 records runas-style credential use and often marks the pivot point in lateral movement, though it is also generated by ordinary administrative tooling.' `
                -Artifact (Get-ArtifactPath 'EventLogs' 'security_logon_events' 'csv')
        }
    }
    $psEvents = $Script:Data['powershell_operational']
    if ($psEvents) {
        $flagged = @($psEvents | Where-Object { Test-SuspiciousCommand -Text $_.Message })
        if ($flagged.Count -gt 0) {
            Add-Finding -Severity 'High' -Category 'EventLogs' -Tier 2 -Title 'PowerShell script block logs contain high-risk content' `
                -Observation ("{0} event(s) matched risk patterns. Most recent: {1} UTC." -f $flagged.Count, (@($flagged)[0].TimeCreatedUtc)) `
                -WhyItMatters 'Script block logging captures deobfuscated script content at execution time, which makes it some of the highest-value evidence available on a Windows endpoint.' `
                -Artifact (Get-ArtifactPath 'EventLogs' 'powershell_operational' 'csv') `
                -NextStep 'Read the full Message column for each matched event and reconstruct the script from multi-part 4104 records.'
        }
    }
    $defEvents = $Script:Data['defender_operational']
    if ($defEvents) {
        $cfg = @($defEvents | Where-Object { $_.EventId -in @(5001, 5007, 5010, 5012) })
        if ($cfg.Count -gt 0) {
            Add-Finding -Severity 'High' -Category 'EventLogs' -Tier 1 -Title 'Defender configuration or protection state was changed' `
                -Observation ("{0} configuration-change event(s) (5001/5007/5010/5012). Most recent: {1} UTC." -f $cfg.Count, (@($cfg)[0].TimeCreatedUtc)) `
                -WhyItMatters 'Event 5007 records the old and new value of a Defender setting, which is how exclusion additions and protection disables are attributed and timed.' `
                -Artifact (Get-ArtifactPath 'EventLogs' 'defender_operational' 'csv')
        }
        $detEvents = @($defEvents | Where-Object { $_.EventId -in @(1116, 1117) })
        if ($detEvents.Count -gt 0) {
            Add-Finding -Severity 'High' -Category 'EventLogs' -Tier 1 -Title 'Defender logged malware detections in the window' `
                -Observation ("{0} detection event(s) (1116/1117). Most recent: {1} UTC." -f $detEvents.Count, (@($detEvents)[0].TimeCreatedUtc)) `
                -WhyItMatters 'Detection events name the threat, the file path, and the process that introduced it, which anchors the earliest known point of the intrusion.' `
                -Artifact (Get-ArtifactPath 'EventLogs' 'defender_operational' 'csv')
        }
    }
    $rdpEvents = $Script:Data['terminal_services_remote']
    if ($rdpEvents) {
        $auth = @($rdpEvents | Where-Object { $_.EventId -eq 1149 })
        if ($auth.Count -gt 0) {
            Add-Finding -Severity 'Medium' -Category 'EventLogs' -Tier 1 -Title 'Successful RDP authentications recorded' `
                -Observation ("{0} event(s) with ID 1149 in the last {1} days. Most recent: {2} UTC." -f $auth.Count, $EventLogDays, (@($auth)[0].TimeCreatedUtc)) `
                -WhyItMatters 'Event 1149 carries the source IP address of the connecting client, which is the fastest way to separate expected administrative access from unexpected remote access.' `
                -Artifact (Get-ArtifactPath 'EventLogs' 'terminal_services_remote' 'csv')
        }
    }
    $wmiEvents = $Script:Data['wmi_activity']
    if ($wmiEvents) {
        $perm = @($wmiEvents | Where-Object { $_.EventId -in @(5860, 5861) })
        if ($perm.Count -gt 0) {
            Add-Finding -Severity 'Medium' -Category 'EventLogs' -Tier 2 -Title 'WMI permanent subscription activity recorded' `
                -Observation ("{0} event(s) with ID 5860/5861." -f $perm.Count) `
                -WhyItMatters 'Event 5861 records permanent event consumer registration, the core artifact of fileless WMI persistence. Legitimate management software also registers consumers.' `
                -Artifact (Get-ArtifactPath 'EventLogs' 'wmi_activity' 'csv') `
                -NextStep 'Compare against wmi_event_subscriptions.txt to see which subscriptions currently exist on the host.'
        }
    }

    # ---------- Software / drivers ----------
    $rat = $Script:Data['remote_access_tool_indicators']
    if ($rat -and @($rat).Count -gt 0) {
        Add-Finding -Severity 'Medium' -Category 'Software' -Tier 2 -Title 'Remote access or data transfer tooling present' `
            -Observation ("{0} indicator(s): {1}." -f @($rat).Count, (Format-Sample (@($rat) | ForEach-Object { "$($_.Source): $($_.Detail)" }) 6)) `
            -WhyItMatters 'Tools such as remote support agents, tunneling utilities, and bulk transfer clients are used legitimately by IT and are also the tools of choice for hands-on-keyboard access and exfiltration. Presence alone is not an indicator of compromise.' `
            -Artifact (Get-ArtifactPath 'Software' 'remote_access_tool_indicators' 'csv') `
            -NextStep 'Confirm each item against the approved software inventory and check install dates against the incident timeline.'
    }
    $drivers = $Script:Data['drivers']
    if ($drivers) {
        $unsignedDrv = @($drivers | Where-Object { $_.State -eq 'Running' -and $_.SignatureStatus -notin @('Valid', 'FileNotFound', 'NotHashed') })
        if ($unsignedDrv.Count -gt 0) {
            Add-Finding -Severity 'Medium' -Category 'Software' -Tier 2 -Title 'Running drivers without a valid signature' `
                -Observation ("{0} driver(s): {1}." -f $unsignedDrv.Count, (Format-Sample ($unsignedDrv | ForEach-Object { "$($_.Name) [$($_.SignatureStatus)]" }))) `
                -WhyItMatters 'Kernel drivers run with the highest privilege available. Unsigned or invalidly signed drivers are worth verifying, though signature checks on system drivers can fail for benign reasons including catalog-signed files.' `
                -Artifact (Get-ArtifactPath 'Software' 'drivers' 'csv')
        }
    }

    # ---------- Filesystem ----------
    $exes = $Script:Data['executables_in_user_writable_paths']
    if ($exes) {
        $recentUnsigned = @($exes | Where-Object {
                $_.SignatureStatus -notin @('Valid', 'NotHashed') -and
                $_.Extension -match '\.(exe|dll|scr|com|pif|sys)$'
            })
        if ($recentUnsigned.Count -gt 0) {
            $sev = 'Medium'
            if ($recentUnsigned.Count -gt 25) { $sev = 'Low' }
            Add-Finding -Severity $sev -Category 'Filesystem' -Tier 2 -Title 'Unsigned executables present in user-writable directories' `
                -Observation ("{0} file(s). Most recently modified: {1}." -f $recentUnsigned.Count, (Format-Sample ($recentUnsigned | ForEach-Object { "$($_.Path) ($($_.ModifiedUtc))" }) 5)) `
                -WhyItMatters 'Temp and AppData accumulate unsigned files from ordinary use (installers, updaters, browser downloads), so volume alone means little. The value here is having hashes and timestamps to filter against the incident window.' `
                -Artifact (Get-ArtifactPath 'Filesystem' 'executables_in_user_writable_paths' 'csv') `
                -NextStep 'Filter the artifact by ModifiedUtc within the suspected incident window and hash-check the survivors.'
        }
    }
    $ads = $Script:Data['alternate_data_streams']
    if ($ads) {
        $oddAds = @($ads | Where-Object { $_.Stream -ne 'Zone.Identifier' })
        if ($oddAds.Count -gt 0) {
            Add-Finding -Severity 'Medium' -Category 'Filesystem' -Tier 2 -Title 'Non-standard alternate data streams found' `
                -Observation ("{0} stream(s): {1}." -f $oddAds.Count, (Format-Sample ($oddAds | ForEach-Object { "$($_.File):$($_.Stream)" }) 4)) `
                -WhyItMatters 'ADS can hide executable content inside an otherwise innocuous file. Zone.Identifier streams are normal and are excluded from this count.' `
                -Artifact (Get-ArtifactPath 'Filesystem' 'alternate_data_streams' 'csv')
        }
    }
    $usb = $Script:Data['usb_device_history']
    if ($usb) {
        $usbstor = @($usb | Where-Object { $_.Source -eq 'USBSTOR' })
        if ($usbstor.Count -gt 0) {
            Add-Finding -Severity 'Info' -Category 'Filesystem' -Tier 1 -Title 'USB storage device history' `
                -Observation ("{0} USB storage device record(s). Sample: {1}." -f $usbstor.Count, (Format-Sample ($usbstor | ForEach-Object { $_.FriendlyName }) 5)) `
                -WhyItMatters 'USBSTOR records which removable devices have been attached. Registry presence establishes connection, not that files were copied.' `
                -Artifact (Get-ArtifactPath 'Filesystem' 'usb_device_history' 'csv')
        }
    }

    # ---------- WMI persistence ----------
    $wmiSubs = $Script:Data['wmi_event_subscriptions']
    if ($wmiSubs) {
        $text = ($wmiSubs -join "`n")
        if ($text -match '__EventFilter' -and $text -notmatch '(?s)=== __EventFilter ===\s*\(none\)') {
            Add-Finding -Severity 'Medium' -Category 'Persistence' -Tier 2 -Title 'WMI event subscriptions exist on this host' `
                -Observation 'One or more objects were returned from root\subscription (__EventFilter, __EventConsumer, or __FilterToConsumerBinding).' `
                -WhyItMatters 'WMI subscriptions provide fileless persistence that survives reboot and leaves no file on disk. Monitoring products (SCCM among them) also create subscriptions, so each one must be identified.' `
                -Artifact (Get-ArtifactPath 'Persistence' 'wmi_event_subscriptions' 'txt') `
                -NextStep 'Read the artifact and identify the consumer command for each binding. Anything invoking a script interpreter warrants immediate attention.'
        }
    }

    # ---------- Visibility gaps ----------
    $logCfg = $Script:Data['event_log_configuration']
    if ($logCfg) {
        $sysmon = @($logCfg | Where-Object { $_.LogName -like '*Sysmon*' -and $_.IsEnabled -eq 'NotPresent' })
        if ($sysmon.Count -gt 0) {
            Add-Finding -Severity 'Info' -Category 'EventLogs' -Tier 1 -Title 'Sysmon is not installed on this host' `
                -Observation 'The Microsoft-Windows-Sysmon/Operational log is not present.' `
                -WhyItMatters 'Without Sysmon, process creation with hashes, network connection attribution, and image load telemetry are largely unavailable. This limits what can be reconstructed and should be stated as a limitation in any report.' `
                -Artifact (Get-ArtifactPath 'EventLogs' 'event_log_configuration' 'csv')
        }
    }
    $procCreate = $Script:Data['security_process_creation']
    if (-not $procCreate -or @($procCreate).Count -eq 0) {
        Add-Finding -Severity 'Info' -Category 'EventLogs' -Tier 1 -Title 'No process creation events (4688) were collected' `
            -Observation 'The Security log returned no 4688 events for the collection window.' `
            -WhyItMatters 'Process creation auditing is off by default. The absence of these events is a logging gap, not evidence that no processes were created.' `
            -Artifact (Get-ArtifactPath 'Security' 'audit_policy' 'txt')
    }

    Write-Status ("Findings generated: {0}" -f $Script:Findings.Count) 'Good'
}

# ==============================================================================
#  HTML REPORT
# ==============================================================================

function New-HtmlReport {
    param([string]$Path)
    Write-Status 'Building HTML overview report' 'Step'

    $sb = New-Object System.Text.StringBuilder
    $osInfo = $Script:Data['os_info']
    $endUtc = (Get-Date).ToUniversalTime()
    $duration = [math]::Round(($endUtc - $Script:StartTimeUtc).TotalMinutes, 1)

    $sevOrder = @{ 'High' = 0; 'Medium' = 1; 'Low' = 2; 'Info' = 3 }
    $findings = $Script:Findings | Sort-Object @{ Expression = { $sevOrder[$_.Severity] } }, Category
    $counts = @{ High = 0; Medium = 0; Low = 0; Info = 0 }
    foreach ($f in $findings) { $counts[$f.Severity] = $counts[$f.Severity] + 1 }

    $css = @'
<style>
:root{
  --bg:#0b1016; --panel:#121a24; --panel2:#0f1720; --line:#22303f;
  --text:#dfe8f1; --muted:#8da0b4; --beam:#37d6ff; --beam2:#7cf5c4;
  --high:#ff5c6c; --med:#ffb340; --low:#7cc4ff; --info:#8fa3b8;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 "Segoe UI",system-ui,-apple-system,sans-serif}
a{color:var(--beam);text-decoration:none}
a:hover{text-decoration:underline}
.wrap{max-width:1240px;margin:0 auto;padding:28px 22px 80px}
header.hero{border:1px solid var(--line);border-radius:14px;padding:26px 28px;background:
  radial-gradient(1100px 200px at 12% -40%,rgba(55,214,255,.20),transparent 60%),
  linear-gradient(180deg,#121b26,#0e151e)}
.brand{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap}
.brand h1{margin:0;font-size:30px;letter-spacing:.5px}
.brand h1 span{color:var(--beam)}
.tagline{color:#93a7bb;font-size:13px;font-style:italic}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(215px,1fr));gap:10px 26px;margin-top:20px}
.meta div{font-size:13px;color:#a9bccf}
.meta b{display:block;color:#6f8399;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.9px;margin-bottom:2px}
.notice{margin-top:18px;border-left:3px solid var(--med);background:rgba(255,179,64,.08);padding:12px 16px;border-radius:0 8px 8px 0;font-size:13px;color:#e8d4b4}
h2{font-size:17px;margin:34px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line);letter-spacing:.3px}
h2 small{color:#6f8399;font-weight:400;font-size:12px;margin-left:8px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:16px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:14px 16px}
.card .n{font-size:26px;font-weight:600;line-height:1.1}
.card .l{font-size:11px;text-transform:uppercase;letter-spacing:.9px;color:#7f93a8;margin-top:4px}
.c-high .n{color:var(--high)} .c-med .n{color:var(--med)} .c-low .n{color:var(--low)} .c-info .n{color:var(--info)}
.controls{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:14px 0 18px}
.btn{background:var(--panel);border:1px solid var(--line);color:#b9cadb;border-radius:20px;padding:6px 15px;font-size:12.5px;cursor:pointer}
.btn:hover{border-color:var(--beam);color:#fff}
.btn.on{background:rgba(55,214,255,.14);border-color:var(--beam);color:#fff}
input[type=search]{flex:1;min-width:230px;background:var(--panel2);border:1px solid var(--line);border-radius:20px;color:var(--text);padding:7px 15px;font-size:13px}
.finding{background:var(--panel);border:1px solid var(--line);border-left-width:4px;border-radius:10px;margin-bottom:11px;overflow:hidden}
.f-high{border-left-color:var(--high)} .f-med{border-left-color:var(--med)}
.f-low{border-left-color:var(--low)} .f-info{border-left-color:var(--info)}
.f-head{display:flex;gap:12px;align-items:center;padding:13px 16px;cursor:pointer}
.f-head:hover{background:rgba(255,255,255,.02)}
.chip{font-size:10.5px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;padding:3px 9px;border-radius:20px;white-space:nowrap}
.chip-high{background:rgba(255,92,108,.16);color:var(--high)}
.chip-med{background:rgba(255,179,64,.16);color:var(--med)}
.chip-low{background:rgba(124,196,255,.14);color:var(--low)}
.chip-info{background:rgba(143,163,184,.16);color:var(--info)}
.chip-cat{background:rgba(124,245,196,.10);color:var(--beam2)}
.chip-tier{background:rgba(255,255,255,.06);color:#9db1c5}
.f-title{flex:1;font-weight:600}
.f-body{display:none;padding:2px 18px 18px;border-top:1px solid var(--line)}
.finding.open .f-body{display:block}
.f-body p{margin:12px 0 0;line-height:1.55}
.f-body .obs-block{margin:12px 0 0}
.f-body .lbl{font-size:11px;text-transform:uppercase;letter-spacing:.9px;color:#6f8399;display:block;margin-bottom:6px}
.f-body .obs{display:block;background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:12px 14px;font-family:ui-monospace,Consolas,monospace;font-size:12.5px;line-height:1.55;word-break:break-word}
.obs-lead{margin:0;color:var(--text);font-family:inherit;line-height:1.55}
.obs-list{margin:8px 0 0;padding:0 0 0 18px;line-height:1.55}
.obs-list li{margin:0 0 8px;padding:0;line-height:1.55}
.obs-list li:last-child{margin-bottom:0}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden;font-size:12.5px}
th{background:var(--panel2);text-align:left;padding:9px 12px;color:#8fa3b8;font-size:11px;text-transform:uppercase;letter-spacing:.8px;border-bottom:1px solid var(--line)}
td{padding:8px 12px;border-bottom:1px solid rgba(34,48,63,.6);vertical-align:top;word-break:break-word}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(255,255,255,.02)}
.ok{color:var(--beam2)} .bad{color:var(--high)} .warn{color:var(--med)} .dim{color:#7f93a8}
details.method{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 18px;margin-top:12px}
details.method summary{cursor:pointer;font-weight:600}
details.method p,details.method li{color:#b6c7d8;font-size:13px}
footer{margin-top:40px;padding-top:16px;border-top:1px solid var(--line);color:#6f8399;font-size:12px}
.hidden{display:none!important}
</style>
'@

    $js = @'
<script>
(function(){
  document.addEventListener("click",function(e){
    var h=e.target.closest(".f-head");
    if(h){h.parentElement.classList.toggle("open");return;}
    var b=e.target.closest(".btn[data-sev]");
    if(b){
      document.querySelectorAll(".btn[data-sev]").forEach(function(x){x.classList.remove("on")});
      b.classList.add("on");
      applyFilters();
    }
  });
  var box=document.getElementById("q");
  if(box){box.addEventListener("input",applyFilters);}
  function applyFilters(){
    var active=document.querySelector(".btn[data-sev].on");
    var sev=active?active.getAttribute("data-sev"):"all";
    var q=(box&&box.value||"").toLowerCase();
    var shown=0;
    document.querySelectorAll(".finding").forEach(function(f){
      var okSev=(sev==="all"||f.getAttribute("data-sev")===sev);
      var okQ=(q===""||f.textContent.toLowerCase().indexOf(q)>-1);
      if(okSev&&okQ){f.classList.remove("hidden");shown++;}else{f.classList.add("hidden");}
    });
    var none=document.getElementById("nores");
    if(none){none.style.display=shown?"none":"block";}
  }
  document.querySelectorAll(".finding").forEach(function(f){
    if(f.getAttribute("data-sev")==="High"){f.classList.add("open");}
  });
})();
</script>
'@

    $null = $sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
    $null = $sb.AppendLine('<meta name="viewport" content="width=device-width,initial-scale=1">')
    $null = $sb.AppendLine("<title>WinFoton Triage Report - $(ConvertTo-SafeHtml $env:COMPUTERNAME)</title>")
    $null = $sb.AppendLine($css)
    $null = $sb.AppendLine('</head><body><div class="wrap">')

    # ---- Hero ----
    $null = $sb.AppendLine('<header class="hero">')
    $null = $sb.AppendLine('<div class="brand"><h1>Win<span>Foton</span></h1><div class="tagline">Windows DFIR triage collection - light through the glass</div></div>')
    $null = $sb.AppendLine('<div class="meta">')
    $null = $sb.AppendLine("<div><b>Hostname</b>$(ConvertTo-SafeHtml $env:COMPUTERNAME)</div>")
    if ($osInfo) {
        $null = $sb.AppendLine("<div><b>Operating System</b>$(ConvertTo-SafeHtml ("{0} (build {1})" -f $osInfo.Caption, $osInfo.BuildNumber))</div>")
        $null = $sb.AppendLine("<div><b>Domain</b>$(ConvertTo-SafeHtml ([string]$osInfo.Domain))</div>")
        $null = $sb.AppendLine("<div><b>Last Boot (UTC)</b>$(ConvertTo-SafeHtml ([string]$osInfo.LastBootUtc)) &middot; up $(ConvertTo-SafeHtml ([string]$osInfo.UptimeDays))d</div>")
    }
    $caseDisplay = $CaseNumber
    if (-not $caseDisplay) { $caseDisplay = '(not supplied)' }
    $null = $sb.AppendLine("<div><b>Case</b>$(ConvertTo-SafeHtml $caseDisplay)</div>")
    $null = $sb.AppendLine("<div><b>Examiner</b>$(ConvertTo-SafeHtml $Examiner)</div>")
    $null = $sb.AppendLine("<div><b>Collected (UTC)</b>$($Script:StartTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')) - $($endUtc.ToString('HH:mm:ss')) ($duration min)</div>")
    $null = $sb.AppendLine("<div><b>Event Window</b>Last $EventLogDays days</div>")
    $null = $sb.AppendLine("<div><b>Privilege</b>$(if ($Script:IsElevated) { 'Elevated (Administrator)' } else { 'Standard user — reduced coverage' })</div>")
    $null = $sb.AppendLine('</div>')
    $null = $sb.AppendLine('<div class="notice"><b>Read this first.</b> Every item below is an automated observation produced by pattern matching, not a conclusion. Nothing here establishes that this host is compromised. Each finding cites the artifact file it came from - verify against that artifact, and against the host owner''s expectations, before it goes anywhere near a report or a remediation decision.</div>')
    $null = $sb.AppendLine('</header>')

    # ---- Counts ----
    $null = $sb.AppendLine('<h2>Triage Summary</h2>')
    $null = $sb.AppendLine('<div class="cards">')
    $null = $sb.AppendLine("<div class=""card c-high""><div class=""n"">$($counts['High'])</div><div class=""l"">High attention</div></div>")
    $null = $sb.AppendLine("<div class=""card c-med""><div class=""n"">$($counts['Medium'])</div><div class=""l"">Medium</div></div>")
    $null = $sb.AppendLine("<div class=""card c-low""><div class=""n"">$($counts['Low'])</div><div class=""l"">Low</div></div>")
    $null = $sb.AppendLine("<div class=""card c-info""><div class=""n"">$($counts['Info'])</div><div class=""l"">Informational</div></div>")
    $procCount = 0
    if ($Script:Data['running_processes']) { $procCount = @($Script:Data['running_processes']).Count }
    $svcCount = 0
    if ($Script:Data['services']) { $svcCount = @($Script:Data['services']).Count }
    $taskCount = 0
    if ($Script:Data['scheduled_tasks']) { $taskCount = @($Script:Data['scheduled_tasks']).Count }
    $connCount = 0
    if ($Script:Data['active_connections']) { $connCount = @($Script:Data['active_connections']).Count }
    $null = $sb.AppendLine('</div>')
    $null = $sb.AppendLine('<div class="cards">')
    $null = $sb.AppendLine("<div class=""card""><div class=""n"">$procCount</div><div class=""l"">Processes</div></div>")
    $null = $sb.AppendLine("<div class=""card""><div class=""n"">$svcCount</div><div class=""l"">Services</div></div>")
    $null = $sb.AppendLine("<div class=""card""><div class=""n"">$taskCount</div><div class=""l"">Scheduled tasks</div></div>")
    $null = $sb.AppendLine("<div class=""card""><div class=""n"">$connCount</div><div class=""l"">Connections</div></div>")
    $null = $sb.AppendLine('</div>')

    # ---- Findings ----
    $null = $sb.AppendLine('<h2>Observations<small>click any row to expand</small></h2>')
    $null = $sb.AppendLine('<div class="controls">')
    $null = $sb.AppendLine('<button class="btn on" data-sev="all">All</button><button class="btn" data-sev="High">High</button><button class="btn" data-sev="Medium">Medium</button><button class="btn" data-sev="Low">Low</button><button class="btn" data-sev="Info">Info</button>')
    $null = $sb.AppendLine('<input id="q" type="search" placeholder="Filter observations (e.g. defender, persistence, rdp)">')
    $null = $sb.AppendLine('</div>')

    foreach ($f in $findings) {
        $cls = 'f-info'; $chip = 'chip-info'
        switch ($f.Severity) {
            'High' { $cls = 'f-high'; $chip = 'chip-high' }
            'Medium' { $cls = 'f-med'; $chip = 'chip-med' }
            'Low' { $cls = 'f-low'; $chip = 'chip-low' }
        }
        $null = $sb.AppendLine("<div class=""finding $cls"" data-sev=""$($f.Severity)"">")
        $null = $sb.AppendLine('<div class="f-head">')
        $null = $sb.AppendLine("<span class=""chip $chip"">$($f.Severity)</span>")
        $null = $sb.AppendLine("<span class=""chip chip-cat"">$(ConvertTo-SafeHtml $f.Category)</span>")
        $null = $sb.AppendLine("<span class=""f-title"">$(ConvertTo-SafeHtml $f.Title)</span>")
        $null = $sb.AppendLine("<span class=""chip chip-tier"">Tier $($f.Tier)</span>")
        $null = $sb.AppendLine('</div><div class="f-body">')
        $null = $sb.AppendLine('<div class="obs-block"><span class="lbl">What was observed</span>')
        $null = $sb.AppendLine((ConvertTo-ObservationHtml $f.Observation))
        $null = $sb.AppendLine('</div>')
        if ($f.WhyItMatters) {
            $null = $sb.AppendLine("<p><span class=""lbl"">Why it matters</span>$(ConvertTo-SafeHtml $f.WhyItMatters)</p>")
        }
        if ($f.NextStep) {
            $null = $sb.AppendLine("<p><span class=""lbl"">Suggested next step</span>$(ConvertTo-SafeHtml $f.NextStep)</p>")
        }
        if ($f.Artifact) {
            $null = $sb.AppendLine("<p><span class=""lbl"">Source artifact</span><a href=""$(ConvertTo-SafeHtml $f.Artifact)"">$(ConvertTo-SafeHtml $f.Artifact)</a></p>")
        }
        $null = $sb.AppendLine('</div></div>')
    }
    $null = $sb.AppendLine('<div id="nores" style="display:none;color:#7f93a8;padding:14px">No observations match the current filter.</div>')

    # ---- Quick reference tables ----
    $admins = @()
    if ($Script:Data['local_group_membership']) {
        $admins = @($Script:Data['local_group_membership'] | Where-Object { $_.Group -eq 'Administrators' -and $_.Member -ne '(none)' })
    }
    if ($admins.Count -gt 0) {
        $null = $sb.AppendLine('<h2>Local Administrators<small>compare against the expected baseline</small></h2><table><tr><th>Member</th><th>Type</th><th>Source</th><th>SID</th></tr>')
        foreach ($a in $admins) {
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-SafeHtml $a.Member)</td><td>$(ConvertTo-SafeHtml $a.ObjectClass)</td><td>$(ConvertTo-SafeHtml $a.PrincipalSource)</td><td class=""dim"">$(ConvertTo-SafeHtml $a.SID)</td></tr>")
        }
        $null = $sb.AppendLine('</table>')
    }

    $ext = @()
    if ($Script:Data['active_connections']) {
        $ext = @($Script:Data['active_connections'] | Where-Object { $_.RemoteIsExternal -eq $true } | Select-Object -First 40)
    }
    if ($ext.Count -gt 0) {
        $null = $sb.AppendLine('<h2>External Network Connections<small>point-in-time snapshot at collection</small></h2><table><tr><th>Process</th><th>PID</th><th>Remote</th><th>State</th><th>Path</th></tr>')
        foreach ($c in $ext) {
            $pathClass = 'dim'
            if ($c.UserWritablePath -eq $true) { $pathClass = 'warn' }
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-SafeHtml $c.ProcessName)</td><td>$(ConvertTo-SafeHtml ([string]$c.OwningPID))</td><td>$(ConvertTo-SafeHtml ("{0}:{1}" -f $c.RemoteAddress, $c.RemotePort))</td><td>$(ConvertTo-SafeHtml $c.State)</td><td class=""$pathClass"">$(ConvertTo-SafeHtml $c.ProcessPath)</td></tr>")
        }
        $null = $sb.AppendLine('</table>')
    }

    if ($Script:Data['hardening_registry_settings']) {
        $mismatch = @($Script:Data['hardening_registry_settings'] | Where-Object { $_.MatchesRecommended -eq $false -and $_.RecommendedValue -ne '' })
        if ($mismatch.Count -gt 0) {
            $null = $sb.AppendLine('<h2>Hardening Settings Not At Recommended Value<small>configuration review, not compromise indicators</small></h2><table><tr><th>Setting</th><th>Current</th><th>Recommended</th><th>Meaning</th></tr>')
            foreach ($m in $mismatch) {
                $null = $sb.AppendLine("<tr><td>$(ConvertTo-SafeHtml $m.Setting)</td><td class=""warn"">$(ConvertTo-SafeHtml $m.Value)</td><td class=""dim"">$(ConvertTo-SafeHtml $m.RecommendedValue)</td><td>$(ConvertTo-SafeHtml $m.Meaning)</td></tr>")
            }
            $null = $sb.AppendLine('</table>')
        }
    }

    # ---- Manifest ----
    $null = $sb.AppendLine('<h2>Collection Manifest<small>every artifact in this package</small></h2><table><tr><th>Category</th><th>Artifact</th><th>What it contains</th><th>Records</th><th>Status</th></tr>')
    foreach ($m in $Script:Manifest) {
        $statusClass = 'ok'
        if ($m.Status -eq 'NoData') { $statusClass = 'dim' }
        elseif ($m.Status -ne 'Success') { $statusClass = 'bad' }
        $link = ($m.File -replace '\\', '/')
        $null = $sb.AppendLine("<tr><td class=""dim"">$(ConvertTo-SafeHtml $m.Category)</td><td><a href=""$(ConvertTo-SafeHtml $link)"">$(ConvertTo-SafeHtml (Split-Path $m.File -Leaf))</a></td><td>$(ConvertTo-SafeHtml $m.Description)</td><td>$($m.Records)</td><td class=""$statusClass"">$(ConvertTo-SafeHtml $m.Status)</td></tr>")
    }
    $null = $sb.AppendLine('</table>')

    if ($Script:Errors.Count -gt 0) {
        $null = $sb.AppendLine('<h2>Collection Errors<small>gaps to disclose in any report built from this data</small></h2><table><tr><th>Task</th><th>Error</th></tr>')
        foreach ($e in $Script:Errors) {
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-SafeHtml $e.Task)</td><td class=""warn"">$(ConvertTo-SafeHtml $e.Error)</td></tr>")
        }
        $null = $sb.AppendLine('</table>')
    }

    # ---- Methodology ----
    $null = $sb.AppendLine('<h2>Methodology, Tiers, and Limitations</h2>')
    $null = $sb.AppendLine(@'
<details class="method" open><summary>How to read the tiers</summary>
<p><b>Tier 1 - Observed artifact.</b> Directly present in the collected data, no interpretation applied. A registry value, an event ID, a signature status. State these as fact.</p>
<p><b>Tier 2 - Supported inference.</b> A reasonable reading of one or more Tier 1 artifacts where other readings remain possible. An unsigned binary in AppData holding an outbound connection is consistent with C2 and equally consistent with a portable application. Cite the artifact and name the assumption.</p>
<p><b>Tier 3 - Unverified hypothesis.</b> Not stated as findings by this tool. If you form one during analysis, record what evidence would move it to Tier 2.</p>
</details>
'@)
    $null = $sb.AppendLine(@'
<details class="method"><summary>Limitations of this collection</summary>
<ul>
<li><b>Live collection.</b> Running this tool altered the host: a process was created, files were written, event log entries were generated, and prefetch and AmCache were updated. No memory image and no disk image were produced.</li>
<li><b>Point-in-time volatile data.</b> Process, connection, and session data reflect the moment of collection only. Activity that ended before collection is absent from those artifacts.</li>
<li><b>Log retention bounds the window.</b> Event data is limited to the configured window and to what retention preserved. Where a log was cleared, everything before that point is unavailable from this host.</li>
<li><b>Heuristics are not detections.</b> The pattern lists used here match on common attacker tradecraft and also match legitimate administrative tooling. Expect false positives, and treat an empty findings list as an absence of matched patterns, not an absence of compromise.</li>
<li><b>Signature status is not integrity.</b> A valid signature does not mean the binary is benign, and an invalid one does not mean it is malicious. Catalog-signed system files frequently return non-Valid status.</li>
<li><b>No anti-rootkit capability.</b> All data is gathered through the operating system''s own APIs. Kernel-level tampering could render any of it unreliable.</li>
<li><b>Standard-user coverage.</b> If this package was collected without Administrator rights, the Security log, Prefetch, VSS, secedit/auditpol, and other users'' artifacts were skipped by design. See 00_Collection/collection_coverage.json. Do not read those gaps as a clean host.</li>
<li><b>Timestamps.</b> All times are UTC as reported by this host. Verify the host clock against the time source data before building a timeline, and note that file MACB times are trivially modifiable.</li>
</ul>
</details>
'@)

    $null = $sb.AppendLine("<footer>WinFoton v$Script:Version &middot; collected $($Script:StartTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC on $(ConvertTo-SafeHtml $env:COMPUTERNAME) by $(ConvertTo-SafeHtml $Examiner) &middot; verify artifact hashes in 00_Collection/hashes.csv before analysis</footer>")
    $null = $sb.AppendLine('</div>')
    $null = $sb.AppendLine($js)
    $null = $sb.AppendLine('</body></html>')

    $sb.ToString() | Out-File -FilePath $Path -Encoding UTF8
    Write-Status "Report written: $Path" 'Good'
}

# ==============================================================================
#  PACKAGING
# ==============================================================================

function Write-ManifestFiles {
    $manifestCsv = Join-Path $Script:Dirs['Collection'] 'collection_manifest.csv'
    $Script:Manifest | Export-Csv -Path $manifestCsv -NoTypeInformation -Encoding UTF8

    $findingsCsv = Join-Path $Script:Dirs['Collection'] 'findings.csv'
    if ($Script:Findings.Count -gt 0) {
        $Script:Findings | Export-Csv -Path $findingsCsv -NoTypeInformation -Encoding UTF8
    }

    if ($Script:Errors.Count -gt 0) {
        $Script:Errors | Export-Csv -Path (Join-Path $Script:Dirs['Collection'] 'collection_errors.csv') -NoTypeInformation -Encoding UTF8
    }
}

function Write-ArtifactHashes {
    Write-Status 'Hashing collected artifacts (SHA-256)' 'Step'
    $rows = @()
    foreach ($f in (Get-ChildItem -LiteralPath $Script:CaseRoot -Recurse -File -ErrorAction SilentlyContinue)) {
        if ($f.Name -eq 'hashes.csv' -or $f.Name -eq 'hashes.txt') { continue }
        $hash = ''
        try { $hash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch { $hash = 'HASH_ERROR' }
        $rel = $f.FullName.Substring($Script:CaseRoot.Length).TrimStart('\')
        $rows += [PSCustomObject]@{
            RelativePath = $rel
            SizeBytes    = $f.Length
            SHA256       = $hash
            ModifiedUtc  = $f.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
        }
    }
    $rows | Export-Csv -Path (Join-Path $Script:Dirs['Collection'] 'hashes.csv') -NoTypeInformation -Encoding UTF8
    $txt = @()
    $txt += "WinFoton artifact hashes (SHA-256) - generated $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC"
    $txt += ''
    foreach ($r in $rows) { $txt += ("{0}  {1}" -f $r.SHA256, $r.RelativePath) }
    $txt | Out-File -FilePath (Join-Path $Script:Dirs['Collection'] 'hashes.txt') -Encoding UTF8
    Write-Status ("Hashed {0} artifacts" -f $rows.Count) 'Good'
    return $rows.Count
}

function Compress-CasePackage {
    Write-Status 'Compressing case package' 'Step'
    $zipPath = "$Script:CaseRoot.zip"
    try {
        if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        [System.IO.Compression.ZipFile]::CreateFromDirectory($Script:CaseRoot, $zipPath,
            [System.IO.Compression.CompressionLevel]::Optimal, $true)
        return $zipPath
    }
    catch {
        try {
            Compress-Archive -Path (Join-Path $Script:CaseRoot '*') -DestinationPath $zipPath -Force -ErrorAction Stop
            return $zipPath
        }
        catch {
            Write-Status "Compression failed: $($_.Exception.Message). The uncompressed case folder is still available." 'Warn'
            return $null
        }
    }
}

# ==============================================================================
#  MAIN
# ==============================================================================

function Show-Banner {
    Write-Host ''
    Write-Host '  +--------------------------------------------------------+' -ForegroundColor DarkCyan
    Write-Host '  |                                                        |' -ForegroundColor DarkCyan
    Write-Host '  |     W i n F o t o n        >>>>>|::|>>>>>              |' -ForegroundColor Cyan
    Write-Host '  |     Windows DFIR triage collector                      |' -ForegroundColor Gray
    Write-Host '  |                                                        |' -ForegroundColor DarkCyan
    Write-Host '  +--------------------------------------------------------+' -ForegroundColor DarkCyan
    Write-Host "   v$Script:Version   Light through the glass." -ForegroundColor DarkGray
    Write-Host ''
}

function Invoke-WinFoton {
    Show-Banner

    if ($env:OS -ne 'Windows_NT') {
        Write-Host '  [x] WinFoton runs on Windows only.' -ForegroundColor Red
        return
    }

    $elevated = Test-Elevated
    $Script:IsElevated = $elevated

    if ($RequireAdministrator -and -not $elevated) {
        Write-Host '  [x] -RequireAdministrator was set, but this process is not elevated.' -ForegroundColor Red
        Write-Host '      Re-run from an elevated PowerShell, or omit -RequireAdministrator' -ForegroundColor Red
        Write-Host '      to collect with standard-user coverage.' -ForegroundColor Red
        return
    }

    if (-not $elevated) {
        Write-Host '  [!] Standard-user coverage (not Administrator).' -ForegroundColor Yellow
        Write-Host '      Still collected: this user''s processes, readable network state,' -ForegroundColor Yellow
        Write-Host '      HKCU persistence, profile files, and any logs the token can read.' -ForegroundColor Yellow
        Write-Host '      Skipped: Security log, Prefetch, VSS, auditpol/secedit, other users.' -ForegroundColor Yellow
        Write-Host '      Use -RequireAdministrator to refuse to run in this mode.' -ForegroundColor DarkGray
        Write-Host ''
    }

    $caseRoot = Initialize-Case
    Write-Status "Case folder: $caseRoot" 'Good'
    Write-Status "Examiner: $Examiner | Case: $(if ($CaseNumber) { $CaseNumber } else { 'not supplied' }) | Coverage: $(if ($elevated) { 'Elevated' } else { 'StandardUser' })" 'Info'
    Write-ChainOfCustody

    if ($LoadUserHives) {
        if (-not $elevated) {
            Write-Status 'LoadUserHives ignored: mounting NTUSER.DAT requires elevation' 'Warn'
        }
        else {
            Write-Status 'Mounting offline user registry hives' 'Step'
            $mounted = Mount-OfflineUserHives
            $Script:LoadUserHivesActive = $true
            Write-Status ("Mounted {0} offline hive(s)" -f @($mounted).Count) 'Info'
        }
    }

    try {
        # Volatility order: most volatile first.
        Invoke-ProcessCollection
        Invoke-NetworkCollection
        Invoke-UserCollection
        Invoke-SystemCollection
        Invoke-PersistenceCollection
        Invoke-SecurityCollection
        Invoke-SoftwareCollection
        Invoke-EventLogCollection
        Invoke-FilesystemCollection

        Write-CollectionCoverage
        Invoke-FindingsAnalysis
    }
    finally {
        if ($Script:LoadUserHivesActive) {
            Write-Status 'Unmounting offline user registry hives' 'Step'
            Dismount-OfflineUserHives
        }
    }

    Write-ManifestFiles
    $reportPath = Join-Path $Script:CaseRoot 'WinFoton_Report.html'
    New-HtmlReport -Path $reportPath
    $artifactCount = Write-ArtifactHashes

    $zipPath = $null
    if (-not $NoZip) {
        $zipPath = Compress-CasePackage
    }

    $zipHash = ''
    $zipSizeMb = 0
    if ($zipPath -and (Test-Path -LiteralPath $zipPath)) {
        try { $zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash } catch { $zipHash = 'HASH_ERROR' }
        $zipSizeMb = [math]::Round((Get-Item -LiteralPath $zipPath).Length / 1MB, 2)
        $stamp = @()
        $stamp += 'WinFoton package integrity record'
        $stamp += ''
        $stamp += "Package      : $(Split-Path $zipPath -Leaf)"
        $stamp += "SHA-256      : $zipHash"
        $stamp += "Size (MB)    : $zipSizeMb"
        $stamp += "Created UTC  : $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'))"
        $stamp += "Host         : $env:COMPUTERNAME"
        $stamp += "Examiner     : $Examiner"
        $stamp += "Case         : $CaseNumber"
        $stamp += ''
        $stamp += 'Record this hash on receipt and verify it at every custody transfer:'
        $stamp += '  Get-FileHash -Algorithm SHA256 <package.zip>'
        $stamp | Out-File -FilePath ("$Script:CaseRoot" + '_PACKAGE_HASH.txt') -Encoding UTF8
    }

    $sevCounts = @{ High = 0; Medium = 0; Low = 0; Info = 0 }
    foreach ($f in $Script:Findings) { $sevCounts[$f.Severity] = $sevCounts[$f.Severity] + 1 }

    Write-Host ''
    Write-Host '  ============================================================' -ForegroundColor Cyan
    Write-Host '   COLLECTION COMPLETE' -ForegroundColor Cyan
    Write-Host '  ============================================================' -ForegroundColor Cyan
    Write-Host ("   Artifacts collected : {0} files across {1} categories" -f $artifactCount, $Script:Categories.Count)
    Write-Host ("   Collection errors   : {0}" -f $Script:Errors.Count)
    Write-Host ("   Observations        : {0} high, {1} medium, {2} low, {3} info" -f `
            $sevCounts['High'], $sevCounts['Medium'], $sevCounts['Low'], $sevCounts['Info'])
    Write-Host ("   Duration            : {0} min" -f [math]::Round(((Get-Date).ToUniversalTime() - $Script:StartTimeUtc).TotalMinutes, 1))
    Write-Host ''
    Write-Host "   Case folder : $Script:CaseRoot" -ForegroundColor White
    Write-Host "   Report      : $reportPath" -ForegroundColor White
    if ($zipPath) {
        Write-Host "   Package     : $zipPath ($zipSizeMb MB)" -ForegroundColor White
        Write-Host "   SHA-256     : $zipHash" -ForegroundColor Green
    }
    Write-Host ''
    Write-Host '   Open WinFoton_Report.html from inside the extracted folder so' -ForegroundColor DarkGray
    Write-Host '   the artifact links resolve. Findings are automated observations,' -ForegroundColor DarkGray
    Write-Host '   not conclusions - verify each one against its source artifact.' -ForegroundColor DarkGray
    Write-Host ''
}

Invoke-WinFoton