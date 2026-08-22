# Initialize-FotonSession
#
# Resets module session state used by Collect, Analyze, and Report.
# Never use $global:. Keys are documented here as they are introduced.
#
# Heuristic strings live in src/Private/Patterns/*.txt so this .ps1 is not
# flagged by AMSI/AV for containing LOLBin substrings (same lists as WinFoton.ps1).

function Initialize-FotonSession {
    param(
        [switch]$SkipHashing,
        [int]$EventLogDays = 14,
        [int]$MaxEventsPerLog = 3000,
        [switch]$SkipEvtxExport,
        [switch]$IncludeFileTimeline
    )

    $keepVersion = $null
    if ($null -ne $script:FotonSession -and $script:FotonSession.ContainsKey('Version')) {
        $keepVersion = $script:FotonSession.Version
    }

    $script:FotonSession = @{
        Version                   = $keepVersion
        Data                      = @{}
        Findings                  = New-Object System.Collections.ArrayList
        Manifest                  = New-Object System.Collections.ArrayList
        Errors                    = New-Object System.Collections.ArrayList
        Package                   = $null
        Dirs                      = @{}
        LogFile                   = $null
        CaseRoot                  = $null
        StartTimeUtc              = $null
        LoadedHives               = New-Object System.Collections.ArrayList
        IsElevated                = $false
        SkipHashing               = [bool]$SkipHashing
        EventLogDays              = $EventLogDays
        MaxEventsPerLog           = $MaxEventsPerLog
        SkipEvtxExport            = [bool]$SkipEvtxExport
        IncludeFileTimeline       = [bool]$IncludeFileTimeline
        LoadUserHivesActive       = $false
        HiveMountPrefix           = 'Foton'
        Categories                = [ordered]@{
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
        UserWritablePatterns      = @()
        SuspiciousCommandPatterns = @()
        RemoteAccessToolNames     = @()
        HardeningRegistryChecks   = @()
        PatternSource             = $null
    }

    Import-FotonPatternTables
}

function Import-FotonPatternTables {
    <#
        Fill pattern lists on the current session. Does not replace $script:FotonSession
        (baseline providers must not wipe StartTimeUtc / CaseRoot mid-capture).
    #>
    if ($null -eq $script:FotonSession) { return }

    $writable = @()
    $suspicious = @()
    $ratNames = @()
    $hardening = @()
    $patternDir = $null

    if ($script:FotonEmbeddedPatterns) {
        $patternDir = '(embedded)'
        $writable = @($script:FotonEmbeddedPatterns.UserWritablePatterns)
        $suspicious = @($script:FotonEmbeddedPatterns.SuspiciousCommandPatterns)
        $ratNames = @($script:FotonEmbeddedPatterns.RemoteAccessToolNames)
        if ($script:FotonEmbeddedPatterns.HardeningCsv) {
            $hardening = @($script:FotonEmbeddedPatterns.HardeningCsv | ConvertFrom-Csv)
        }
    }
    elseif ($script:FotonSrcRoot) {
        $patternDir = Join-Path $script:FotonSrcRoot 'Private\Patterns'
        $writable = @(Get-FotonPatternLines -Path (Join-Path $patternDir 'UserWritablePatterns.txt'))
        $suspicious = @(Get-FotonPatternLines -Path (Join-Path $patternDir 'SuspiciousCommandPatterns.txt'))
        $ratNames = @(Get-FotonPatternLines -Path (Join-Path $patternDir 'RemoteAccessToolNames.txt'))
        $hardeningFile = Join-Path $patternDir 'HardeningRegistryChecks.csv'
        if (Test-Path -LiteralPath $hardeningFile) {
            $hardening = @(Import-Csv -LiteralPath $hardeningFile)
        }
    }

    if ($writable.Count -gt 0) { $script:FotonSession.UserWritablePatterns = $writable }
    if ($suspicious.Count -gt 0) { $script:FotonSession.SuspiciousCommandPatterns = $suspicious }
    if ($ratNames.Count -gt 0) { $script:FotonSession.RemoteAccessToolNames = $ratNames }
    if ($hardening.Count -gt 0) { $script:FotonSession.HardeningRegistryChecks = $hardening }
    if ($patternDir) { $script:FotonSession.PatternSource = $patternDir }
}
