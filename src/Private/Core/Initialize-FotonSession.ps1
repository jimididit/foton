# Initialize-FotonSession
#
# Resets module session state used by Collect, Analyze, and Report.
# Never use $global:. Keys are documented here as they are introduced.
#
# Heuristic strings live in src/Private/Patterns/*.txt so this .ps1 is not
# flagged by AMSI/AV for containing LOLBin substrings (same lists as WinFoton.ps1).

function Initialize-FotonSession {
    param(
        [switch]$SkipHashing
    )

    $keepVersion = $null
    if ($null -ne $script:FotonSession -and $script:FotonSession.ContainsKey('Version')) {
        $keepVersion = $script:FotonSession.Version
    }

    $writable = @()
    $suspicious = @()
    $patternDir = Join-Path $script:FotonSrcRoot 'Private\Patterns'
    $writableFile = Join-Path $patternDir 'UserWritablePatterns.txt'
    $suspiciousFile = Join-Path $patternDir 'SuspiciousCommandPatterns.txt'
    if (Test-Path -LiteralPath $writableFile) {
        $writable = @(Get-Content -LiteralPath $writableFile -ErrorAction SilentlyContinue |
                Where-Object { $_ -and $_.Trim() -notmatch '^#' })
    }
    if (Test-Path -LiteralPath $suspiciousFile) {
        $suspicious = @(Get-Content -LiteralPath $suspiciousFile -ErrorAction SilentlyContinue |
                Where-Object { $_ -and $_.Trim() -notmatch '^#' })
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
        UserWritablePatterns      = $writable
        SuspiciousCommandPatterns = $suspicious
        PatternSource             = $patternDir
    }
}
