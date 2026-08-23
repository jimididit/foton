# Invoke-FotonSecurityCollection
# Live facts only. Called from Invoke-FotonTriage when that exists.
# Endpoint collect. Rebuild dist/Foton-Collect.ps1 after edits.

function Invoke-FotonSecurityCollection {
    Write-FotonStatus 'Collecting security posture, AV state, logging and hardening configuration' 'Step'

    Invoke-FotonCollection -Category 'Security' -Name 'defender_status' -Description 'Microsoft Defender engine, signature, and protection state' -Script {
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

    Invoke-FotonCollection -Category 'Security' -Name 'defender_preferences_and_exclusions' -Description 'Defender preferences, including exclusion paths/processes/extensions' -Script {
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

    Invoke-FotonCollection -Category 'Security' -Name 'defender_detections' -Format 'Csv' -Description 'Defender threat detection history' -Script {
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

    Invoke-FotonCollection -Category 'Security' -Name 'installed_av_products' -Format 'Csv' -Description 'Registered AV products from Security Center' -Script {
        Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop |
            Select-Object displayName, productState, pathToSignedProductExe, pathToSignedReportingExe, timestamp
    } | Out-Null

    Invoke-FotonCollection -Category 'Security' -Name 'hardening_registry_settings' -Format 'Csv' -Description 'UAC, LSA, WDigest, SMB, and credential protection settings' -Script {
        $rows = @()
        foreach ($c in $script:FotonSession.HardeningRegistryChecks) {
            $val = Get-FotonRegValue -Path $c.Path -Name $c.Name
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

    Invoke-FotonCollection -Category 'Security' -Name 'audit_policy' -Format 'Txt' -Description 'Advanced audit policy configuration (log coverage)' -RequiresElevation -Script {
        & auditpol.exe /get /category:* 2>&1 | Out-String
    } | Out-Null

    Invoke-FotonCollection -Category 'Security' -Name 'smb_and_winrm_config' -Format 'Txt' -Description 'SMB server config, SMBv1 feature state, WinRM listeners' -Script {
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

    Invoke-FotonCollection -Category 'Security' -Name 'powershell_environment' -Description 'PowerShell versions, policy, and logging configuration' -Script {
        $psv2 = 'Unknown'
        try { $psv2 = [string](Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction Stop).State } catch { }
        [PSCustomObject]@{
            CurrentVersion        = $PSVersionTable.PSVersion.ToString()
            ExecutionPolicyList   = (Get-ExecutionPolicy -List | Out-String)
            PSv2FeatureState      = $psv2
            ScriptBlockLogging    = (Get-FotonRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging')
            ModuleLogging         = (Get-FotonRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging')
            Transcription         = (Get-FotonRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscripting')
            TranscriptOutputDir   = (Get-FotonRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'OutputDirectory')
            LanguageMode          = [string]$ExecutionContext.SessionState.LanguageMode
        }
    } | Out-Null

    Invoke-FotonCollection -Category 'Security' -Name 'non_microsoft_root_certificates' -Format 'Csv' -Description 'Root/intermediate CAs not issued by Microsoft (rogue CA check)' -Script {
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

    Invoke-FotonCollection -Category 'Security' -Name 'applocker_wdac_and_policy' -Format 'Txt' -Description 'Application control policy and applied group policy summary' -Script {
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
