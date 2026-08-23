# Invoke-FotonSystemCollection
# Live facts only. Called from Invoke-FotonTriage when that exists.
# Endpoint collect. Rebuild dist/Foton-Collect.ps1 after edits.

function Invoke-FotonSystemCollection {
    Write-FotonStatus 'Collecting system identity, configuration, and boot state' 'Step'

    Invoke-FotonCollection -Category 'System' -Name 'os_info' -Description 'Operating system build, install date, uptime' -Script {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            Hostname           = $env:COMPUTERNAME
            Caption            = $os.Caption
            Version            = $os.Version
            BuildNumber        = $os.BuildNumber
            DisplayVersion     = (Get-FotonRegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'DisplayVersion')
            UBR                = (Get-FotonRegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'UBR')
            Architecture       = $os.OSArchitecture
            InstallDateUtc     = $os.InstallDate.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
            LastBootUtc        = $os.LastBootUpTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
            UptimeDays         = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 2)
            SerialNumber       = $os.SerialNumber
            RegisteredUser     = $os.RegisteredUser
            SystemDirectory    = $os.SystemDirectory
            Domain             = if ($cs) { $cs.Domain } else { '' }
            PartOfDomain       = if ($cs) { $cs.PartOfDomain } else { $null }
            Manufacturer       = if ($cs) { $cs.Manufacturer } else { '' }
            Model              = if ($cs) { $cs.Model } else { '' }
            TotalPhysicalMemGB = if ($cs) { [math]::Round($cs.TotalPhysicalMemory / 1GB, 2) } else { $null }
            BiosVersion        = if ($bios) { ($bios.BIOSVersion -join ' ') } else { '' }
            BiosSerial         = if ($bios) { $bios.SerialNumber } else { '' }
            TimeZone           = [System.TimeZoneInfo]::Local.Id
            UtcOffset          = [System.TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).ToString()
        }
    } | Out-Null

    Invoke-FotonCollection -Category 'System' -Name 'entra_workplace_join' -Format 'Csv' -Description 'Entra/Azure AD join, workplace join, and MDM enrollment from local registry (no dsregcmd, no Graph)' -Script {
        Get-FotonCloudJoinRows
    } | Out-Null

    Invoke-FotonCollection -Category 'System' -Name 'time_sync' -Format 'Txt' -Description 'NTP/time source configuration (timestamp reliability)' -Script {
        $out = @()
        $out += '--- w32tm /query /status ---'
        $out += (& w32tm.exe /query /status 2>&1 | Out-String)
        $out += '--- w32tm /query /configuration ---'
        $out += (& w32tm.exe /query /configuration 2>&1 | Out-String)
        $out += '--- Time Service ---'
        $out += (Get-Service W32Time -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType | Out-String)
        $out
    } | Out-Null

    Invoke-FotonCollection -Category 'System' -Name 'hotfixes' -Format 'Csv' -Description 'Installed updates and patch dates' -Script {
        Get-HotFix -ErrorAction Stop |
            Select-Object HotFixID, Description, InstalledBy, @{n = 'InstalledOn'; e = { if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') } else { '' } } } |
            Sort-Object InstalledOn -Descending
    } | Out-Null

    Invoke-FotonCollection -Category 'System' -Name 'boot_and_firmware' -Description 'Secure Boot, TPM, BitLocker, boot configuration' -Script {
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

    Invoke-FotonCollection -Category 'System' -Name 'disks_and_volumes' -Format 'Csv' -Description 'Logical volumes, free space, filesystem type' -Script {
        Get-CimInstance Win32_LogicalDisk -ErrorAction Stop | Select-Object DeviceID, DriveType, FileSystem, VolumeName,
        @{n = 'SizeGB'; e = { [math]::Round($_.Size / 1GB, 2) } },
        @{n = 'FreeGB'; e = { [math]::Round($_.FreeSpace / 1GB, 2) } }, VolumeSerialNumber
    } | Out-Null

    Invoke-FotonCollection -Category 'System' -Name 'environment_variables' -Format 'Csv' -Description 'Process/machine environment variables' -Script {
        Get-ChildItem Env: | Select-Object Name, Value
    } | Out-Null

    Invoke-FotonCollection -Category 'System' -Name 'system_restore_and_shadowcopies' -Format 'Txt' -Description 'Volume shadow copies (deletion is a ransomware indicator)' -RequiresElevation -Script {
        $out = @()
        $out += '--- vssadmin list shadows ---'
        $out += (& vssadmin.exe list shadows 2>&1 | Out-String)
        $out += '--- vssadmin list shadowstorage ---'
        $out += (& vssadmin.exe list shadowstorage 2>&1 | Out-String)
        $out
    } | Out-Null
}
