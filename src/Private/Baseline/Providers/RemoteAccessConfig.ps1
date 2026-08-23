# RemoteAccessConfig - RDP NLA/port/layer, WinRM policy auth, SMBv1 DWORD.
# Identity is Setting. RDP *enable* (fDenyTSConnections) stays HardeningRegistry to avoid a double finding.
# False positives: helpdesk RDP, GPO WinRM, old file servers still on SMB1.
Register-FotonBaselineProvider -RecordType 'RemoteAccessConfig' `
    -IdentityFields @('Setting') `
    -ComparedFields @('Value') `
    -FalsePositives 'Helpdesk turning NLA off or changing the RDP port. Domain GPO for WinRM Basic/unencrypted. File servers that still have SMBv1. fDenyTSConnections is HardeningRegistry, not this type.' `
    -Collect {
        $shown = {
            param($v)
            if ($null -eq $v -or [string]$v -eq '') { return '(not set)' }
            return [string]$v
        }
        $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        $rdpTcp = Join-Path $ts 'WinStations\RDP-Tcp'
        $winrmPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
        $smb = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        $rows = @(
            [PSCustomObject]@{ Setting = 'RdpNla'; Value = & $shown (Get-FotonRegValue -Path $rdpTcp -Name 'UserAuthentication') }
            [PSCustomObject]@{ Setting = 'RdpPort'; Value = & $shown (Get-FotonRegValue -Path $rdpTcp -Name 'PortNumber') }
            [PSCustomObject]@{ Setting = 'RdpSecurityLayer'; Value = & $shown (Get-FotonRegValue -Path $rdpTcp -Name 'SecurityLayer') }
            [PSCustomObject]@{ Setting = 'RdpAllowRemoteRPC'; Value = & $shown (Get-FotonRegValue -Path $ts -Name 'AllowRemoteRPC') }
            [PSCustomObject]@{ Setting = 'WinRmPolicyAllowUnencrypted'; Value = & $shown (Get-FotonRegValue -Path $winrmPol -Name 'AllowUnencrypted') }
            [PSCustomObject]@{ Setting = 'WinRmPolicyAllowBasic'; Value = & $shown (Get-FotonRegValue -Path $winrmPol -Name 'AllowBasic') }
            [PSCustomObject]@{ Setting = 'Smb1LanmanServer'; Value = & $shown (Get-FotonRegValue -Path $smb -Name 'SMB1') }
        )
        $rows | Sort-Object Setting
    }
