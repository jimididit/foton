# Invoke-FotonUserCollection - accounts, groups, sessions, RDP, credentials.

function Invoke-FotonUserCollection {
    Write-FotonStatus 'Collecting accounts, groups, sessions, and access configuration' 'Step'

    Invoke-FotonCollection -Category 'Users' -Name 'local_users' -Format 'Csv' -Description 'Local user accounts and password state' -Script {
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

    Invoke-FotonCollection -Category 'Users' -Name 'local_group_membership' -Format 'Csv' -Description 'Members of every local group (privilege mapping)' -Script {
        $rows = @()
        try {
            foreach ($g in (Get-LocalGroup -ErrorAction Stop)) {
                $members = @()
                $enumError = $null
                # Empty catch used to write Member='(none)' when Get-LocalGroupMember threw
                # (common on domain-joined hosts with domain principals / orphaned SIDs),
                # which hid real membership - including Administrators - behind Status Success.
                $source = 'Cmdlet'
                try { $members = @(Get-LocalGroupMember -Group $g.Name -ErrorAction Stop) }
                catch { $enumError = $_.Exception.Message }
                if ($enumError) {
                    try {
                        $adsi = @(Get-FotonLocalGroupMemberAdsi -GroupName $g.Name)
                        $members = @($adsi | ForEach-Object {
                                [PSCustomObject]@{ Name = $_.Member; ObjectClass = $_.ObjectClass; PrincipalSource = 'ADSI'; SID = $_.SID }
                            })
                        $source = 'ADSI'
                        $enumError = $null
                    }
                    catch {
                        $enumError = ('{0}; ADSI fallback: {1}' -f $enumError, $_.Exception.Message)
                    }
                }
                if ($enumError) {
                    $rows += [PSCustomObject]@{
                        Group           = $g.Name
                        Member          = ('(error: {0})' -f $enumError)
                        ObjectClass     = ''
                        PrincipalSource = ''
                        SID             = ''
                    }
                }
                elseif ($members.Count -eq 0) {
                    $rows += [PSCustomObject]@{ Group = $g.Name; Member = '(none)'; ObjectClass = ''; PrincipalSource = $source; SID = '' }
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

    Invoke-FotonCollection -Category 'Users' -Name 'user_profiles' -Format 'Csv' -Description 'Profiles present on disk with SID mapping' -Script {
        Get-FotonUserProfile
    } | Out-Null

    Invoke-FotonCollection -Category 'Users' -Name 'logged_on_sessions' -Format 'Txt' -Description 'Current interactive and remote sessions' -Script {
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

    Invoke-FotonCollection -Category 'Users' -Name 'password_and_lockout_policy' -Format 'Txt' -Description 'Local account policy (net accounts)' -Script {
        & net.exe accounts 2>&1 | Out-String
    } | Out-Null

    Invoke-FotonCollection -Category 'Users' -Name 'user_rights_and_secpol' -Format 'Txt' -Description 'Security policy export (secedit)' -RequiresElevation -Script {
        $tmp = Join-Path $env:TEMP ("foton_secpol_{0}.inf" -f ([guid]::NewGuid().ToString('N')))
        $null = & secedit.exe /export /cfg "$tmp" /quiet 2>&1
        if (Test-Path -LiteralPath $tmp) {
            $content = Get-Content -LiteralPath $tmp -Raw -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
            $content
        }
        else { 'secedit export unavailable (requires elevation).' }
    } | Out-Null

    Invoke-FotonCollection -Category 'Users' -Name 'rdp_configuration' -Description 'Remote Desktop enablement and NLA state' -Script {
        $rdpUsers = 'unavailable'
        try { $rdpUsers = ((Get-LocalGroupMember -Group 'Remote Desktop Users' -ErrorAction Stop | Select-Object -ExpandProperty Name) -join '; ') }
        catch {
            try { $rdpUsers = ((Get-FotonLocalGroupMemberAdsi -GroupName 'Remote Desktop Users' | Select-Object -ExpandProperty Member) -join '; ') } catch { }
        }
        $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        $rdpTcp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        [PSCustomObject]@{
            DenyTSConnections  = (Get-FotonRegValue $ts 'fDenyTSConnections')
            RdpEnabled         = ((Get-FotonRegValue $ts 'fDenyTSConnections') -eq 0)
            UserAuthentication = (Get-FotonRegValue $rdpTcp 'UserAuthentication')
            SecurityLayer      = (Get-FotonRegValue $rdpTcp 'SecurityLayer')
            PortNumber         = (Get-FotonRegValue $rdpTcp 'PortNumber')
            AllowRemoteRPC     = (Get-FotonRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'AllowRemoteRPC')
            RemoteDesktopUsers = $rdpUsers
            ShadowSetting      = (Get-FotonRegValue $rdpTcp 'Shadow')
        }
    } | Out-Null

    Invoke-FotonCollection -Category 'Users' -Name 'stored_credentials_and_trusts' -Format 'Txt' -Description 'Credential manager entries and domain trust state' -Script {
        $out = @()
        $out += '--- cmdkey /list ---'
        $out += (& cmdkey.exe /list 2>&1 | Out-String)
        $out += '--- nltest /domain_trusts ---'
        $out += (& nltest.exe /domain_trusts 2>&1 | Out-String)
        $out += '--- Vault directories present ---'
        foreach ($p in @("$env:LOCALAPPDATA\Microsoft\Vault", "$env:APPDATA\Microsoft\Credentials", "$env:LOCALAPPDATA\Microsoft\Credentials")) {
            if (Test-FotonPathAccessible -Path $p) {
                $out += "PATH: $p"
                $out += (Get-ChildItem -LiteralPath $p -Force -Recurse -ErrorAction SilentlyContinue |
                        Select-Object FullName, Length, LastWriteTimeUtc | Out-String -Width 300)
            }
        }
        $out
    } | Out-Null
}
