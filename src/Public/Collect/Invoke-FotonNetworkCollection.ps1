# Invoke-FotonNetworkCollection - connections, DNS, firewall, shares, proxy, Wi-Fi.

function Invoke-FotonNetworkCollection {
    Write-FotonStatus 'Collecting network configuration, connections, and DNS state' 'Step'

    Invoke-FotonCollection -Category 'Network' -Name 'active_connections' -Format 'Csv' -Description 'TCP connections mapped to owning process' -Script {
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
                    LocalAddress     = [string]$c.LocalAddress
                    LocalPort        = $c.LocalPort
                    RemoteAddress    = $remote
                    RemotePort       = $c.RemotePort
                    State            = [string]$c.State
                    OwningPID        = $c.OwningProcess
                    ProcessName      = if ($proc) { $proc.Name } else { '' }
                    ProcessPath      = if ($proc) { $proc.ExecutablePath } else { '' }
                    CommandLine      = if ($proc) { $proc.CommandLine } else { '' }
                    RemoteIsExternal = $isExternal
                    UserWritablePath = if ($proc) { (Test-FotonUserWritablePath -Path $proc.ExecutablePath) } else { $false }
                    CreationTimeUtc  = if ($c.CreationTime) { $c.CreationTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
                }
            }
        }
        catch {
            $rows += [PSCustomObject]@{ LocalAddress = 'ERROR'; LocalPort = 0; RemoteAddress = $_.Exception.Message; RemotePort = 0; State = ''; OwningPID = 0; ProcessName = ''; ProcessPath = ''; CommandLine = ''; RemoteIsExternal = $false; UserWritablePath = $false; CreationTimeUtc = '' }
        }
        $rows
    } | Out-Null

    Invoke-FotonCollection -Category 'Network' -Name 'listening_ports' -Format 'Csv' -Description 'Listening TCP/UDP endpoints with owning process' -Script {
        $procs = @{}
        try { foreach ($p in (Get-CimInstance Win32_Process -ErrorAction Stop)) { $procs[[int]$p.ProcessId] = $p } } catch { }
        $rows = @()
        try {
            foreach ($c in (Get-NetTCPConnection -State Listen -ErrorAction Stop)) {
                $proc = $null
                if ($procs.ContainsKey([int]$c.OwningProcess)) { $proc = $procs[[int]$c.OwningProcess] }
                $rows += [PSCustomObject]@{
                    Protocol    = 'TCP'; LocalAddress = [string]$c.LocalAddress; LocalPort = $c.LocalPort
                    OwningPID   = $c.OwningProcess
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
                    Protocol    = 'UDP'; LocalAddress = [string]$u.LocalAddress; LocalPort = $u.LocalPort
                    OwningPID   = $u.OwningProcess
                    ProcessName = if ($proc) { $proc.Name } else { '' }
                    ProcessPath = if ($proc) { $proc.ExecutablePath } else { '' }
                }
            }
        }
        catch { }
        $rows | Sort-Object Protocol, LocalPort
    } | Out-Null

    Invoke-FotonCollection -Category 'Network' -Name 'ip_configuration' -Format 'Txt' -Description 'Adapters, addresses, routes, ARP cache' -Script {
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

    Invoke-FotonCollection -Category 'Network' -Name 'dns_cache' -Format 'Csv' -Description 'Resolved DNS entries currently cached' -Script {
        try {
            Get-DnsClientCache -ErrorAction Stop | Select-Object Entry, Name, Type, Status, TimeToLive, Data
        }
        catch {
            (& ipconfig.exe /displaydns 2>&1 | Out-String)
        }
    } | Out-Null

    Invoke-FotonCollection -Category 'Network' -Name 'dns_client_servers' -Format 'Csv' -Description 'Configured DNS servers per interface' -Script {
        Get-DnsClientServerAddress -ErrorAction Stop |
            Select-Object InterfaceAlias, InterfaceIndex, AddressFamily, @{n = 'ServerAddresses'; e = { $_.ServerAddresses -join ', ' } }
    } | Out-Null

    Invoke-FotonCollection -Category 'Network' -Name 'hosts_file' -Format 'Txt' -Description 'hosts file contents (redirection indicator)' -Script {
        $p = "$env:SystemRoot\System32\drivers\etc\hosts"
        if (Test-FotonPathAccessible -Path $p) { Get-Content -LiteralPath $p -ErrorAction Stop } else { 'hosts file not found' }
    } | Out-Null

    Invoke-FotonCollection -Category 'Network' -Name 'firewall_profiles' -Format 'Csv' -Description 'Firewall profile enablement and default actions' -Script {
        Get-NetFirewallProfile -ErrorAction Stop |
            Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked, LogFileName
    } | Out-Null

    Invoke-FotonCollection -Category 'Network' -Name 'firewall_rules_inbound_allow' -Format 'Csv' -Description 'Enabled inbound allow rules (exposure surface)' -Script {
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

    Invoke-FotonCollection -Category 'Network' -Name 'shares_and_sessions' -Format 'Txt' -Description 'SMB shares, permissions, open sessions and files' -Script {
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

    Invoke-FotonCollection -Category 'Network' -Name 'proxy_and_winhttp' -Format 'Txt' -Description 'User and system proxy configuration' -Script {
        $out = @()
        $out += '--- netsh winhttp show proxy ---'
        $out += (& netsh.exe winhttp show proxy 2>&1 | Out-String)
        foreach ($hiveRoot in (Get-FotonUserHiveRoot)) {
            $key = "$($hiveRoot.Root)\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            if (Test-FotonPathAccessible -Path $key) {
                $out += "=== Internet Settings for $($hiveRoot.UserName) ==="
                $out += (Get-FotonRegValueList -Path $key | Where-Object { $_.Name -match 'Proxy|AutoConfig' } | Out-String -Width 300)
            }
        }
        $out
    } | Out-Null

    Invoke-FotonCollection -Category 'Network' -Name 'wifi_profiles' -Format 'Txt' -Description 'Saved wireless profiles' -Script {
        & netsh.exe wlan show profiles 2>&1 | Out-String
    } | Out-Null
}
