$script:FotonPerUserServiceTemplates = @(
    'AarSvc', 'BcastDVRUserService', 'BluetoothUserService', 'CaptureService', 'cbdhsvc',
    'CDPUserSvc', 'CloudBackupRestoreSvc', 'ConsentUxUserSvc', 'CredentialEnrollmentManagerUserSvc',
    'DeviceAssociationBrokerSvc', 'DevicePickerUserSvc', 'DevicesFlowUserSvc', 'LxssManagerUser',
    'MessagingService', 'NPSMSvc', 'OneSyncSvc', 'P9RdrService', 'PenService',
    'PimIndexMaintenanceSvc', 'PrintWorkflowUserSvc', 'UdkUserSvc', 'UnistoreSvc', 'UserDataSvc',
    'webthreatdefusersvc', 'WpnUserService'
)

function Test-FotonPerUserServiceName {
    <#
        True for per-user service instances (OneSyncSvc_1701f8, CDPUserSvc_2a8824).
        Windows creates one per template service at every interactive logon and logs
        each as a service install (4697), so on any Windows 10/11 host they outnumber
        real installs. The suffix is a hex logon-session identifier.

        The base name must be a known Microsoft per-user template: a bare Name_<hex>
        shape is attacker-choosable (Updater_1a2b3c) and would hide a real install.
        A template Microsoft adds later is counted rather than hidden - noisy, not blind.
    #>
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    $m = [regex]::Match($Name.Trim(), '^(?<base>[A-Za-z][A-Za-z0-9]*)_[0-9a-fA-F]{4,8}$')
    if (-not $m.Success) { return $false }
    return ($script:FotonPerUserServiceTemplates -contains $m.Groups['base'].Value)
}

function Get-FotonServiceNameFromEvent {
    <#
        Service name from a 7045/4697 row: EvtxECmd PayloadData1 ("Name: X" or
        "ServiceName: X") or the native Message text ("Service Name:  X").
    #>
    param([object]$Row)
    $end = '(?=\s{2,}|\s+Service File Name:|\s+Service Type:|\s+Image Path:|\r|\n|$)'
    foreach ($field in @('PayloadData1', 'Message')) {
        $text = [string]$Row.$field
        if (-not $text) { continue }
        # "Service Name:" first: a native 4697 message names the subject account
        # ("Account Name: HOST$") before the service, so a bare "Name:" match there
        # returns the account.
        $m = [regex]::Match($text, '(?i)Service\s?Name:\s+(?<n>.+?)' + $end)
        if ($m.Success) { return $m.Groups['n'].Value.Trim() }
        # EvtxECmd 7045 PayloadData1 is exactly "Name: <service>".
        $m = [regex]::Match($text, '(?i)^\s*Name:\s+(?<n>.+?)' + $end)
        if ($m.Success) { return $m.Groups['n'].Value.Trim() }
    }
    return ''
}

function Get-FotonAccountEventFacts {
    <#
        Normalise account lifecycle events (4720 create, 4726 delete, 4728/4732/4756
        group add) from either native Message text or EvtxECmd PayloadData columns.
        Returns EventId, TimeUtc (datetime or $null), AccountSid, AccountName,
        GroupSid, GroupName.
    #>
    param([object[]]$Rows)
    $out = @()
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $eid = [string]$r.EventId
        if (-not $eid) { $eid = [string]$r.EventID }
        if ($eid -notin @('4720', '4726', '4728', '4732', '4756')) { continue }
        $tsText = [string]$r.TimeCreatedUtc
        if (-not $tsText) { $tsText = [string]$r.TimeCreated }
        $ts = $null
        if ($tsText.Length -ge 19) {
            $d = [datetime]::MinValue
            if ([datetime]::TryParseExact($tsText.Substring(0, 19), 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$d)) { $ts = $d }
        }
        $fact = [PSCustomObject]@{ EventId = $eid; TimeUtc = $ts; AccountSid = ''; AccountName = ''; GroupSid = ''; GroupName = '' }
        $msg = [string]$r.Message
        if ($msg) {
            # Rendered messages show "Security ID:" as a SID when it cannot be
            # resolved and as DOMAIN\Name when it can (BUILTIN\Administrators), so the
            # identifier is any non-space token, and group names are checked too.
            if ($eid -in @('4720', '4726')) {
                $m = [regex]::Match($msg, '(?:New Account|Target Account):\s+Security ID:\s+(?<sid>\S+)\s+Account Name:\s+(?<n>\S+)')
                if ($m.Success) { $fact.AccountSid = $m.Groups['sid'].Value; $fact.AccountName = $m.Groups['n'].Value }
            }
            else {
                $m = [regex]::Match($msg, 'Member:\s+Security ID:\s+(?<sid>\S+)')
                if ($m.Success) { $fact.AccountSid = $m.Groups['sid'].Value }
                $g = [regex]::Match($msg, 'Group:\s+Security ID:\s+(?<sid>\S+)\s+Group Name:\s+(?<n>.+?)\s+Group Domain:')
                if ($g.Success) { $fact.GroupSid = $g.Groups['sid'].Value; $fact.GroupName = $g.Groups['n'].Value.Trim() }
            }
        }
        else {
            $p1 = [string]$r.PayloadData1
            $t = [regex]::Match($p1, 'Target:\s+(?<n>[^(]+?)\s+\((?<sid>S-[\d-]+)\)')
            if ($eid -in @('4720', '4726')) {
                if ($t.Success) { $fact.AccountName = (($t.Groups['n'].Value -split '\\')[-1]).Trim(); $fact.AccountSid = $t.Groups['sid'].Value }
            }
            else {
                if ($t.Success) { $fact.GroupName = (($t.Groups['n'].Value -split '\\')[-1]).Trim(); $fact.GroupSid = $t.Groups['sid'].Value }
                foreach ($f in @('PayloadData2', 'PayloadData3')) {
                    $ms = [regex]::Match([string]$r.$f, 'MemberSid:\s+(?<sid>S-[\d-]+)')
                    if ($ms.Success) { $fact.AccountSid = $ms.Groups['sid'].Value }
                }
            }
        }
        $out += $fact
    }
    return $out
}

function Test-FotonPrivilegedGroupSid {
    <#
        True for groups whose membership grants administrative or remote-access rights.
        Adding a new account to the default primary group (RID 513, "None" /
        "Domain Users") happens on every account creation and is not a privilege change.

        -Sid may be a SID or a resolved DOMAIN\Name; -Name is the event's Group Name.
        Names are the English built-in names; a localized OS that renders neither a
        SID nor these names is missed, so the SID check runs first.
    #>
    param([string]$Sid, [string]$Name)
    if ($Sid -match '^S-1-5-32-(544|547|548|549|550|551|555|562|573|578|580)$') { return $true }
    if ($Sid -match '^S-1-5-21-[\d-]+-(512|518|519|520|526|527)$') { return $true }
    $names = @('Administrators', 'Power Users', 'Account Operators', 'Server Operators', 'Print Operators',
        'Backup Operators', 'Remote Desktop Users', 'Distributed COM Users', 'Event Log Readers',
        'Hyper-V Administrators', 'Remote Management Users', 'Domain Admins', 'Cert Publishers',
        'Schema Admins', 'Enterprise Admins', 'Group Policy Creator Owners', 'Key Admins', 'Enterprise Key Admins')
    foreach ($candidate in @($Name, (([string]$Sid) -split '\\')[-1])) {
        if ($candidate -and ($names -contains $candidate.Trim())) { return $true }
    }
    return $false
}

function Get-FotonAccountChangeSummary {
    <#
        Split account events into transient create-then-delete pairs (same SID,
        deleted within $TransientSeconds), accounts that persisted, and group adds
        into privileged versus default groups. Provisioning scripts and LAPS-style
        tooling often create and remove an account in the same second; counting
        those as "account creation" makes routine automation look like persistence.
    #>
    param(
        [object[]]$Facts,
        [int]$TransientSeconds = 60
    )
    $creates = @($Facts | Where-Object { $_.EventId -eq '4720' })
    $deletes = @($Facts | Where-Object { $_.EventId -eq '4726' })
    $adds = @($Facts | Where-Object { $_.EventId -in @('4728', '4732', '4756') })
    $transient = @()
    $persistent = @()
    foreach ($c in $creates) {
        $match = $deletes | Where-Object {
            $_.AccountSid -and $_.AccountSid -eq $c.AccountSid -and $c.TimeUtc -and $_.TimeUtc -and
            ($_.TimeUtc - $c.TimeUtc).TotalSeconds -ge 0 -and ($_.TimeUtc - $c.TimeUtc).TotalSeconds -le $TransientSeconds
        } | Select-Object -First 1
        if ($match) { $transient += $c } else { $persistent += $c }
    }
    $transientSids = @($transient | ForEach-Object { $_.AccountSid })
    $priv = @($adds | Where-Object { Test-FotonPrivilegedGroupSid -Sid $_.GroupSid -Name $_.GroupName })
    # Adds of a transient account into its default group are part of the same blip.
    $other = @($adds | Where-Object { -not (Test-FotonPrivilegedGroupSid -Sid $_.GroupSid -Name $_.GroupName) -and $transientSids -notcontains $_.AccountSid })
    return [PSCustomObject]@{
        Transient       = $transient
        Persistent      = $persistent
        Deleted         = $deletes
        PrivilegedAdds  = $priv
        OtherGroupAdds  = $other
    }
}
