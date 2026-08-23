function Get-FotonBaselineChangeSeverity {
    <#
        Attention weight for a baseline change. Still a fact ranking, not a verdict.
        High = unusual persistence / trust surface; Info = expected software churn.
    #>
    param($Change)
    $c = $Change
    $sev = 'Medium'
    if ($c.RecordType -eq 'InstalledSoftware' -and $c.Field -eq 'DisplayVersion') { $sev = 'Info' }
    if ($c.RecordType -eq 'Listener' -and $c.ChangeType -eq 'Added') { $sev = 'Low' }
    if ($c.RecordType -eq 'FirewallRule' -and $c.ChangeType -eq 'Added') { $sev = 'Medium' }
    if ($c.RecordType -eq 'LocalAccount' -and $c.ChangeType -eq 'Added') { $sev = 'Medium' }
    if ($c.RecordType -eq 'Service' -and $c.Field -eq 'PathName') { $sev = 'High' }
    if ($c.RecordType -eq 'Driver' -and $c.Field -eq 'PathName') { $sev = 'High' }
    if ($c.RecordType -eq 'Autorun' -and $c.Field -eq 'Command') { $sev = 'High' }
    if ($c.RecordType -eq 'ScheduledTask' -and $c.Field -eq 'Actions') { $sev = 'High' }
    if ($c.RecordType -eq 'HardeningRegistry' -and $c.Identity -in @('UseLogonCredential', 'EnableLUA', 'AlwaysInstallElevated')) { $sev = 'High' }
    if ($c.RecordType -eq 'LocalGroupMember' -and $c.ChangeType -eq 'Added' -and $c.Identity -like 'Administrators|*') { $sev = 'High' }
    if ($c.RecordType -eq 'Certificate' -and $c.ChangeType -eq 'Added' -and $c.Identity -like 'Cert:\LocalMachine\Root|*') { $sev = 'High' }
    if ($c.RecordType -eq 'NetworkShare' -and $c.ChangeType -eq 'Added') { $sev = 'High' }
    if ($c.RecordType -eq 'SystemBinary' -and $c.Field -eq 'Sha256') { $sev = 'High' }
    if ($c.RecordType -eq 'HostsEntry' -and $c.ChangeType -eq 'Added') { $sev = 'High' }
    if ($c.RecordType -eq 'WmiPermanentEvent' -and $c.ChangeType -eq 'Added') { $sev = 'High' }
    if ($c.RecordType -eq 'StartupFile' -and $c.ChangeType -eq 'Added') { $sev = 'High' }
    if ($c.RecordType -eq 'ImageFileExecution' -and ($c.ChangeType -eq 'Added' -or $c.Field -eq 'Debugger')) { $sev = 'High' }
    if ($c.RecordType -eq 'Winlogon' -and $c.Identity -in @('Userinit', 'Shell', 'GinaDLL', 'System', 'UIHost')) { $sev = 'High' }
    if ($c.RecordType -eq 'AppInitDll' -and $c.ChangeType -in @('Added', 'Modified')) { $sev = 'High' }
    if ($c.RecordType -eq 'MachineEnvironment' -and $c.Identity -eq 'Path' -and $c.ChangeType -eq 'Modified') { $sev = 'High' }
    if ($c.RecordType -eq 'StartupApproved' -and $c.Field -eq 'State') { $sev = 'High' }
    if ($c.RecordType -eq 'UserAutorun' -and ($c.ChangeType -eq 'Added' -or $c.Field -eq 'Command')) { $sev = 'High' }
    if ($c.RecordType -eq 'DefenderPreference' -and $c.Identity -like 'Switch|DisableRealtimeMonitoring') { $sev = 'High' }
    if ($c.RecordType -eq 'RemoteAccessConfig' -and $c.ChangeType -in @('Added', 'Removed', 'Modified')) { $sev = 'High' }
    if ($c.RecordType -eq 'LsaPackage' -and $c.ChangeType -in @('Added', 'Removed')) { $sev = 'High' }
    if ($c.RecordType -eq 'PrintMonitor' -and ($c.ChangeType -in @('Added', 'Removed') -or $c.Field -eq 'Driver')) { $sev = 'High' }
    if ($c.RecordType -eq 'BitsJob' -and $c.Field -eq 'NotifyCmdLine') { $sev = 'High' }
    if ($c.RecordType -eq 'CmdAutoRun') { $sev = 'High' }
    if ($c.RecordType -eq 'SessionManager') { $sev = 'High' }
    if ($c.RecordType -eq 'KnownDll') { $sev = 'High' }
    if ($c.RecordType -eq 'ProxyConfig') { $sev = 'High' }
    if ($c.RecordType -eq 'ProxyConfig' -and [string]$c.Identity -like '*|AutoConfigURL') { $sev = 'Medium' }
    return $sev
}
