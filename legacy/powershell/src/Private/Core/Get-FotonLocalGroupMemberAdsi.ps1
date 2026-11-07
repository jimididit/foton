function Get-FotonLocalGroupMemberAdsi {
    <#
        Local group members through the WinNT ADSI provider.

        Get-LocalGroupMember throws (error 1789, "trust relationship") on many
        domain-joined and Entra-joined hosts when a member SID cannot be resolved,
        and returns nothing for the whole group - Administrators included. The WinNT
        provider still enumerates members and their SIDs without resolving every one
        against a domain controller. Throws if the group cannot be bound at all, so
        the caller can record both failures.
    #>
    param([Parameter(Mandatory)][string]$GroupName)

    $group = [ADSI]("WinNT://./{0},group" -f $GroupName)
    $rows = @()
    foreach ($m in @($group.psbase.Invoke('Members'))) {
        $type = $m.GetType()
        $name = [string]$type.InvokeMember('Name', 'GetProperty', $null, $m, $null)
        $path = [string]$type.InvokeMember('ADsPath', 'GetProperty', $null, $m, $null)
        $class = [string]$type.InvokeMember('Class', 'GetProperty', $null, $m, $null)
        $sid = ''
        try {
            $bytes = [byte[]]$type.InvokeMember('objectSid', 'GetProperty', $null, $m, $null)
            if ($bytes) { $sid = (New-Object System.Security.Principal.SecurityIdentifier($bytes, 0)).Value }
        }
        catch { }
        # ADsPath is WinNT://DOMAIN/name or WinNT://DOMAIN/HOST/name; render as DOMAIN\name.
        $display = $name
        $parts = @(($path -replace '^WinNT://', '') -split '/')
        if ($parts.Count -ge 2) { $display = '{0}\{1}' -f $parts[$parts.Count - 2], $parts[$parts.Count - 1] }
        $rows += [PSCustomObject]@{
            Member      = $display
            ObjectClass = $class
            SID         = $sid
        }
    }
    return $rows
}
