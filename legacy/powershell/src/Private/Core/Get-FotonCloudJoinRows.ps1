function Get-FotonCloudJoinRows {
    <#
        Local Entra / workplace-join / MDM enrollment facts from the registry.
        Does not run dsregcmd, Graph, or any network call. Empty is a visibility
        gap (keys missing, other users' hives not loaded), not proof the host
        was never joined.
    #>
    param(
        [string]$JoinInfoRoot = 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo',
        [string]$TenantInfoRoot = 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo',
        [string]$EnrollmentRoot = 'HKLM:\SOFTWARE\Microsoft\Enrollments',
        $UserHiveRoots
    )
    if ($null -eq $UserHiveRoots) {
        $UserHiveRoots = @(Get-FotonUserHiveRoot)
    }

    $rows = @()
    $guidRe = '^[\{]?[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}[\}]?$'

    foreach ($sub in (Get-FotonCloudJoinGuidKeys -Root $JoinInfoRoot -GuidRe $guidRe)) {
        $rk = $sub.Key
        $deviceId = Get-FotonCloudJoinDisplayValue -Key $rk -Name 'DeviceId'
        $tenantId = Get-FotonCloudJoinDisplayValue -Key $rk -Name 'TenantId'
        $id = $deviceId
        if (-not $id) { $id = $sub.Leaf }
        $rows += [PSCustomObject]@{
            Kind           = 'AzureAdJoin'
            Scope          = 'Machine'
            User           = 'N/A'
            Identity       = $id
            TenantId       = $tenantId
            TenantName     = ''
            DeviceId       = $deviceId
            UPN            = (Get-FotonCloudJoinDisplayValue -Key $rk -Name 'UserEmail')
            IdpDomain      = (Get-FotonCloudJoinDisplayValue -Key $rk -Name 'IdpDomain')
            ProviderId     = ''
            EnrollmentType = ''
            SourceKey      = $sub.Path
            Note           = 'CloudDomainJoin JoinInfo. Local cache only; not a live tenant lookup.'
        }
    }

    foreach ($sub in (Get-FotonCloudJoinGuidKeys -Root $TenantInfoRoot -GuidRe $guidRe)) {
        $rk = $sub.Key
        $tenantId = Get-FotonCloudJoinDisplayValue -Key $rk -Name 'TenantId'
        if (-not $tenantId) { $tenantId = $sub.Leaf }
        $rows += [PSCustomObject]@{
            Kind           = 'TenantInfo'
            Scope          = 'Machine'
            User           = 'N/A'
            Identity       = $tenantId
            TenantId       = $tenantId
            TenantName     = (Get-FotonCloudJoinDisplayValue -Key $rk -Name 'DisplayName')
            DeviceId       = ''
            UPN            = ''
            IdpDomain      = ''
            ProviderId     = ''
            EnrollmentType = ''
            SourceKey      = $sub.Path
            Note           = 'CloudDomainJoin TenantInfo DisplayName is cached locally and can lag a rename.'
        }
    }

    foreach ($sub in (Get-FotonCloudJoinGuidKeys -Root $EnrollmentRoot -GuidRe $guidRe)) {
        $rk = $sub.Key
        $upn = Get-FotonCloudJoinDisplayValue -Key $rk -Name 'UPN'
        $tenant = Get-FotonCloudJoinDisplayValue -Key $rk -Name 'AADTenantID'
        $prov = Get-FotonCloudJoinDisplayValue -Key $rk -Name 'ProviderID'
        $etype = Get-FotonCloudJoinDisplayValue -Key $rk -Name 'EnrollmentType'
        $state = Get-FotonCloudJoinDisplayValue -Key $rk -Name 'EnrollmentState'
        if (-not $upn -and -not $tenant -and -not $prov -and -not $etype) { continue }
        $rows += [PSCustomObject]@{
            Kind           = 'MdmEnrollment'
            Scope          = 'Machine'
            User           = 'N/A'
            Identity       = $sub.Leaf
            TenantId       = $tenant
            TenantName     = ''
            DeviceId       = ''
            UPN            = $upn
            IdpDomain      = ''
            ProviderId     = $prov
            EnrollmentType = $etype
            SourceKey      = $sub.Path
            Note           = ('EnrollmentState={0}. Numeric EnrollmentType is recorded as stored; do not treat a number as a join verdict.' -f $(if ($state) { $state } else { '(not set)' }))
        }
    }

    foreach ($hive in @($UserHiveRoots)) {
        $wp = Join-Path $hive.Root 'Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\JoinInfo'
        foreach ($sub in (Get-FotonCloudJoinGuidKeys -Root $wp -GuidRe $guidRe)) {
            $rk = $sub.Key
            $tenantId = Get-FotonCloudJoinDisplayValue -Key $rk -Name 'TenantId'
            $deviceId = Get-FotonCloudJoinDisplayValue -Key $rk -Name 'DeviceId'
            $id = $deviceId
            if (-not $id) { $id = $sub.Leaf }
            $user = [string]$hive.UserName
            if (-not $user) { $user = [string]$hive.SID }
            $rows += [PSCustomObject]@{
                Kind           = 'WorkplaceJoin'
                Scope          = 'User'
                User           = $user
                Identity       = $id
                TenantId       = $tenantId
                TenantName     = ''
                DeviceId       = $deviceId
                UPN            = (Get-FotonCloudJoinDisplayValue -Key $rk -Name 'UserEmail')
                IdpDomain      = (Get-FotonCloudJoinDisplayValue -Key $rk -Name 'IdpDomain')
                ProviderId     = ''
                EnrollmentType = ''
                SourceKey      = $sub.Path
                Note           = 'WorkplaceJoin JoinInfo from a loaded user hive. Unloaded NTUSER is a visibility gap.'
            }
        }
    }

    $rows | Sort-Object Kind, Scope, User, Identity
}

function Get-FotonCloudJoinGuidKeys {
    param(
        [string]$Root,
        [string]$GuidRe
    )
    $out = @()
    if (-not $Root -or -not (Test-Path -LiteralPath $Root)) { return $out }
    try {
        foreach ($item in (Get-ChildItem -LiteralPath $Root -ErrorAction Stop)) {
            $leaf = [string]$item.PSChildName
            if ($leaf -notmatch $GuidRe) { continue }
            $rk = $null
            try { $rk = Get-Item -LiteralPath $item.PSPath -ErrorAction Stop } catch { continue }
            $out += [PSCustomObject]@{
                Leaf = $leaf
                Path = [string]$item.PSPath
                Key  = $rk
            }
        }
    }
    catch { }
    return $out
}

function Get-FotonCloudJoinDisplayValue {
    param(
        $Key,
        [string]$Name
    )
    if ($null -eq $Key -or -not $Name) { return '' }
    if ($Name -match '(?i)(password|secret|private|token|prt|refresh|encrypted)') { return '' }
    $raw = $null
    try { $raw = $Key.GetValue($Name) } catch { return '' }
    if ($null -eq $raw) { return '' }
    if ($raw -is [byte[]]) { return ('(binary {0} bytes)' -f $raw.Length) }
    return [string]$raw
}
