# BitsJob - JobId identity. Compare type/owner/notify, never bytes or JobState (T1197).
# Windows Update creates short-lived jobs; NotifyCmdLine is the persistence signal.
Register-FotonBaselineProvider -RecordType 'BitsJob' `
    -IdentityFields @('JobId') `
    -ComparedFields @('DisplayName', 'TransferType', 'OwnerAccount', 'Priority', 'ProxyUsage', 'NotifyCmdLine') `
    -FalsePositives 'Windows Update and Store use BITS. Added/Removed JobIds between captures are common. A new or changed NotifyCmdLine (bitsadmin /SetNotifyCmdLine) is the usual review item, not BytesTransferred.' `
    -Collect {
        $rows = @()
        $jobs = $null
        try {
            $jobs = @(Get-BitsTransfer -AllUsers -ErrorAction Stop)
        }
        catch {
            try { $jobs = @(Get-BitsTransfer -ErrorAction Stop) } catch { $jobs = @() }
        }
        foreach ($j in $jobs) {
            if ($null -eq $j) { continue }
            $notify = '(not set)'
            if ($j.PSObject.Properties['NotificationCommandLine'] -and $null -ne $j.NotificationCommandLine -and [string]$j.NotificationCommandLine -ne '') {
                $notify = [string]$j.NotificationCommandLine
            }
            elseif ($j.PSObject.Properties['NotifyCmdLine'] -and $null -ne $j.NotifyCmdLine -and [string]$j.NotifyCmdLine -ne '') {
                $notify = [string]$j.NotifyCmdLine
            }
            $id = ''
            if ($j.PSObject.Properties['JobId']) { $id = [string]$j.JobId }
            if (-not $id) { continue }
            $disp = '(not set)'
            if ($j.PSObject.Properties['DisplayName'] -and $null -ne $j.DisplayName -and [string]$j.DisplayName -ne '') {
                $disp = [string]$j.DisplayName
            }
            $xfer = '(not set)'
            if ($j.PSObject.Properties['TransferType']) { $xfer = [string]$j.TransferType }
            $owner = '(not set)'
            if ($j.PSObject.Properties['OwnerAccount'] -and $null -ne $j.OwnerAccount -and [string]$j.OwnerAccount -ne '') {
                $owner = [string]$j.OwnerAccount
            }
            $prio = '(not set)'
            if ($j.PSObject.Properties['Priority']) { $prio = [string]$j.Priority }
            $proxy = '(not set)'
            if ($j.PSObject.Properties['ProxyUsage']) { $proxy = [string]$j.ProxyUsage }
            $rows += [PSCustomObject]@{
                JobId          = $id
                DisplayName    = $disp
                TransferType   = $xfer
                OwnerAccount   = $owner
                Priority       = $prio
                ProxyUsage     = $proxy
                NotifyCmdLine  = $notify
            }
        }
        $rows | Sort-Object JobId
    }
