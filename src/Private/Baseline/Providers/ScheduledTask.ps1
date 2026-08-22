# ScheduledTask — identity TaskPath + TaskName. Ignore last-run (volatile).
Register-FotonBaselineProvider -RecordType 'ScheduledTask' `
    -IdentityFields @('TaskPath', 'TaskName') `
    -ComparedFields @('Actions', 'RunAsUser', 'RunLevel', 'Triggers') `
    -FalsePositives 'Vendor software registers tasks after install. Root-folder SYSTEM tasks are more interesting than nested Microsoft\Windows tasks, but still often legitimate.' `
    -Collect {
        $rows = @()
        try {
            foreach ($t in (Get-ScheduledTask -ErrorAction Stop)) {
                $actions = @()
                foreach ($a in @($t.Actions)) {
                    if ($a.Execute) { $actions += ("{0} {1}" -f $a.Execute, $a.Arguments) }
                    elseif ($a.ClassId) { $actions += ("COM:{0}" -f $a.ClassId) }
                }
                $triggers = @()
                foreach ($tr in @($t.Triggers)) {
                    if ($tr.CimClass) { $triggers += $tr.CimClass.CimClassName }
                }
                $rows += [PSCustomObject]@{
                    TaskPath  = [string]$t.TaskPath
                    TaskName  = [string]$t.TaskName
                    Actions   = ($actions -join ' | ')
                    RunAsUser = [string]$t.Principal.UserId
                    RunLevel  = [string]$t.Principal.RunLevel
                    Triggers  = ($triggers -join ',')
                }
            }
        }
        catch { }
        $rows | Sort-Object TaskPath, TaskName
    }
