# WmiPermanentEvent - root\subscription filters/consumers/bindings. WMI persistence is rare in a clean image; SCCM/AV WMI consumers are a known false positive.
Register-FotonBaselineProvider -RecordType 'WmiPermanentEvent' `
    -IdentityFields @('Kind', 'Name') `
    -ComparedFields @('Detail') `
    -FalsePositives 'ConfigMgr, Defender, and backup agents register WMI consumers. Empty on many home images. Unelevated capture may return zero rows (visibility gap, not proof of absence).' `
    -Collect {
        $rows = @()
        $ns = 'root\subscription'
        try {
            foreach ($f in @(Get-CimInstance -Namespace $ns -ClassName '__EventFilter' -ErrorAction Stop)) {
                $rows += [PSCustomObject]@{
                    Kind   = 'EventFilter'
                    Name   = [string]$f.Name
                    Detail = [string]$f.Query
                }
            }
        }
        catch { }
        try {
            foreach ($c in @(Get-CimInstance -Namespace $ns -ClassName 'CommandLineEventConsumer' -ErrorAction Stop)) {
                $rows += [PSCustomObject]@{
                    Kind   = 'CommandLineConsumer'
                    Name   = [string]$c.Name
                    Detail = [string]$c.CommandLineTemplate
                }
            }
        }
        catch { }
        try {
            foreach ($c in @(Get-CimInstance -Namespace $ns -ClassName 'ActiveScriptEventConsumer' -ErrorAction Stop)) {
                $scriptText = [string]$c.ScriptText
                if ($scriptText.Length -gt 400) { $scriptText = $scriptText.Substring(0, 400) }
                $rows += [PSCustomObject]@{
                    Kind   = 'ActiveScriptConsumer'
                    Name   = [string]$c.Name
                    Detail = $scriptText
                }
            }
        }
        catch { }
        try {
            foreach ($b in @(Get-CimInstance -Namespace $ns -ClassName '__FilterToConsumerBinding' -ErrorAction Stop)) {
                $fname = [string]$b.Filter
                $cname = [string]$b.Consumer
                $rows += [PSCustomObject]@{
                    Kind   = 'Binding'
                    Name   = ($fname + '=>' + $cname)
                    Detail = ($fname + ' => ' + $cname)
                }
            }
        }
        catch { }
        $rows | Sort-Object Kind, Name
    }
