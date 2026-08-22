# ImageFileExecution - IFEO Debugger values only (the huge IFEO tree without Debugger is ignored).
Register-FotonBaselineProvider -RecordType 'ImageFileExecution' `
    -IdentityFields @('ImageName') `
    -ComparedFields @('Debugger') `
    -FalsePositives 'Application Verifier, GFlags, and some debuggers set Debugger. SilentProcessExit is not collected here.' `
    -Collect {
        $rows = @()
        $root = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        try {
            if (Test-Path -LiteralPath $root) {
                foreach ($sub in (Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
                    $dbg = Get-FotonRegValue -Path $sub.PSPath -Name 'Debugger'
                    if ($null -eq $dbg -or [string]$dbg -eq '') { continue }
                    $rows += [PSCustomObject]@{
                        ImageName = [string]$sub.PSChildName
                        Debugger  = [string]$dbg
                    }
                }
            }
        }
        catch { }
        $rows | Sort-Object ImageName
    }
