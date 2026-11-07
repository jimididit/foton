# StartupFile - Common Startup plus each profile Startup folder. Identity Scope (Common or SID) + FileName. Shortcut churn from Teams/OneDrive is a common false positive.
Register-FotonBaselineProvider -RecordType 'StartupFile' `
    -IdentityFields @('Scope', 'FileName') `
    -ComparedFields @('Sha256', 'Length') `
    -FalsePositives 'Vendor updaters drop .lnk files here. Per-user rows follow who has a profile on disk, not who is logged on. desktop.ini is omitted.' `
    -Collect {
        $rows = @()
        $dirs = @()
        $common = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'
        $dirs += [PSCustomObject]@{ Scope = 'Common'; Path = $common }
        foreach ($u in @(Get-FotonUserProfile)) {
            if (-not $u.Exists) { continue }
            $p = Join-Path $u.ProfilePath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
            $dirs += [PSCustomObject]@{ Scope = [string]$u.SID; Path = $p }
        }
        foreach ($d in $dirs) {
            if (-not (Test-Path -LiteralPath $d.Path)) { continue }
            try {
                foreach ($f in (Get-ChildItem -LiteralPath $d.Path -File -Force -ErrorAction Stop)) {
                    if ($f.Name -eq 'desktop.ini') { continue }
                    $rows += [PSCustomObject]@{
                        Scope    = [string]$d.Scope
                        FileName = [string]$f.Name
                        Path     = [string]$f.FullName
                        Length   = [string]$f.Length
                        Sha256   = Get-FotonSafeHash -Path $f.FullName
                    }
                }
            }
            catch { }
        }
        $rows | Sort-Object Scope, FileName
    }
