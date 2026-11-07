# WdacApplockerPolicy - Code Integrity / AppLocker policy blob hash. Not a compliance score.
# Identity is Kind + Name so SIPolicy.p7b, each .cip, and AppLocker XML stay stable.
# FP: feature updates refresh SiPolicy.p7b; Intune/GPO republish AppLocker XML with new timestamps inside the XML even when rules look the same.
Register-FotonBaselineProvider -RecordType 'WdacApplockerPolicy' `
    -IdentityFields @('Kind', 'Name') `
    -ComparedFields @('PolicyHash', 'Path') `
    -FalsePositives 'Windows Update and WDAC/AppLocker MDM refresh change PolicyHash without a local operator edit. Compare is change between snapshots, not who published the policy.' `
    -Collect {
        $rows = @()
        $ci = Join-Path $env:SystemRoot 'System32\CodeIntegrity'
        $si = Join-Path $ci 'SiPolicy.p7b'
        if (Test-Path -LiteralPath $si -PathType Leaf) {
            $rows += [PSCustomObject]@{
                Kind        = 'Wdac'
                Name        = 'SiPolicy.p7b'
                Path        = $si
                PolicyHash  = (Get-FotonSafeHash -Path $si)
            }
        }
        else {
            $rows += [PSCustomObject]@{
                Kind        = 'Wdac'
                Name        = 'SiPolicy.p7b'
                Path        = $si
                PolicyHash  = '(not present)'
            }
        }
        if (Test-Path -LiteralPath $ci) {
            foreach ($f in (Get-ChildItem -LiteralPath $ci -Filter '*.cip' -File -Force -ErrorAction SilentlyContinue)) {
                $rows += [PSCustomObject]@{
                    Kind       = 'WdacCip'
                    Name       = $f.Name
                    Path       = $f.FullName
                    PolicyHash = (Get-FotonSafeHash -Path $f.FullName)
                }
            }
        }
        $alXml = $null
        try {
            if (Get-Command Get-AppLockerPolicy -ErrorAction SilentlyContinue) {
                $alXml = [string](Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop)
            }
        }
        catch { }
        if ($alXml) {
            $bytes = [Text.Encoding]::UTF8.GetBytes($alXml)
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try {
                $hash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '')
            }
            finally { $sha.Dispose() }
            $rows += [PSCustomObject]@{
                Kind       = 'AppLocker'
                Name       = 'EffectiveXml'
                Path       = 'Get-AppLockerPolicy -Effective -Xml'
                PolicyHash = $hash
            }
        }
        else {
            $rows += [PSCustomObject]@{
                Kind       = 'AppLocker'
                Name       = 'EffectiveXml'
                Path       = 'Get-AppLockerPolicy -Effective -Xml'
                PolicyHash = '(not present)'
            }
        }
        $rows | Sort-Object Kind, Name
    }
