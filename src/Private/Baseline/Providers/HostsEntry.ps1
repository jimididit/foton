# HostsEntry - identity Address + Hostname. Comments and blanks omitted. Added rows are High; lab DNS overrides are a common false positive.
Register-FotonBaselineProvider -RecordType 'HostsEntry' `
    -IdentityFields @('Address', 'Hostname') `
    -ComparedFields @() `
    -FalsePositives 'Local development (localhost, kubernetes.docker.internal), ad-block lists, and MDM-managed hosts files. IPv6 localhost (::1) is expected.' `
    -Collect {
        $rows = @()
        $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
        try {
            if (-not (Test-Path -LiteralPath $hostsPath -PathType Leaf)) { return @() }
            foreach ($line in (Get-Content -LiteralPath $hostsPath -ErrorAction Stop)) {
                if ($null -eq $line) { continue }
                $t = $line.Trim()
                if ($t -eq '' -or $t.StartsWith('#')) { continue }
                $hash = $t.IndexOf('#')
                if ($hash -ge 0) { $t = $t.Substring(0, $hash).Trim() }
                $parts = @($t -split '\s+' | Where-Object { $_ -ne '' })
                if ($parts.Count -lt 2) { continue }
                $addr = [string]$parts[0]
                for ($i = 1; $i -lt $parts.Count; $i++) {
                    $rows += [PSCustomObject]@{
                        Address  = $addr
                        Hostname = [string]$parts[$i]
                    }
                }
            }
        }
        catch { }
        $rows | Sort-Object Address, Hostname
    }
