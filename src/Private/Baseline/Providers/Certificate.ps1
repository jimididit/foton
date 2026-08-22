# Certificate — identity Store + Thumbprint (same CA in Root vs CA is two rows).
Register-FotonBaselineProvider -RecordType 'Certificate' `
    -IdentityFields @('Store', 'Thumbprint') `
    -ComparedFields @('Subject', 'Issuer', 'NotAfter') `
    -FalsePositives 'Enterprise Root CA rollout and Intune add roots. A new Root thumbprint that is not Microsoft/your org CA is the usual review item. Renewal changes NotAfter for the same thumbprint only if the cert is reissued with the same key — often a new thumbprint (Added+Removed).' `
    -Collect {
        $rows = @()
        foreach ($store in @('Cert:\LocalMachine\Root', 'Cert:\LocalMachine\CA', 'Cert:\LocalMachine\TrustedPublisher')) {
            try {
                foreach ($c in (Get-ChildItem -Path $store -ErrorAction Stop)) {
                    $rows += [PSCustomObject]@{
                        Store      = $store
                        Thumbprint = [string]$c.Thumbprint
                        Subject    = [string]$c.Subject
                        Issuer     = [string]$c.Issuer
                        NotAfter   = $c.NotAfter.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
                    }
                }
            }
            catch { }
        }
        $rows | Sort-Object Store, Thumbprint
    }
