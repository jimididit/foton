# WinsockLsp - Protocol_Catalog9 PackedCatalogItem + NameSpace_Catalog5 LibraryPath.
# Identity Kind + Entry (catalog index). FP: VPN/security LSPs.
Register-FotonBaselineProvider -RecordType 'WinsockLsp' `
    -IdentityFields @('Kind', 'Entry') `
    -ComparedFields @('LibraryPath') `
    -FalsePositives 'VPN, filter, and endpoint-security products register LSPs and namespace providers. Stock Catalog_Entries are many (often mswsock.dll). A new LibraryPath outside System32 is the review item, not the numeric index itself.' `
    -Collect {
        $rows = @()
        $protoRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9'
        foreach ($leaf in @('Catalog_Entries', 'Catalog_Entries64')) {
            $root = Join-Path $protoRoot $leaf
            if (-not (Test-Path -LiteralPath $root)) { continue }
            $kind = 'Protocol'
            if ($leaf -eq 'Catalog_Entries64') { $kind = 'Protocol64' }
            try {
                foreach ($sub in (Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
                    $packed = Get-FotonRegValue -Path $sub.PSPath -Name 'PackedCatalogItem'
                    $rows += [PSCustomObject]@{
                        Kind        = $kind
                        Entry       = [string]$sub.PSChildName
                        LibraryPath = Get-FotonWinsockPackedPath -Bytes $packed
                    }
                }
            }
            catch { }
        }
        $ns = 'HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries'
        if (Test-Path -LiteralPath $ns) {
            try {
                foreach ($sub in (Get-ChildItem -LiteralPath $ns -ErrorAction Stop)) {
                    $lib = Get-FotonRegValue -Path $sub.PSPath -Name 'LibraryPath'
                    $shown = '(not set)'
                    if ($null -ne $lib -and [string]$lib -ne '') { $shown = [string]$lib }
                    $rows += [PSCustomObject]@{
                        Kind        = 'Namespace'
                        Entry       = [string]$sub.PSChildName
                        LibraryPath = $shown
                    }
                }
            }
            catch { }
        }
        $rows | Sort-Object Kind, Entry
    }
