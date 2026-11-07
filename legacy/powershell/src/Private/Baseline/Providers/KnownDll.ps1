# KnownDll - Session Manager KnownDLLs map (search-order). Identity value name; compared mapped file.
# Do not hash the DLL. DllDirectory* path values are included; OS upgrades add entries.
Register-FotonBaselineProvider -RecordType 'KnownDll' `
    -IdentityFields @('Name') `
    -ComparedFields @('MappedFile') `
    -FalsePositives 'Feature updates add KnownDLL entries. DllDirectory / DllDirectory32 follow SysWOW64 layout. A new Name or a MappedFile that is not a System32 DLL is the review item, not the stock ntdll/kernel32 list.' `
    -Collect {
        $rows = @()
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs'
        foreach ($v in (Get-FotonRegValueList -Path $key)) {
            $rows += [PSCustomObject]@{
                Name       = [string]$v.Name
                MappedFile = [string]$v.Value
            }
        }
        $rows | Sort-Object Name
    }
