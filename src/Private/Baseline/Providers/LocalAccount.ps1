# LocalAccount — identity SID, never username (rename would look like remove+add).
Register-FotonBaselineProvider -RecordType 'LocalAccount' `
    -IdentityFields @('SID') `
    -ComparedFields @('Name', 'Enabled', 'PasswordRequired', 'PasswordExpires') `
    -FalsePositives 'Built-in accounts differ by Windows edition. Enabled Guest is unusual; a renamed Administrator SID is still S-1-5-21-*-500.' `
    -Collect {
        $rows = @()
        try {
            Get-LocalUser -ErrorAction Stop | ForEach-Object {
                $rows += [PSCustomObject]@{
                    SID              = [string]$_.SID
                    Name             = [string]$_.Name
                    Enabled          = [bool]$_.Enabled
                    PasswordRequired = [bool]$_.PasswordRequired
                    PasswordExpires  = [bool]$_.PasswordExpires
                }
            }
        }
        catch { }
        $rows | Sort-Object SID
    }
