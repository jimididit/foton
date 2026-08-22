# StartupApproved - Task Manager / Settings enable-disable bits. Not the Startup folder (that is StartupFile).
Register-FotonBaselineProvider -RecordType 'StartupApproved' `
    -IdentityFields @('Scope', 'Store', 'ValueName') `
    -ComparedFields @('State') `
    -FalsePositives 'Users toggling Teams, OneDrive, chat, and vendor updaters in Settings is a common benign change. Only loaded user hives are visible without hive load.' `
    -Collect {
        Get-FotonStartupApprovedRows
    }
