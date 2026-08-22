function Test-FotonElevated {
    <# True when the current process token is in the local Administrators role. Catch-all false: a failed check must not look elevated. #>
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}
