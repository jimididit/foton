function ConvertTo-FotonCommandLine {
    <#
    .SYNOPSIS
        Join arguments into one Windows command line that CommandLineToArgvW splits back unchanged.
    .DESCRIPTION
        Start-Process -ArgumentList joins an array with spaces and adds no quoting, so a
        case path such as D:\My Cases\CASE-0001 reaches the tool as two arguments.
        Quoting follows the MSVCRT rules the EZ Tools (.NET), Hayabusa and Chainsaw (Rust)
        all use: wrap in quotes when the value is empty or holds whitespace or a quote,
        escape embedded quotes, and double backslashes that precede a quote.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyCollection()][object[]]$Arguments)

    $parts = foreach ($a in @($Arguments)) {
        $s = [string]$a
        if ($s.Length -gt 0 -and $s -notmatch '[\s"]') { $s; continue }
        $sb = New-Object System.Text.StringBuilder
        $null = $sb.Append('"')
        $slashes = 0
        foreach ($ch in $s.ToCharArray()) {
            if ($ch -eq '\') { $slashes++; continue }
            if ($ch -eq '"') {
                $null = $sb.Append('\', (2 * $slashes + 1)).Append('"')
            }
            else {
                $null = $sb.Append('\', $slashes).Append($ch)
            }
            $slashes = 0
        }
        $null = $sb.Append('\', (2 * $slashes)).Append('"')
        $sb.ToString()
    }
    return (@($parts) -join ' ')
}
