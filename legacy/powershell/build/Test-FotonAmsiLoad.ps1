<#
    .SYNOPSIS
    Reports whether antivirus blocks a generated Foton script at load time.

    .DESCRIPTION
    The parse check in the verification loop uses
    [Parser]::ParseFile, which reads the file directly and never invokes AMSI.
    That is why a flatten containing an embedded list of credential-theft strings
    passed every local check and was still blocked on the endpoint as
    Trojan:PowerShell/PSAttackTool.A.

    This check compiles the script text in a child Windows PowerShell process with
    [ScriptBlock]::Create, which does pass the content through AMSI. Compilation is
    not execution: no collection runs, nothing is written, and Invoke-FotonTriage is
    never called.

    A pass here only means the scanner on THIS machine allows the file. Operators
    run other products, so this is a regression guard against reintroducing a known
    signature, not a guarantee of clean delivery.

    Note that a block may cause the local antivirus to quarantine the tested file.
    That is the intended signal; rebuild after fixing the cause.

    .PARAMETER Path
    The generated script to test, typically dist/Foton-Collect.ps1.

    .EXAMPLE
    .\build\Test-FotonAmsiLoad.ps1 -Path .\dist\Foton-Collect.ps1

    Prints 'AMSI LOAD OK' or the blocking error, and sets a non-zero exit code when
    the script is blocked.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path
)

$resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath

# Windows PowerShell 5.1 is the Collect/Baseline target runtime, so scan under the
# engine the endpoint will actually use.
$probe = @'
param([string]$Target)
try {
    $null = [ScriptBlock]::Create([IO.File]::ReadAllText($Target))
    'ALLOWED'
}
catch {
    'BLOCKED: ' + $_.Exception.Message
}
'@

$probePath = Join-Path $env:TEMP ('foton-amsiload-' + [guid]::NewGuid().ToString('N') + '.ps1')
try {
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [IO.File]::WriteAllText($probePath, $probe, $utf8)

    $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $probePath -Target $resolved 2>&1 |
        Out-String

    if ($out -match 'ALLOWED') {
        Write-Host "AMSI LOAD OK  $resolved" -ForegroundColor Green
        exit 0
    }

    Write-Host "AMSI LOAD BLOCKED  $resolved" -ForegroundColor Red
    Write-Host ($out.Trim()) -ForegroundColor Red
    Write-Host 'The file may now be quarantined. Find the offending content, remove it from the build, and rebuild.' -ForegroundColor Yellow
    Write-Host 'Do not encode or split strings to defeat the scanner: obfuscation is itself an antivirus signal and breaks examiner readability.' -ForegroundColor Yellow
    exit 1
}
finally {
    Remove-Item -LiteralPath $probePath -Force -ErrorAction SilentlyContinue
}
