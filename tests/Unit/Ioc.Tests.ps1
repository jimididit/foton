$moduleManifest = Join-Path $PSScriptRoot '..\..\Foton.psd1'
$pkg = Join-Path $PSScriptRoot '..\Fixtures\WinFoton_FIXTURE_20260115-120000Z'
$ioc = Join-Path $PSScriptRoot '..\Fixtures\Ioc\lab-iocs.txt'
Import-Module $moduleManifest -Force

Describe 'Invoke-FotonIocMatch' {
    It 'matches a text IOC against loaded package rows' {
        Get-FotonPackage -Path $pkg | Out-Null
        $hits = Invoke-FotonIocMatch -IocPath $ioc
        @($hits | Where-Object { $_.Sample -match 'payload.exe' }).Count | Should -BeGreaterThan 0
    }

    It 'does not match a benign string that is not in the IOC file' {
        Get-FotonPackage -Path $pkg | Out-Null
        $tmp = Join-Path $env:TEMP ('foton-ioc-' + [guid]::NewGuid().ToString('N') + '.txt')
        'text:this-indicator-is-not-in-the-fixture' | Out-File -FilePath $tmp -Encoding ascii
        try {
            $hits = Invoke-FotonIocMatch -IocPath $tmp
            @($hits).Count | Should -Be 0
        }
        finally {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }
}
