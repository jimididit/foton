$moduleManifest = Join-Path $PSScriptRoot '..\..\Foton.psd1'
$fx = Join-Path $PSScriptRoot '..\Fixtures\Parse'
Import-Module $moduleManifest -Force

Describe 'ConvertFrom-FotonPrefetch' {
    It 'reads an uncompressed SCCA v23 executable name' {
        $r = ConvertFrom-FotonPrefetch -Path (Join-Path $fx 'prefetch-scca-v23.bin')
        $r.Format | Should -Be 'SCCA'
        $r.Supported | Should -Be $true
        $r.ExecutableName | Should -Be 'NOTEPAD.EXE'
    }

    It 'does not invent a name for MAM-compressed prefetch' {
        $r = ConvertFrom-FotonPrefetch -Path (Join-Path $fx 'prefetch-mam.bin')
        $r.Format | Should -Be 'MAM-compressed'
        $r.Supported | Should -Be $false
        $r.ExecutableName | Should -Be ''
    }

    It 'emits unsupported for non-prefetch bytes' {
        $r = ConvertFrom-FotonPrefetch -Path (Join-Path $fx 'prefetch-not.bin')
        $r.Format | Should -Be 'Unsupported-NotPrefetch'
        $r.Supported | Should -Be $false
    }
}
