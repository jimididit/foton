$moduleManifest = Join-Path $PSScriptRoot '..\..\Foton.psd1'
Import-Module $moduleManifest -Force

Describe 'Invoke-FotonCarve' {
    It 'refuses to fake NTFS carving' {
        { Invoke-FotonCarve -Path 'C:\not-an-image.bin' } | Should -Throw
    }
}
