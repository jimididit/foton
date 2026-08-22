$moduleManifest = Join-Path $PSScriptRoot '..\Foton.psd1'
Import-Module $moduleManifest -Force

InModuleScope Foton {
    Describe 'Collect category functions (extracted)' {
        It 'defines all nine category collectors' {
            Get-Command Invoke-FotonSystemCollection -ErrorAction Stop | Should -Not -BeNullOrEmpty
            Get-Command Invoke-FotonUserCollection -ErrorAction Stop | Should -Not -BeNullOrEmpty
            Get-Command Invoke-FotonProcessCollection -ErrorAction Stop | Should -Not -BeNullOrEmpty
            Get-Command Invoke-FotonNetworkCollection -ErrorAction Stop | Should -Not -BeNullOrEmpty
            Get-Command Invoke-FotonPersistenceCollection -ErrorAction Stop | Should -Not -BeNullOrEmpty
            Get-Command Invoke-FotonSecurityCollection -ErrorAction Stop | Should -Not -BeNullOrEmpty
            Get-Command Invoke-FotonEventLogCollection -ErrorAction Stop | Should -Not -BeNullOrEmpty
            Get-Command Invoke-FotonFilesystemCollection -ErrorAction Stop | Should -Not -BeNullOrEmpty
            Get-Command Invoke-FotonSoftwareCollection -ErrorAction Stop | Should -Not -BeNullOrEmpty
        }
        It 'does not export Collect commands on the public module surface yet' {
            Get-Command -Module Foton | Select-Object -ExpandProperty Name | Sort-Object |
                Should -Be @(
                    'Compare-FotonBaseline'
                    'ConvertFrom-FotonPrefetch'
                    'Get-FotonPackage'
                    'Get-FotonVersion'
                    'Invoke-FotonAnalysis'
                    'Invoke-FotonCarve'
                    'Invoke-FotonIocMatch'
                    'Invoke-FotonParse'
                    'Invoke-FotonTriage'
                    'New-FotonBaseline'
                    'New-FotonReport'
                )
        }
    }
}
