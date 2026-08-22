BeforeAll {
    $script:FotonPsd1 = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\Foton.psd1'))
    Import-Module $script:FotonPsd1 -Force
}

Describe 'Collect category functions (extracted)' {
    It 'defines all nine category collectors' {
        InModuleScope Foton {
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
    }

    It 'does not export Collect commands on the public module surface yet' {
        Get-Command -Module Foton | Select-Object -ExpandProperty Name | Sort-Object |
            Should -Be @(
                'Compare-FotonBaseline'
                'ConvertFrom-FotonLnk'
                'ConvertFrom-FotonPrefetch'
                'Get-FotonPackage'
                'Get-FotonVersion'
                'Invoke-FotonAnalysis'
                'Invoke-FotonCarve'
                'Invoke-FotonIocMatch'
                'Invoke-FotonParse'
                'Invoke-FotonTriage'
                'New-FotonBaseline'
                'New-FotonBaselineReport'
                'New-FotonReport'
            )
    }
}
