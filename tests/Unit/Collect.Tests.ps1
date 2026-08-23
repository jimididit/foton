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

    It 'adds named persistence CSVs for CmdAutoRun, Session Manager, KnownDLLs, Winsock, Active Setup' {
        $src = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\src\Public\Collect\Invoke-FotonPersistenceCollection.ps1') -Raw
        $src | Should -Match "Name 'cmd_autorun'"
        $src | Should -Match "Name 'session_manager_boot'"
        $src | Should -Match "Name 'known_dlls'"
        $src | Should -Match "Name 'winsock_lsp'"
        $src | Should -Match "Name 'active_setup'"
    }

    It 'adds copy-into-package tasks for Prefetch, Amcache, and SRUM' {
        $src = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\src\Public\Collect\Invoke-FotonFilesystemCollection.ps1') -Raw
        $src | Should -Match "Name 'prefetch_files'"
        $src | Should -Match "Name 'amcache_hive'"
        $src | Should -Match "Name 'srum_database'"
        $src | Should -Match "Name 'prefetch_listing'"
    }

    It 'does not export Collect commands on the public module surface yet' {
        Get-Command -Module Foton | Select-Object -ExpandProperty Name | Sort-Object |
            Should -Be @(
                'Compare-FotonBaseline'
                'ConvertFrom-FotonEvtx'
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
                'New-FotonBaselineCompareReport'
                'New-FotonBaselineReport'
                'New-FotonParseReport'
                'New-FotonReport'
            )
    }
}
