# Foton.Tests.ps1 - module import smoke test

BeforeAll {
    $script:FotonPsd1 = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\Foton.psd1'))
}

Describe 'Foton module scaffold' {
    It 'has a parse-clean module manifest' {
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:FotonPsd1,
            [ref]$null,
            [ref]$errors
        )
        $errors | Should -BeNullOrEmpty
    }

    It 'imports and reports version metadata' {
        Import-Module $script:FotonPsd1 -Force
        $v = Get-FotonVersion
        $v.ProductName | Should -Be 'Foton'
        $v.ModuleVersion | Should -Be '1.32.0'
        $v.CollectSchemaVersion | Should -Be '1.11.0'
        $v.BaselineSchemaVersion | Should -Be '1.14.0'
        $v.FindingsSchemaVersion | Should -Be '1.0.0'
    }

    It 'exports package, analysis, and report commands (Collect stays unexported)' {
        Import-Module $script:FotonPsd1 -Force
        Get-Command -Module Foton | Select-Object -ExpandProperty Name | Sort-Object |
            Should -Be @(
                'Compare-FotonBaseline'
                'ConvertFrom-FotonAmcache'
                'ConvertFrom-FotonEvtx'
                'ConvertFrom-FotonJumplist'
                'ConvertFrom-FotonLnk'
                'ConvertFrom-FotonPrefetch'
                'Get-FotonPackage'
                'Get-FotonVersion'
                'Install-FotonTool'
                'Invoke-FotonAnalysis'
                'Invoke-FotonCarve'
                'Invoke-FotonExternalParse'
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
