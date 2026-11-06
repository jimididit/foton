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
        $v.ModuleVersion | Should -Be '1.37.1'
        $v.CollectSchemaVersion | Should -Be '1.13.0'
        $v.BaselineSchemaVersion | Should -Be '1.14.0'
        $v.FindingsSchemaVersion | Should -Be '1.0.0'
        $v.ReleaseDate | Should -Match '^\d{4}-\d{2}-\d{2}$'
    }

    It 'keeps public docs and the banner on the current version' {
        $man = Import-PowerShellDataFile -LiteralPath $script:FotonPsd1
        $ver = [string]$man.ModuleVersion
        $collect = [string]$man.PrivateData.Foton.CollectSchemaVersion
        $baseline = [string]$man.PrivateData.Foton.BaselineSchemaVersion
        $root = Split-Path $script:FotonPsd1 -Parent
        $readme = Get-Content -LiteralPath (Join-Path $root 'README.md') -Raw
        $usage = Get-Content -LiteralPath (Join-Path $root 'docs\USAGE.md') -Raw
        $readme | Should -Match ([regex]::Escape("badge/module-$ver-"))
        $usage | Should -Match ([regex]::Escape("module **$ver**, collect schema **$collect**, baseline schema **$baseline**"))
        foreach ($doc in @($readme, $usage)) {
            foreach ($m in [regex]::Matches($doc, 'Foton-(Collect|Baseline)_v(?<v>[\d.]+)_schema(?<s>[\d.]+)\.ps1')) {
                $m.Groups['v'].Value | Should -Be $ver
                $expectSchema = $collect
                if ($m.Value -like 'Foton-Baseline*') { $expectSchema = $baseline }
                $m.Groups['s'].Value | Should -Be $expectSchema
            }
        }
        $banner = Get-Content -LiteralPath (Join-Path $root 'src\Private\Core\Write-FotonBanner.ps1') -Raw
        $banner | Should -Not -Match "Updated\s+\d"
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
