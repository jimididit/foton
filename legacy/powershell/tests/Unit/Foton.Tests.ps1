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
        $v.ModuleVersion | Should -Be '1.38.1'
        $v.CollectSchemaVersion | Should -Be '1.13.0'
        $v.BaselineSchemaVersion | Should -Be '1.14.0'
        $v.FindingsSchemaVersion | Should -Be '1.0.0'
        $v.ReleaseDate | Should -Match '^\d{4}-\d{2}-\d{2}$'
    }

    It 'reads the banner version and release date from top-level manifest keys only' {
        Import-Module $script:FotonPsd1 -Force
        $tmp = Join-Path $env:TEMP ('foton-banner-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $tmp | Out-Null
        try {
            @(
                '@{'
                "    RequiredModules = @(@{ ModuleName = 'Other'; ModuleVersion = '9.9.9' })"
                "    ModuleVersion     = '1.2.3'"
                '    PrivateData = @{'
                '        Foton = @{'
                "            ReleaseDate = '2026-01-02'"
                '        }'
                '    }'
                '}'
            ) | Set-Content -LiteralPath (Join-Path $tmp 'Foton.psd1')
            $out = InModuleScope Foton -Parameters @{ Root = $tmp } {
                param($Root)
                $savedRoot = $script:FotonModuleRoot
                $savedSession = $script:FotonSession
                try {
                    $script:FotonModuleRoot = $Root
                    $script:FotonSession = $null
                    Write-FotonBanner -Kind Analyze -Color None 6>&1 | Out-String
                }
                finally {
                    $script:FotonModuleRoot = $savedRoot
                    $script:FotonSession = $savedSession
                }
            }
            $out | Should -Match 'Version\s+1\.2\.3'
            $out | Should -Match 'Updated\s+2026-01-02'
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'keeps public docs and the banner on the current version' {
        $man = Import-PowerShellDataFile -LiteralPath $script:FotonPsd1
        $ver = [string]$man.ModuleVersion
        $collect = [string]$man.PrivateData.Foton.CollectSchemaVersion
        $baseline = [string]$man.PrivateData.Foton.BaselineSchemaVersion
        $root = Split-Path $script:FotonPsd1 -Parent
        # The module lives in legacy\powershell; public docs and LICENSE stay at the repository root.
        $repo = [IO.Path]::GetFullPath((Join-Path $root '..\..'))
        $readme = Get-Content -LiteralPath (Join-Path $repo 'README.md') -Raw
        $usage = Get-Content -LiteralPath (Join-Path $repo 'docs\USAGE.md') -Raw
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
        # The Gallery shows the manifest Author; the banner must name the same author.
        $banner | Should -Match ("Author\s+{0}'" -f [regex]::Escape([string]$man.Author))
        (Get-Content -LiteralPath (Join-Path $repo 'LICENSE') -Raw) | Should -Match ([regex]::Escape([string]$man.Author))
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
