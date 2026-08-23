BeforeAll {
    $script:BuildScript = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\build\Build-Standalone.ps1'))
    $script:BaselineBuild = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\build\Build-BaselineStandalone.ps1'))
}

Describe 'Build-Standalone' {
    It 'emits a parse-clean Foton-Collect.ps1 without Import-Module' {
        $out = Join-Path $env:TEMP ('Foton-Collect-test-' + [guid]::NewGuid().ToString('N') + '.ps1')
        try {
            & $script:BuildScript -OutputPath $out
            Test-Path -LiteralPath $out | Should -Be $true
            $errors = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile($out, [ref]$null, [ref]$errors)
            $errors | Should -BeNullOrEmpty
            $raw = Get-Content -LiteralPath $out -Raw
            $raw | Should -Match 'function Invoke-FotonTriage'
            $raw | Should -Match 'function Invoke-FotonSystemCollection'
            $raw | Should -Not -Match '(?m)^\s*Import-Module\b'
            $raw | Should -Match "'iex '"
        }
        finally {
            Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
        }
    }

    It 'default dist leaf includes module version and collect schema' {
        $src = Get-Content -LiteralPath $script:BuildScript -Raw
        $src | Should -Match 'Foton-Collect_v\$\{version\}_schema\$\{collectSchema\}'
    }
}

Describe 'Build-BaselineStandalone' {
    It 'emits a parse-clean Foton-Baseline.ps1 without Collect or Import-Module' {
        $out = Join-Path $env:TEMP ('Foton-Baseline-test-' + [guid]::NewGuid().ToString('N') + '.ps1')
        try {
            & $script:BaselineBuild -OutputPath $out
            Test-Path -LiteralPath $out | Should -Be $true
            $errors = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile($out, [ref]$null, [ref]$errors)
            $errors | Should -BeNullOrEmpty
            $raw = Get-Content -LiteralPath $out -Raw
            $raw | Should -Match 'function New-FotonBaseline'
            $raw | Should -Match 'function New-FotonBaselineReport'
            $raw | Should -Match 'Register-FotonBaselineProvider'
            $raw | Should -Match 'HardeningCsv'
            $raw | Should -Match 'EnableLUA'
            $raw | Should -Not -Match 'function Invoke-FotonTriage'
            $raw | Should -Not -Match '(?m)^\s*Import-Module\b'
        }
        finally {
            Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
        }
    }

    It 'default dist leaf includes module version and baseline schema' {
        $src = Get-Content -LiteralPath $script:BaselineBuild -Raw
        $src | Should -Match 'Foton-Baseline_v\$\{version\}_schema\$\{baseSchema\}'
    }
}
