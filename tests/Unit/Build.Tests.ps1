BeforeAll {
    $script:BuildScript = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\build\Build-Standalone.ps1'))
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
}
