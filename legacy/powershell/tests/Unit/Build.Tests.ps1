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
            # Script-level switches must land in the flatten param() or operators get NamedParameterNotFound.
            $raw | Should -Match '(?m)^\s*\[switch\]\$Deep\s*,?\s*$'
            $raw | Should -Match '(?m)^\s*\[switch\]\$IncludeUsnJournal\s*,?\s*$'
            $raw | Should -Not -Match '(?m)^\s*Import-Module\b'
            # Benign pattern tables still embed; the endpoint needs them offline.
            $raw | Should -Match 'UserWritablePatterns'
            $raw | Should -Match 'HardeningCsv'
            # The suspicious-command list must not. Embedding it makes Defender block
            # the whole collector at load as Trojan:PowerShell/PSAttackTool.A.
            $raw | Should -Match 'SuspiciousCommandPatterns\s*=\s*@\(\)'
            $raw | Should -Not -Match 'sekurlsa'
        }
        finally {
            Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
        }
    }

    It 'defines every Foton function the Collect flatten calls' {
        # The module loads every src/Private folder; the flatten only concatenates an
        # explicit list. A helper outside that list passes the module tests and then
        # throws CommandNotFound on the endpoint (seen with analyze helpers).
        $out = Join-Path $env:TEMP ('Foton-Collect-calls-' + [guid]::NewGuid().ToString('N') + '.ps1')
        try {
            & $script:BuildScript -OutputPath $out 6>$null | Out-Null
            $tokens = $null; $errs = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($out, [ref]$tokens, [ref]$errs)
            $defined = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
                    ForEach-Object { $_.Name })
            $called = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                    ForEach-Object { $_.GetCommandName() } |
                    Where-Object { $_ -and $_ -match '^[A-Za-z]+-Foton' } | Sort-Object -Unique)
            $missing = @($called | Where-Object { $defined -notcontains $_ })
            $missing | Should -BeNullOrEmpty
        }
        finally {
            Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
        }
    }

    It 'never reads the WSMan: drive during collection' {
        $src = Join-Path (Split-Path $script:BuildScript -Parent) '..\src\Public\Collect'
        $hits = @(Get-ChildItem -LiteralPath $src -Filter '*.ps1' -File | Select-String -Pattern 'WSMan:\\' -SimpleMatch:$false |
                Where-Object { $_.Line -notmatch '^\s*#' })
        $hits | Should -BeNullOrEmpty
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

    It 'defines every Foton function the Baseline flatten calls' {
        $out = Join-Path $env:TEMP ('Foton-Baseline-calls-' + [guid]::NewGuid().ToString('N') + '.ps1')
        try {
            & $script:BaselineBuild -OutputPath $out 6>$null | Out-Null
            $tokens = $null; $errs = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($out, [ref]$tokens, [ref]$errs)
            $defined = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
                    ForEach-Object { $_.Name })
            $called = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                    ForEach-Object { $_.GetCommandName() } |
                    Where-Object { $_ -and $_ -match '^[A-Za-z]+-Foton' } | Sort-Object -Unique)
            @($called | Where-Object { $defined -notcontains $_ }) | Should -BeNullOrEmpty
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
