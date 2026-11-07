# Release.Tests.ps1 - release assets build, ship only allow-listed files, and the
# workstation zip analyzes a case on its own (no repo checkout next to it).

BeforeAll {
    $script:RepoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
    $script:Manifest = Import-PowerShellDataFile -LiteralPath (Join-Path $script:RepoRoot 'Foton.psd1')
    $script:Version = [string]$script:Manifest.ModuleVersion
    $script:Out = Join-Path $env:TEMP ('foton-release-' + [guid]::NewGuid().ToString('N'))
    & (Join-Path $script:RepoRoot 'build\Build-Release.ps1') -RepoRoot $script:RepoRoot -OutputPath $script:Out *> $null
    $script:ZipPath = Join-Path $script:Out ("Foton-Workstation_v{0}.zip" -f $script:Version)
}

AfterAll {
    Remove-Item -LiteralPath $script:Out -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Build-Release' {
    It 'writes the three assets and a matching SHA256SUMS.txt' {
        $sums = @(Get-Content -LiteralPath (Join-Path $script:Out 'SHA256SUMS.txt'))
        $sums | Should -HaveCount 3
        foreach ($line in $sums) {
            $hash, $leaf = $line -split '  ', 2
            $file = Join-Path $script:Out $leaf
            Test-Path -LiteralPath $file | Should -Be $true
            (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() | Should -Be $hash
        }
        ($sums -join "`n") | Should -Match ([regex]::Escape("Foton-Workstation_v$($script:Version).zip"))
        ($sums -join "`n") | Should -Match ("Foton-Collect_v{0}_schema[\d.]+\.ps1" -f [regex]::Escape($script:Version))
    }

    It 'ships only the allow-listed files in the workstation zip' {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [IO.Compression.ZipFile]::OpenRead($script:ZipPath)
        try { $names = @($zip.Entries | ForEach-Object { $_.FullName -replace '\\', '/' }) }
        finally { $zip.Dispose() }
        $prefix = "Foton-$($script:Version)/"
        @($names | Where-Object { -not $_.StartsWith($prefix) }) | Should -HaveCount 0
        foreach ($need in @('Foton.psd1', 'Foton.psm1', 'Foton.cmd', 'LICENSE', 'tools/Invoke-FotonEasy.ps1', 'docs/USAGE.md', 'dist/Foton-Collect.ps1', 'src/Public/Analyze/Invoke-FotonAnalysis.ps1')) {
            $names | Should -Contain ($prefix + $need)
        }
        foreach ($bad in @('tests/', 'build/', '.github/', 'docs/TODO.md', 'docs/CONTRIBUTING.md', 'AGENTS.md', 'WinFoton.ps1', '.scratchpad/')) {
            @($names | Where-Object { $_.StartsWith($prefix + $bad) }) | Should -HaveCount 0
        }
    }

    It 'refuses a -DocsRoot that is missing the operator docs' {
        $empty = Join-Path $env:TEMP ('foton-docs-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $empty | Out-Null
        try {
            { & (Join-Path $script:RepoRoot 'build\Build-Release.ps1') -RepoRoot $script:RepoRoot -DocsRoot $empty -OutputPath (Join-Path $empty 'out') -SkipFlattenBuild *> $null } |
                Should -Throw '*must contain*'
        }
        finally { Remove-Item -LiteralPath $empty -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'refuses a module copy with no operator docs nearby instead of assuming a layout' {
        $lone = Join-Path $env:TEMP ('foton-lone-' + [guid]::NewGuid().ToString('N'))
        $module = Join-Path $lone 'a\b\module'
        New-Item -ItemType Directory -Path $module -Force | Out-Null
        try {
            { & (Join-Path $script:RepoRoot 'build\Build-Release.ps1') -RepoRoot $module -OutputPath (Join-Path $lone 'out') -SkipFlattenBuild *> $null } |
                Should -Throw '*Pass -DocsRoot*'
        }
        finally { Remove-Item -LiteralPath $lone -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'stages a Gallery module whose manifest validates' {
        $psd1 = Join-Path $script:Out 'gallery\Foton\Foton.psd1'
        $m = Test-ModuleManifest -Path $psd1 -ErrorAction Stop
        $m.Name | Should -Be 'Foton'
        [string]$m.Version | Should -Be $script:Version
        $m.PrivateData.PSData.LicenseUri | Should -Not -BeNullOrEmpty
        $m.PrivateData.PSData.ProjectUri | Should -Not -BeNullOrEmpty
        $m.Copyright | Should -Not -Match 'All rights reserved'
    }

    It 'analyzes a case from the extracted workstation zip with no repo beside it' {
        $work = Join-Path $env:TEMP ('foton-ws-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $work | Out-Null
        try {
            Expand-Archive -LiteralPath $script:ZipPath -DestinationPath (Join-Path $work 'app')
            $app = Join-Path $work ("app\Foton-{0}" -f $script:Version)
            $case = Join-Path $work 'WinFoton_FIXTURE_20260115-120000Z'
            Copy-Item -LiteralPath (Join-Path $script:RepoRoot 'tests\Fixtures\WinFoton_FIXTURE_20260115-120000Z') -Destination $case -Recurse
            $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
            Push-Location $work
            try {
                $out = & $exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $app 'tools\Invoke-FotonEasy.ps1') analyze $case 2>&1 | Out-String
                $code = $LASTEXITCODE
            }
            finally { Pop-Location }
            $code | Should -Be 0 -Because $out
            Test-Path -LiteralPath (Join-Path $case 'Foton_Report.html') | Should -Be $true
            $out | Should -Match ("Version\s+{0}" -f [regex]::Escape($script:Version))
        }
        finally {
            Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
