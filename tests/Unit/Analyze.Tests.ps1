BeforeAll {
    $script:FotonPsd1 = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\Foton.psd1'))
    $script:Fixture = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\Fixtures\WinFoton_FIXTURE_20260115-120000Z'))
    Import-Module $script:FotonPsd1 -Force
}

Describe 'Get-FotonPackage and offline analysis' {
    It 'loads v1-style folder artifacts and does not treat hashes as collect data' {
        $pkg = Get-FotonPackage -Path $script:Fixture
        $pkg.Kind | Should -Be 'Folder'
        InModuleScope Foton {
            $script:FotonSession.Data.ContainsKey('os_info') | Should -Be $true
            $script:FotonSession.Data['os_info'].Hostname | Should -Be 'FIXTURE-PC'
            $script:FotonSession.Data.ContainsKey('hashes') | Should -Be $false
            $script:FotonSession.Data.ContainsKey('security_process_creation') | Should -Be $false
            $script:FotonSession.Data['running_processes'][1].UserWritablePath | Should -Be $true
        }
    }

    It 'fires WDigest and RTP heuristics and not for a benign hardening value' {
        Get-FotonPackage -Path $script:Fixture | Out-Null
        Invoke-FotonAnalysis
        InModuleScope Foton {
            $titles = @($script:FotonSession.Findings | ForEach-Object { $_.Title })
            $titles | Should -Contain 'WDigest cleartext credential storage is enabled'
            $titles | Should -Contain 'Defender real-time protection is disabled'
            $titles | Should -Contain 'Unsigned processes running from user-writable paths'
            $titles | Should -Contain 'Host and collection baseline'
            $titles | Should -Contain 'Collection ran without Administrator rights'
        }
        $analysisCsv = Join-Path $script:Fixture 'analysis\findings.csv'
        Test-Path -LiteralPath $analysisCsv | Should -Be $true
    }

    It 'does not fire WDigest when UseLogonCredential is 0' {
        InModuleScope Foton {
            Initialize-FotonSession
            $script:FotonSession.Data['hardening_registry_settings'] = @(
                [PSCustomObject]@{ Setting = 'UseLogonCredential'; Value = '0' }
            )
            $script:FotonSession.Data['security_process_creation'] = @(
                [PSCustomObject]@{ EventId = 4688 }
            )
            Invoke-FotonAnalysis
            @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'WDigest cleartext credential storage is enabled' }) |
                Should -HaveCount 0
        }
    }

    It 'fires on parsed user-writable paths and not on System32' {
        $tmp = Join-Path $env:TEMP ('foton-an-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path (Join-Path $tmp 'analysis') -ItemType Directory -Force | Out-Null
        try {
            @(
                [PSCustomObject]@{ Identity = 'C:\Users\Public\evil.exe'; Path = 'C:\Users\Public\evil.exe'; LocalBasePath = ''; LowerCaseLongPath = '' }
            ) | Export-Csv -Path (Join-Path $tmp 'analysis\parsed_records.csv') -NoTypeInformation -Encoding UTF8
            InModuleScope Foton -Parameters @{ Root = $tmp } {
                param($Root)
                Initialize-FotonSession
                $script:FotonSession.CaseRoot = $Root
                $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
                Invoke-FotonAnalysis
                @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'Parsed artifacts reference user-writable paths' }) |
                    Should -HaveCount 1
            }
            @(
                [PSCustomObject]@{ Identity = 'C:\Windows\System32\notepad.exe'; Path = 'C:\Windows\System32\notepad.exe'; LocalBasePath = ''; LowerCaseLongPath = '' }
            ) | Export-Csv -Path (Join-Path $tmp 'analysis\parsed_records.csv') -NoTypeInformation -Encoding UTF8
            InModuleScope Foton -Parameters @{ Root = $tmp } {
                param($Root)
                Initialize-FotonSession
                $script:FotonSession.CaseRoot = $Root
                $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
                Invoke-FotonAnalysis
                @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'Parsed artifacts reference user-writable paths' }) |
                    Should -HaveCount 0
            }
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'fires on baseline_diff service PathName and not on DisplayVersion' {
        $tmp = Join-Path $env:TEMP ('foton-diff-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path (Join-Path $tmp 'analysis') -ItemType Directory -Force | Out-Null
        try {
            @(
                [PSCustomObject]@{ RecordType = 'Service'; Identity = 'EvilSvc'; ChangeType = 'Modified'; Field = 'PathName' }
            ) | Export-Csv -Path (Join-Path $tmp 'analysis\baseline_diff.csv') -NoTypeInformation -Encoding UTF8
            InModuleScope Foton -Parameters @{ Root = $tmp } {
                param($Root)
                Initialize-FotonSession
                $script:FotonSession.CaseRoot = $Root
                $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
                Invoke-FotonAnalysis
                @($script:FotonSession.Findings | Where-Object { $_.Title -like 'Baseline diff: service*' }) |
                    Should -HaveCount 1
            }
            @(
                [PSCustomObject]@{ RecordType = 'InstalledSoftware'; Identity = 'App|Pub'; ChangeType = 'Modified'; Field = 'DisplayVersion' }
            ) | Export-Csv -Path (Join-Path $tmp 'analysis\baseline_diff.csv') -NoTypeInformation -Encoding UTF8
            InModuleScope Foton -Parameters @{ Root = $tmp } {
                param($Root)
                Initialize-FotonSession
                $script:FotonSession.CaseRoot = $Root
                $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
                Invoke-FotonAnalysis
                @($script:FotonSession.Findings | Where-Object { $_.Title -like 'Baseline diff:*' }) |
                    Should -HaveCount 0
            }
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'writes HTML using package hostname not the analyst workstation' {
        Get-FotonPackage -Path $script:Fixture | Out-Null
        Invoke-FotonAnalysis
        $htmlPath = Join-Path $env:TEMP ('foton-report-' + [guid]::NewGuid().ToString('N') + '.html')
        try {
            New-FotonReport -Path $htmlPath
            $html = Get-Content -LiteralPath $htmlPath -Raw
            $html | Should -Match 'FIXTURE-PC'
            $html | Should -Not -Match '<script src="https://'
            $html | Should -Match 'What was observed'
            $html | Should -Match 'class="mark"'
            $html | Should -Match 'id="foton-q"'
            $html | Should -Match 'id="foton-toc"'
            $html | Should -Match '(?s)<style>.*\.foton-bar'
            $html | Should -Not -Match '</style>\s*\.foton-bar'
        }
        finally {
            Remove-Item -LiteralPath $htmlPath -Force -ErrorAction SilentlyContinue
        }
    }

    AfterAll {
        $analysisDir = Join-Path $script:Fixture 'analysis'
        if (Test-Path -LiteralPath $analysisDir) {
            Remove-Item -LiteralPath $analysisDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        $rpt = Join-Path $script:Fixture 'Foton_Report.html'
        if (Test-Path -LiteralPath $rpt) {
            Remove-Item -LiteralPath $rpt -Force -ErrorAction SilentlyContinue
        }
    }
}
