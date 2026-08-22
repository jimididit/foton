# Core helper tests. These functions are module-private; InModuleScope is required.
# Behavior must match WinFoton.ps1 helpers (sentinels, escape rules, skip status).

$moduleManifest = Join-Path $PSScriptRoot '..\Foton.psd1'
Import-Module $moduleManifest -Force

InModuleScope Foton {
    Describe 'ConvertTo-FotonSafeHtml' {
        It 'escapes markup and quotes' {
            ConvertTo-FotonSafeHtml "<a href=""x"">&'</a>" |
                Should -Be '&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;'
        }
        It 'returns empty string for null' {
            ConvertTo-FotonSafeHtml $null | Should -Be ''
        }
    }

    Describe 'Test-FotonUserWritablePath' {
        BeforeEach { Initialize-FotonSession }
        It 'flags AppData-style paths' {
            Test-FotonUserWritablePath 'C:\Users\a\AppData\Local\payload.exe' | Should -Be $true
        }
        It 'does not flag System32' {
            Test-FotonUserWritablePath 'C:\Windows\System32\svchost.exe' | Should -Be $false
        }
        It 'returns false for empty' {
            Test-FotonUserWritablePath '' | Should -Be $false
        }
    }

    Describe 'Test-FotonSuspiciousCommand' {
        BeforeEach { Initialize-FotonSession }
        It 'hits encodedcommand' {
            $r = Test-FotonSuspiciousCommand 'powershell -encodedcommand ABC'
            $r | Should -Match 'encodedcommand'
        }
        It 'returns null for a benign line' {
            Test-FotonSuspiciousCommand 'notepad.exe C:\temp\notes.txt' | Should -BeNullOrEmpty
        }
    }

    Describe 'Get-FotonArtifactPath' {
        BeforeEach { Initialize-FotonSession }
        It 'builds a relative package path' {
            Get-FotonArtifactPath -Category 'System' -Name 'os_info' -Format 'json' |
                Should -Be '01_System/os_info.json'
        }
    }

    Describe 'Get-FotonSafeHash' {
        BeforeEach { Initialize-FotonSession }
        It 'returns empty for a blank path' {
            Get-FotonSafeHash -Path '' | Should -Be ''
        }
        It 'returns FileNotFound for a missing leaf' {
            Get-FotonSafeHash -Path 'C:\this-path-does-not-exist-foton-test.bin' | Should -Be 'FileNotFound'
        }
        It 'returns NotHashed when SkipHashing is set' {
            Initialize-FotonSession -SkipHashing
            Get-FotonSafeHash -Path 'C:\Windows\System32\kernel32.dll' | Should -Be 'NotHashed'
        }
        It 'returns a SHA-256 hex string for a small readable file' {
            $f = Join-Path $env:TEMP ("foton-hash-" + [guid]::NewGuid().ToString('N') + '.txt')
            'foton' | Out-File -FilePath $f -Encoding ASCII -NoNewline
            try {
                $h = Get-FotonSafeHash -Path $f
                $h | Should -Match '^[0-9A-F]{64}$'
            }
            finally {
                Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Describe 'Add-FotonFinding' {
        BeforeEach { Initialize-FotonSession }
        It 'appends a finding with tier and artifact' {
            Add-FotonFinding -Severity 'Info' -Category 'System' -Title 't' -Observation 'o' -Tier 1 -Artifact '01_System/os_info.json'
            $script:FotonSession.Findings.Count | Should -Be 1
            $script:FotonSession.Findings[0].Tier | Should -Be 1
        }
    }

    Describe 'Invoke-FotonCollection' {
        BeforeEach {
            Initialize-FotonSession
            $root = Join-Path $env:TEMP ("foton-col-" + [guid]::NewGuid().ToString('N'))
            New-Item -Path $root -ItemType Directory | Out-Null
            $sys = Join-Path $root '01_System'
            New-Item -Path $sys -ItemType Directory | Out-Null
            $script:FotonSession.Dirs['System'] = $sys
        }
        AfterEach {
            $sys = $script:FotonSession.Dirs['System']
            if ($sys) {
                $root = Split-Path $sys -Parent
                if (Test-Path -LiteralPath $root) {
                    Remove-Item -LiteralPath $root -Recurse -Force
                }
            }
        }
        It 'writes csv, caches data, and records Success' {
            Invoke-FotonCollection -Category 'System' -Name 'unit_probe' -Format 'Csv' -Description 'test' -Script {
                @(
                    [PSCustomObject]@{ Name = 'a'; Value = 1 }
                    [PSCustomObject]@{ Name = 'b'; Value = 2 }
                )
            } | Out-Null
            $script:FotonSession.Manifest[0].Status | Should -Be 'Success'
            $script:FotonSession.Manifest[0].Records | Should -Be 2
            $script:FotonSession.Data['unit_probe'].Count | Should -Be 2
            Test-Path -LiteralPath (Join-Path $script:FotonSession.Dirs['System'] 'unit_probe.csv') | Should -Be $true
        }
        It 'skips RequiresElevation when not elevated' {
            $script:FotonSession.IsElevated = $false
            Invoke-FotonCollection -Category 'System' -Name 'admin_only' -Format 'Txt' -RequiresElevation -Script { 'secret' } | Out-Null
            $script:FotonSession.Manifest[0].Status | Should -Be 'SkippedNotElevated'
            $script:FotonSession.Errors.Count | Should -Be 0
            (Get-Content -LiteralPath (Join-Path $script:FotonSession.Dirs['System'] 'admin_only.txt') -Raw) | Should -Match 'SkippedNotElevated'
        }
        It 'records Error without throwing' {
            Invoke-FotonCollection -Category 'System' -Name 'boom' -Format 'Txt' -Script { throw 'unit-fail' } | Out-Null
            $script:FotonSession.Manifest[0].Status | Should -Be 'Error'
            $script:FotonSession.Errors[0].Task | Should -Be 'boom'
        }
    }

    Describe 'Test-FotonElevated' {
        It 'returns a boolean' {
            $r = Test-FotonElevated
            ($r -eq $true -or $r -eq $false) | Should -Be $true
        }
    }
}
